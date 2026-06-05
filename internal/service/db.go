package service

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/model"
)

// Reload 从 MySQL 全量加载到内存缓存。启动时及每次写操作后调用。
func (s *Store) Reload(ctx context.Context) error {
	// 基础表
	var areas []*model.Area
	if err := g.Model("area").Ctx(ctx).Order("id").Scan(&areas); err != nil {
		return err
	}
	var orgs []*model.Org
	if err := g.Model("org").Ctx(ctx).Order("id").Scan(&orgs); err != nil {
		return err
	}
	var menus []*model.Menu
	if err := g.Model("menu").Ctx(ctx).Order("id").Scan(&menus); err != nil {
		return err
	}
	var resources []*model.Resource
	if err := g.Model("resource").Ctx(ctx).Order("id").Scan(&resources); err != nil {
		return err
	}
	var actions []model.Action
	if err := g.Model("action").Ctx(ctx).Order("sort").Scan(&actions); err != nil {
		return err
	}

	// 角色及其关联
	type roleRow struct {
		Id          int
		Name        string
		Description string
		CreatedBy   int
	}
	var roleRows []roleRow
	if err := g.Model("role").Ctx(ctx).Order("id").Scan(&roleRows); err != nil {
		return err
	}
	type rmRow struct{ RoleId, MenuId int }
	var rms []rmRow
	if err := g.Model("role_menu").Ctx(ctx).Scan(&rms); err != nil {
		return err
	}
	type dsRow struct {
		RoleId       int
		ScopeType    string
		NodeId       int
		IncludeChild bool
	}
	var dss []dsRow
	if err := g.Model("role_data_scope").Ctx(ctx).Scan(&dss); err != nil {
		return err
	}
	type raRow struct {
		RoleId     int
		ResourceId int
		ActionCode string
	}
	var ras []raRow
	if err := g.Model("role_resource_action").Ctx(ctx).Scan(&ras); err != nil {
		return err
	}

	// 用户及绑定
	var users []*model.User
	if err := g.Model("user").Ctx(ctx).Order("id").Scan(&users); err != nil {
		return err
	}
	type urRow struct{ UserId, RoleId int }
	var urs []urRow
	if err := g.Model("user_role").Ctx(ctx).Scan(&urs); err != nil {
		return err
	}

	// 组装角色
	roles := make(map[int]*model.Role, len(roleRows))
	for _, r := range roleRows {
		roles[r.Id] = &model.Role{Id: r.Id, Name: r.Name, Description: r.Description, CreatedBy: r.CreatedBy}
	}
	for _, x := range rms {
		if r := roles[x.RoleId]; r != nil {
			r.MenuIds = append(r.MenuIds, x.MenuId)
		}
	}
	for _, x := range dss {
		r := roles[x.RoleId]
		if r == nil {
			continue
		}
		sc := model.DataScope{NodeId: x.NodeId, IncludeChild: x.IncludeChild}
		switch x.ScopeType {
		case "AREA":
			r.AreaScopes = append(r.AreaScopes, sc)
		case "ORG":
			r.OrgScopes = append(r.OrgScopes, sc)
		case "RES_AREA":
			r.ResourceAreaScopes = append(r.ResourceAreaScopes, sc)
		}
	}
	for _, x := range ras {
		if r := roles[x.RoleId]; r != nil {
			r.ResourceActions = append(r.ResourceActions, model.ResourceAction{ResourceId: x.ResourceId, ActionCode: x.ActionCode})
		}
	}

	// 组装用户绑定
	userMap := make(map[int]*model.User, len(users))
	for _, u := range users {
		userMap[u.Id] = u
	}
	for _, x := range urs {
		if u := userMap[x.UserId]; u != nil {
			u.RoleIds = append(u.RoleIds, x.RoleId)
		}
	}

	// 原子替换缓存
	s.mu.Lock()
	defer s.mu.Unlock()
	s.areas = toMap(areas, func(a *model.Area) int { return a.Id })
	s.orgs = toMap(orgs, func(o *model.Org) int { return o.Id })
	s.menus = toMap(menus, func(m *model.Menu) int { return m.Id })
	s.resources = toMap(resources, func(r *model.Resource) int { return r.Id })
	s.actions = actions
	s.roles = roles
	s.users = userMap
	return nil
}

func toMap[T any](list []T, key func(T) int) map[int]T {
	m := make(map[int]T, len(list))
	for _, v := range list {
		m[key(v)] = v
	}
	return m
}

// SaveRole 落库(角色主表 + 三类关联表),成功后刷新缓存。id<=0 为新增。
func (s *Store) SaveRole(ctx context.Context, r *model.Role) (*model.Role, error) {
	err := g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := g.Map{"name": r.Name, "description": r.Description, "created_by": r.CreatedBy}
		if r.Id <= 0 {
			res, err := tx.Model("role").Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			r.Id = int(id)
		} else {
			if _, err := tx.Model("role").Ctx(ctx).Data(data).Where("id", r.Id).Update(); err != nil {
				return err
			}
		}

		// 关联表:先清后插(全量覆盖)
		if _, err := tx.Model("role_menu").Ctx(ctx).Where("role_id", r.Id).Delete(); err != nil {
			return err
		}
		for _, mid := range r.MenuIds {
			if _, err := tx.Model("role_menu").Ctx(ctx).Data(g.Map{"role_id": r.Id, "menu_id": mid}).Insert(); err != nil {
				return err
			}
		}

		if _, err := tx.Model("role_data_scope").Ctx(ctx).Where("role_id", r.Id).Delete(); err != nil {
			return err
		}
		insScope := func(t string, scopes []model.DataScope) error {
			for _, sc := range scopes {
				if _, err := tx.Model("role_data_scope").Ctx(ctx).Data(g.Map{
					"role_id": r.Id, "scope_type": t, "node_id": sc.NodeId, "include_child": sc.IncludeChild,
				}).Insert(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := insScope("AREA", r.AreaScopes); err != nil {
			return err
		}
		if err := insScope("ORG", r.OrgScopes); err != nil {
			return err
		}
		if err := insScope("RES_AREA", r.ResourceAreaScopes); err != nil {
			return err
		}

		if _, err := tx.Model("role_resource_action").Ctx(ctx).Where("role_id", r.Id).Delete(); err != nil {
			return err
		}
		for _, ra := range r.ResourceActions {
			if _, err := tx.Model("role_resource_action").Ctx(ctx).Data(g.Map{
				"role_id": r.Id, "resource_id": ra.ResourceId, "action_code": ra.ActionCode,
			}).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s.Role(r.Id), nil
}

// SaveUser 落库(用户主表 + user_role 绑定),成功后刷新缓存。id<=0 为新增。
func (s *Store) SaveUser(ctx context.Context, u *model.User) (*model.User, error) {
	err := g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := g.Map{"name": u.Name, "org_id": u.OrgId, "is_superuser": u.IsSuperuser}
		if u.Id <= 0 {
			res, err := tx.Model("user").Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			u.Id = int(id)
		} else {
			if _, err := tx.Model("user").Ctx(ctx).Data(data).Where("id", u.Id).Update(); err != nil {
				return err
			}
		}
		if _, err := tx.Model("user_role").Ctx(ctx).Where("user_id", u.Id).Delete(); err != nil {
			return err
		}
		for _, rid := range u.RoleIds {
			if _, err := tx.Model("user_role").Ctx(ctx).Data(g.Map{"user_id": u.Id, "role_id": rid}).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s.User(u.Id), nil
}
