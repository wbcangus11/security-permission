package service

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
	"security-permission/internal/model/entity"
)

func (s *Store) Reload(ctx context.Context) error {
	areas, err := loadAreas(ctx)
	if err != nil {
		return err
	}
	orgs, err := loadOrgs(ctx)
	if err != nil {
		return err
	}
	menus, err := loadMenus(ctx)
	if err != nil {
		return err
	}
	resources, err := loadResources(ctx)
	if err != nil {
		return err
	}
	actions, err := loadActions(ctx)
	if err != nil {
		return err
	}

	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	users, err := loadUsers(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.areas = toMap(areas, func(a *model.Area) int { return a.Id })
	s.orgs = toMap(orgs, func(o *model.Org) int { return o.Id })
	s.menus = toMap(menus, func(m *model.Menu) int { return m.Id })
	s.resources = toMap(resources, func(r *model.Resource) int { return r.Id })
	s.actions = actions
	s.roles = roles
	s.users = users
	s.invalidatePermissionsLocked()
	return nil
}

func (s *Store) reloadAreas(ctx context.Context) error {
	areas, err := loadAreas(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.areas = toMap(areas, func(a *model.Area) int { return a.Id })
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadOrgs(ctx context.Context) error {
	orgs, err := loadOrgs(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.orgs = toMap(orgs, func(o *model.Org) int { return o.Id })
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadResources(ctx context.Context) error {
	resources, err := loadResources(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.resources = toMap(resources, func(r *model.Resource) int { return r.Id })
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadRoles(ctx context.Context) error {
	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.roles = roles
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadUsers(ctx context.Context) error {
	users, err := loadUsers(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.users = users
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadAreasAndRoles(ctx context.Context) error {
	areas, err := loadAreas(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.areas = toMap(areas, func(a *model.Area) int { return a.Id })
	s.roles = roles
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadOrgsAndRoles(ctx context.Context) error {
	orgs, err := loadOrgs(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.orgs = toMap(orgs, func(o *model.Org) int { return o.Id })
	s.roles = roles
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadResourcesAndRoles(ctx context.Context) error {
	resources, err := loadResources(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.resources = toMap(resources, func(r *model.Resource) int { return r.Id })
	s.roles = roles
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func (s *Store) reloadRolesAndUsers(ctx context.Context) error {
	roles, err := loadRoles(ctx)
	if err != nil {
		return err
	}
	users, err := loadUsers(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.roles = roles
	s.users = users
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

func loadAreas(ctx context.Context) ([]*model.Area, error) {
	var rows []*entity.Area
	if err := dao.Area.Ctx(ctx).Order(dao.Area.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	items := make([]*model.Area, 0, len(rows))
	for _, row := range rows {
		items = append(items, &model.Area{
			Id:       int(row.Id),
			ParentId: int(row.ParentId),
			Name:     row.Name,
			Path:     row.Path,
			Sort:     row.Sort,
		})
	}
	return items, nil
}

func loadOrgs(ctx context.Context) ([]*model.Org, error) {
	var rows []*entity.Org
	if err := dao.Org.Ctx(ctx).Order(dao.Org.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	items := make([]*model.Org, 0, len(rows))
	for _, row := range rows {
		items = append(items, &model.Org{
			Id:       int(row.Id),
			ParentId: int(row.ParentId),
			Name:     row.Name,
			Path:     row.Path,
		})
	}
	return items, nil
}

func loadMenus(ctx context.Context) ([]*model.Menu, error) {
	var rows []*entity.Menu
	if err := dao.Menu.Ctx(ctx).Order(dao.Menu.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	items := make([]*model.Menu, 0, len(rows))
	for _, row := range rows {
		items = append(items, &model.Menu{
			Id:       int(row.Id),
			ParentId: int(row.ParentId),
			Code:     row.Code,
			Name:     row.Name,
			Domain:   row.Domain,
		})
	}
	return items, nil
}

func loadResources(ctx context.Context) ([]*model.Resource, error) {
	var rows []*entity.Resource
	if err := dao.Resource.Ctx(ctx).Order(dao.Resource.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	items := make([]*model.Resource, 0, len(rows))
	for _, row := range rows {
		items = append(items, &model.Resource{
			Id:     int(row.Id),
			AreaId: int(row.AreaId),
			Type:   row.Type,
			Name:   row.Name,
		})
	}
	return items, nil
}

func loadActions(ctx context.Context) ([]model.Action, error) {
	var rows []entity.Action
	if err := dao.Action.Ctx(ctx).Order(dao.Action.Columns().Sort).Scan(&rows); err != nil {
		return nil, err
	}
	actions := make([]model.Action, 0, len(rows))
	for _, row := range rows {
		actions = append(actions, model.Action{
			Code: row.Code,
			Name: row.Name,
		})
	}
	return actions, nil
}

func loadRoles(ctx context.Context) (map[int]*model.Role, error) {
	var roleRows []*entity.Role
	if err := dao.Role.Ctx(ctx).Order(dao.Role.Columns().Id).Scan(&roleRows); err != nil {
		return nil, err
	}
	var menuRows []*entity.RoleMenu
	if err := dao.RoleMenu.Ctx(ctx).Scan(&menuRows); err != nil {
		return nil, err
	}
	var scopeRows []*entity.RoleDataScope
	if err := dao.RoleDataScope.Ctx(ctx).Scan(&scopeRows); err != nil {
		return nil, err
	}
	var actionRows []*entity.RoleResourceAction
	if err := dao.RoleResourceAction.Ctx(ctx).Scan(&actionRows); err != nil {
		return nil, err
	}

	roles := make(map[int]*model.Role, len(roleRows))
	for _, row := range roleRows {
		roles[int(row.Id)] = &model.Role{
			Id:          int(row.Id),
			Name:        row.Name,
			Description: row.Description,
			CreatedBy:   int(row.CreatedBy),
		}
	}
	for _, row := range menuRows {
		if r := roles[int(row.RoleId)]; r != nil {
			r.MenuIds = append(r.MenuIds, int(row.MenuId))
		}
	}
	for _, row := range scopeRows {
		r := roles[int(row.RoleId)]
		if r == nil {
			continue
		}
		sc := model.DataScope{NodeId: int(row.NodeId), IncludeChild: row.IncludeChild != 0}
		switch row.ScopeType {
		case model.ScopeTypeArea:
			r.AreaScopes = append(r.AreaScopes, sc)
		case model.ScopeTypeOrg:
			r.OrgScopes = append(r.OrgScopes, sc)
		case model.ScopeTypeResourceArea:
			r.ResourceAreaScopes = append(r.ResourceAreaScopes, sc)
		case model.ScopeTypeResourceOverride:
			r.ResourceOverrides = append(r.ResourceOverrides, int(row.NodeId))
		}
	}
	for _, row := range actionRows {
		if r := roles[int(row.RoleId)]; r != nil {
			r.ResourceActions = append(r.ResourceActions, model.ResourceAction{
				ResourceId: int(row.ResourceId),
				ActionCode: row.ActionCode,
			})
		}
	}
	return roles, nil
}

func loadUsers(ctx context.Context) (map[int]*model.User, error) {
	var rows []*entity.User
	if err := dao.User.Ctx(ctx).Order(dao.User.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	var roleRows []*entity.UserRole
	if err := dao.UserRole.Ctx(ctx).Scan(&roleRows); err != nil {
		return nil, err
	}

	users := make(map[int]*model.User, len(rows))
	for _, row := range rows {
		users[int(row.Id)] = &model.User{
			Id:          int(row.Id),
			Name:        row.Name,
			OrgId:       int(row.OrgId),
			IsSuperuser: row.IsSuperuser != 0,
		}
	}
	for _, row := range roleRows {
		if u := users[int(row.UserId)]; u != nil {
			u.RoleIds = append(u.RoleIds, int(row.RoleId))
		}
	}
	return users, nil
}

func toMap[T any](list []T, key func(T) int) map[int]T {
	m := make(map[int]T, len(list))
	for _, v := range list {
		m[key(v)] = v
	}
	return m
}

func (s *Store) SaveRole(ctx context.Context, r *model.Role) (*model.Role, error) {
	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.Role{Name: r.Name, Description: r.Description, CreatedBy: r.CreatedBy}
		if r.Id <= 0 {
			res, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			r.Id = int(id)
		} else {
			if _, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).Where(dao.Role.Columns().Id, r.Id).Update(); err != nil {
				return err
			}
		}

		if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).Where(dao.RoleMenu.Columns().RoleId, r.Id).Delete(); err != nil {
			return err
		}
		for _, mid := range r.MenuIds {
			if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).Data(do.RoleMenu{RoleId: r.Id, MenuId: mid}).Insert(); err != nil {
				return err
			}
		}

		if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Where(dao.RoleDataScope.Columns().RoleId, r.Id).Delete(); err != nil {
			return err
		}
		insScope := func(t string, scopes []model.DataScope) error {
			for _, sc := range scopes {
				if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
					RoleId:       r.Id,
					ScopeType:    t,
					NodeId:       sc.NodeId,
					IncludeChild: sc.IncludeChild,
				}).Insert(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := insScope(model.ScopeTypeArea, r.AreaScopes); err != nil {
			return err
		}
		if err := insScope(model.ScopeTypeOrg, r.OrgScopes); err != nil {
			return err
		}
		if err := insScope(model.ScopeTypeResourceArea, r.ResourceAreaScopes); err != nil {
			return err
		}
		for _, resId := range r.ResourceOverrides {
			if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
				RoleId:       r.Id,
				ScopeType:    model.ScopeTypeResourceOverride,
				NodeId:       resId,
				IncludeChild: false,
			}).Insert(); err != nil {
				return err
			}
		}

		if _, err := tx.Model(dao.RoleResourceAction.Table()).Ctx(ctx).Where(dao.RoleResourceAction.Columns().RoleId, r.Id).Delete(); err != nil {
			return err
		}
		for _, ra := range r.ResourceActions {
			if _, err := tx.Model(dao.RoleResourceAction.Table()).Ctx(ctx).Data(do.RoleResourceAction{
				RoleId:     r.Id,
				ResourceId: ra.ResourceId,
				ActionCode: ra.ActionCode,
			}).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.reloadRoles(ctx); err != nil {
		return nil, err
	}
	return s.Role(r.Id), nil
}

func (s *Store) SaveUser(ctx context.Context, u *model.User) (*model.User, error) {
	err := dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.User{Name: u.Name, OrgId: u.OrgId, IsSuperuser: u.IsSuperuser}
		if u.Id <= 0 {
			res, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			u.Id = int(id)
		} else {
			if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Where(dao.User.Columns().Id, u.Id).Update(); err != nil {
				return err
			}
		}
		if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Where(dao.UserRole.Columns().UserId, u.Id).Delete(); err != nil {
			return err
		}
		for _, rid := range u.RoleIds {
			if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Data(do.UserRole{UserId: u.Id, RoleId: rid}).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.reloadUsers(ctx); err != nil {
		return nil, err
	}
	return s.User(u.Id), nil
}
