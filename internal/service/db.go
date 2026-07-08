package service

import (
	"context"

	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
	"security-permission/internal/model/entity"
)

// Reload 从 MySQL 全量加载权限数据到内存缓存。
// 服务启动时调用一次;写操作成功后也会局部或全量重载,让鉴权始终读内存快照。
func (s *Store) Reload(ctx context.Context) error {
	areas, err := loadAreas(ctx)
	if err != nil {
		return err
	}
	orgs, err := loadOrgs(ctx)
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
	menus, err := loadMenus(ctx)
	if err != nil {
		return err
	}

	roles, err := loadRoles(ctx, menus)
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
	s.resources = toMap(resources, func(r *model.Resource) int { return r.Id })
	s.actions = actions
	s.menus = toMap(menus, func(m *model.Menu) int { return m.Id })
	s.roles = roles
	s.users = users
	s.invalidatePermissionsLocked()
	return nil
}

// reloadAreas 只重载区域缓存。
// 区域新增/移动会改变 path,因此重载后必须让权限快照失效。
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

// reloadOrgs 只重载组织缓存,并清空用户有效权限快照。
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

// reloadResources 只重载业务资源缓存,并清空用户有效权限快照。
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

// reloadRoles 只重载角色缓存。
// 角色变化会影响几乎所有鉴权结果,所以必须让权限快照失效。
func (s *Store) reloadRoles(ctx context.Context) error {
	roles, err := loadRoles(ctx, s.Menus())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.roles = roles
	s.invalidatePermissionsLocked()
	s.mu.Unlock()
	return nil
}

// reloadUsers 只重载用户缓存。
// 用户角色绑定或超管标志变化后需要调用它。
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

// reloadAreasAndRoles 同时重载区域和角色。
// 删除区域会清理角色范围引用,所以两类缓存要一起刷新。
func (s *Store) reloadAreasAndRoles(ctx context.Context) error {
	areas, err := loadAreas(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx, s.Menus())
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

// reloadOrgsAndRoles 同时重载组织和角色。
// 删除组织会清理角色范围引用,所以两类缓存要一起刷新。
func (s *Store) reloadOrgsAndRoles(ctx context.Context) error {
	orgs, err := loadOrgs(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx, s.Menus())
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

// reloadResourcesAndRoles 同时重载资源和角色。
// 删除资源会清理资源精细授权,所以两类缓存要一起刷新。
func (s *Store) reloadResourcesAndRoles(ctx context.Context) error {
	resources, err := loadResources(ctx)
	if err != nil {
		return err
	}
	roles, err := loadRoles(ctx, s.Menus())
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

// reloadRolesAndUsers 同时重载角色和用户。
// 删除角色会清理 user_role 绑定,所以用户缓存也要刷新。
func (s *Store) reloadRolesAndUsers(ctx context.Context) error {
	roles, err := loadRoles(ctx, s.Menus())
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

// loadAreas 从数据库读取区域树节点。
// path 字段是权限子树判断和 SQL 下推过滤的关键字段。
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

// loadOrgs 从数据库读取组织树节点。
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

// loadResources 从数据库读取业务资源。
// 资源本身不是树,它通过 AreaId 挂到区域树上。
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

// loadActions 从数据库读取资源操作字典。
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

// loadMenus 从数据库读取已启用的菜单/功能权限点。
// code 是接口和鉴权使用的稳定标识;id 只用于 role_menu 关联。
func loadMenus(ctx context.Context) ([]*model.Menu, error) {
	type menuRow struct {
		Id       int64
		ParentId int64
		Code     string
		Name     string
		Domain   string
		Sort     int
	}
	var rows []*menuRow
	if err := g.DB().Model("menu").Ctx(ctx).
		Fields("id,parent_id,code,name,domain,sort").
		Where("enabled", 1).
		Order("sort,id").
		Scan(&rows); err != nil {
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
			Sort:     row.Sort,
		})
	}
	return items, nil
}

// loadRoles 读取角色及所有角色关联表,组装成领域模型 Role。
// role_data_scope 同时承载 AREA/ORG/RES_AREA/RESOVR 四种范围,这里按 scope_type 分发。
func loadRoles(ctx context.Context, menus []*model.Menu) (map[int]*model.Role, error) {
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

	menuCodeById := make(map[int]string, len(menus))
	for _, menu := range menus {
		menuCodeById[menu.Id] = menu.Code
	}

	roles := make(map[int]*model.Role, len(roleRows))
	for _, row := range roleRows {
		roles[int(row.Id)] = &model.Role{
			Id:          int(row.Id),
			Name:        row.Name,
			Description: row.Description,
			CreatedBy:   row.CreatedBy,
		}
	}
	for _, row := range menuRows {
		if r := roles[int(row.RoleId)]; r != nil {
			menuId := int(row.MenuId)
			r.MenuIds = append(r.MenuIds, menuId)
			if code := menuCodeById[menuId]; code != "" {
				r.MenuCodes = append(r.MenuCodes, code)
			}
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

// loadUsers 读取用户及 user_role 绑定。
func loadUsers(ctx context.Context) (map[string]*model.User, error) {
	var rows []*entity.User
	if err := dao.User.Ctx(ctx).Order(dao.User.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	var roleRows []*entity.UserRole
	if err := dao.UserRole.Ctx(ctx).Scan(&roleRows); err != nil {
		return nil, err
	}

	users := make(map[string]*model.User, len(rows))
	for _, row := range rows {
		users[row.Id] = &model.User{
			Id:          row.Id,
			Name:        row.Name,
			OrgId:       int(row.OrgId),
			IsSuperuser: row.IsSuperuser != 0,
		}
	}
	for _, row := range roleRows {
		if u := users[row.UserId]; u != nil {
			u.RoleIds = append(u.RoleIds, int(row.RoleId))
		}
	}
	return users, nil
}

// toMap 把切片按 ID 转成 map,方便运行时 O(1) 查询。
func toMap[T any, K comparable](list []T, key func(T) K) map[K]T {
	m := make(map[K]T, len(list))
	for _, v := range list {
		m[key(v)] = v
	}
	return m
}

// SaveRole 保存角色聚合。
// 它会重写该角色的菜单、数据范围、资源精细授权等关联表;调用方必须先完成委派合并和管理权限校验。
func (s *Store) SaveRole(ctx context.Context, r *model.Role) (*model.Role, error) {
	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.Role{Name: r.Name, Description: r.Description, CreatedBy: r.CreatedBy}
		if r.Id <= 0 {
			// 新建只写角色主表,拿到自增 id 后再写菜单/数据范围/资源精细授权。
			res, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			r.Id = int(id)
		} else {
			// 更新角色主表。created_by 是否保持原值由上层 RoleSave 先处理好。
			if _, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).Where(dao.Role.Columns().Id, r.Id).Update(); err != nil {
				return err
			}
		}

		// 关联表采用“整体重写”:上层已算出最终权限,这里先删旧行再插入新行,避免残留脏授权。
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
		// role_data_scope 统一保存三类树范围:AREA / ORG / RES_AREA。
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
		// RESOVR 表示“资源进入精细模式”;即使没有 action 行,也能表达资源级不可见。
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
		// role_resource_action 只存精细模式下明确授予的操作;无精细行时按区域范围继承。
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

// SaveUser 保存用户基础信息和角色绑定。
// 这里是底层落库方法;带权限校验的账号管理入口是 SaveUserManaged。
func (s *Store) SaveUser(ctx context.Context, u *model.User) (*model.User, error) {
	err := dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if u.Id == "" {
			// 用户 ID 是字符串。当前基础数据使用数字字符串,新建时延续“最大数字 + 1”策略。
			u.Id = s.nextUserId()
		}
		data := do.User{Id: u.Id, Name: u.Name, OrgId: u.OrgId, IsSuperuser: u.IsSuperuser}
		if s.User(u.Id) == nil {
			// 新建用户:显式写入字符串 id,不依赖数据库自增用户主键。
			if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Insert(); err != nil {
				return err
			}
		} else {
			// 更新用户基础字段;角色绑定在下面整体重写。
			if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Where(dao.User.Columns().Id, u.Id).Update(); err != nil {
				return err
			}
		}
		// 用户-角色绑定整体重写。上层 SaveUserManaged 已完成可分配角色合并和越权保护。
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
