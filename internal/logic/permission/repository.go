package permission

import (
	"context"
	"sort"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/google/uuid"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
	"security-permission/internal/model/entity"
)

func findUser(ctx context.Context, id string) (*model.User, error) {
	// 新建用户时还没有 ID，直接返回就行，没必要拿空值去查数据库。
	if id == "" {
		return nil, nil
	}

	var row entity.User
	if err := dao.User.Ctx(ctx).Where(dao.User.Columns().Id, id).Scan(&row); err != nil {
		return nil, gerror.Wrap(err, "查询用户失败")
	}
	if row.Id == "" {
		return nil, nil
	}
	var bindings []struct{ RoleId int64 }
	if err := dao.UserRole.Ctx(ctx).Fields(dao.UserRole.Columns().RoleId).
		Where(dao.UserRole.Columns().UserId, id).Order(dao.UserRole.Columns().RoleId).Scan(&bindings); err != nil {
		return nil, gerror.Wrap(err, "查询用户角色失败")
	}
	u := &model.User{Id: row.Id, Name: row.Name, OrgId: int(row.OrgId), IsSuperuser: row.IsSuperuser != 0}
	for _, binding := range bindings {
		u.RoleIds = append(u.RoleIds, int(binding.RoleId))
	}
	return u, nil
}

// loadPermissionFacts 固定用几次批量查询把一个用户的鉴权数据读全。
// 缓存未命中时才会走到这里，不再按角色和范围节点一条条查。
func loadPermissionFacts(ctx context.Context, userID string) (*permissionFacts, error) {
	var userRow entity.User
	if err := dao.User.Ctx(ctx).Where(dao.User.Columns().Id, userID).Scan(&userRow); err != nil {
		return nil, err
	}
	if userRow.Id == "" {
		return &permissionFacts{}, nil
	}

	user := &model.User{
		Id: userRow.Id, Name: userRow.Name, OrgId: int(userRow.OrgId),
		IsSuperuser: userRow.IsSuperuser != 0, RoleIds: []int{},
	}
	facts := &permissionFacts{
		user: user,
		scopePaths: map[string]map[int]string{
			treeKindArea:    {},
			treeKindOrg:     {},
			treeKindResArea: {},
		},
	}

	var roleRows []struct {
		Id          int
		Name        string
		Description string
		CreatedBy   string
	}
	if err := g.DB().Model(dao.UserRole.Table()+" ur").Ctx(ctx).
		InnerJoin(dao.Role.Table()+" r", "r.id=ur.role_id").
		Fields("r.id,r.name,r.description,r.created_by").
		Where("ur.user_id", userID).Order("r.id").Scan(&roleRows); err != nil {
		return nil, err
	}
	roleIDs := make([]int, 0, len(roleRows))
	rolesByID := make(map[int]*model.Role, len(roleRows))
	for _, row := range roleRows {
		role := &model.Role{
			Id: row.Id, Name: row.Name, Description: row.Description, CreatedBy: row.CreatedBy,
		}
		facts.roles = append(facts.roles, role)
		rolesByID[role.Id] = role
		roleIDs = append(roleIDs, role.Id)
		user.RoleIds = append(user.RoleIds, role.Id)
	}
	if user.IsSuperuser || len(roleIDs) == 0 {
		return facts, nil
	}

	catalog, err := currentMenuCatalog()
	if err != nil {
		return nil, err
	}
	var menuRows []struct {
		RoleId   int
		MenuCode string
	}
	if err := dao.RoleMenu.Ctx(ctx).Fields(
		dao.RoleMenu.Columns().RoleId,
		dao.RoleMenu.Columns().MenuCode,
	).WhereIn(dao.RoleMenu.Columns().RoleId, roleIDs).
		Order(dao.RoleMenu.Columns().RoleId + "," + dao.RoleMenu.Columns().MenuCode).
		Scan(&menuRows); err != nil {
		return nil, err
	}
	for _, row := range menuRows {
		role, menu := rolesByID[row.RoleId], catalog.byCode[row.MenuCode]
		if role == nil || menu == nil {
			continue
		}
		if menu.Domain == model.MenuDomainSys {
			role.MenuConfigCodes = append(role.MenuConfigCodes, menu.Code)
		} else if menu.Domain == model.MenuDomainApp {
			role.MenuAppCodes = append(role.MenuAppCodes, menu.Code)
		}
	}

	var scopeRows []struct {
		RoleId       int
		ScopeType    string
		NodeId       int
		IncludeChild int
		NodePath     string
	}
	if err := g.DB().Model(dao.RoleDataScope.Table()+" s").Ctx(ctx).
		LeftJoin(dao.Area.Table()+" a", "a.id=s.node_id AND s.scope_type IN ('AREA','RES_AREA')").
		LeftJoin(dao.Org.Table()+" o", "o.id=s.node_id AND s.scope_type='ORG'").
		Fields("s.role_id,s.scope_type,s.node_id,s.include_child,COALESCE(a.path,o.path,'') AS node_path").
		WhereIn("s.role_id", roleIDs).Order("s.id").Scan(&scopeRows); err != nil {
		return nil, err
	}
	for _, row := range scopeRows {
		role := rolesByID[row.RoleId]
		if role == nil {
			continue
		}
		scope := model.DataScope{NodeId: row.NodeId, IncludeChild: row.IncludeChild != 0}
		switch row.ScopeType {
		case model.ScopeTypeArea:
			role.AreaScopes = append(role.AreaScopes, scope)
			facts.scopePaths[treeKindArea][row.NodeId] = row.NodePath
		case model.ScopeTypeOrg:
			role.OrgScopes = append(role.OrgScopes, scope)
			facts.scopePaths[treeKindOrg][row.NodeId] = row.NodePath
		case model.ScopeTypeResourceArea:
			role.ResourceAreaScopes = append(role.ResourceAreaScopes, scope)
			facts.scopePaths[treeKindResArea][row.NodeId] = row.NodePath
		}
	}
	return facts, nil
}

func userIDsByRole(ctx context.Context, roleID int) ([]string, error) {
	var rows []struct{ UserId string }
	if err := dao.UserRole.Ctx(ctx).Fields(dao.UserRole.Columns().UserId).
		Where(dao.UserRole.Columns().RoleId, roleID).
		Order(dao.UserRole.Columns().UserId).Scan(&rows); err != nil {
		return nil, err
	}
	userIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		userIDs = append(userIDs, row.UserId)
	}
	return userIDs, nil
}

func findRole(ctx context.Context, id int) (*model.Role, error) {
	// 第 1 步：读取角色主体。不存在时返回 nil，交由上层区分新增和非法角色 ID。
	var row entity.Role
	if err := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	r := &model.Role{Id: int(row.Id), Name: row.Name, Description: row.Description, CreatedBy: row.CreatedBy}
	// 第 2 步：角色关系表直接保存稳定 menu_code；菜单名称和权限域从进程目录解析，
	// 避免每次角色冷加载再查询 menu 表。
	catalog, err := currentMenuCatalog()
	if err != nil {
		return nil, err
	}
	var menuRows []struct{ MenuCode string }
	if err := dao.RoleMenu.Ctx(ctx).
		Fields(dao.RoleMenu.Columns().MenuCode).
		Where(dao.RoleMenu.Columns().RoleId, id).
		Order(dao.RoleMenu.Columns().MenuCode).Scan(&menuRows); err != nil {
		return nil, err
	}
	for _, row := range menuRows {
		if menu := catalog.byCode[row.MenuCode]; menu != nil {
			switch menu.Domain {
			case model.MenuDomainSys:
				r.MenuConfigCodes = append(r.MenuConfigCodes, menu.Code)
			case model.MenuDomainApp:
				r.MenuAppCodes = append(r.MenuAppCodes, menu.Code)
			}
		}
	}
	// 第 3 步：一次读取角色的全部数据范围，再按类型装配为三个独立权限域。
	var scopeRows []entity.RoleDataScope
	if err := dao.RoleDataScope.Ctx(ctx).Where(dao.RoleDataScope.Columns().RoleId, id).
		Order(dao.RoleDataScope.Columns().Id).Scan(&scopeRows); err != nil {
		return nil, err
	}
	for _, row := range scopeRows {
		scope := model.DataScope{NodeId: int(row.NodeId), IncludeChild: row.IncludeChild != 0}
		switch row.ScopeType {
		case model.ScopeTypeArea:
			r.AreaScopes = append(r.AreaScopes, scope)
		case model.ScopeTypeOrg:
			r.OrgScopes = append(r.OrgScopes, scope)
		case model.ScopeTypeResourceArea:
			r.ResourceAreaScopes = append(r.ResourceAreaScopes, scope)
		}
	}
	return r, nil
}

func findArea(ctx context.Context, id int) (*model.Area, error) {
	var row entity.Area
	if err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Area{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path, Sort: row.Sort}, nil
}

func findOrg(ctx context.Context, id int) (*model.Org, error) {
	var row entity.Org
	if err := dao.Org.Ctx(ctx).Where(dao.Org.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Org{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path}, nil
}

func findResource(ctx context.Context, id int) (*model.Resource, error) {
	var row entity.Resource
	if err := dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Resource{Id: int(row.Id), AreaId: int(row.AreaId), Type: row.Type, Name: row.Name}, nil
}

// findTreeNode 把两种树的读取收在一个小入口里，调用方能同时拿到路径和名字。
// 找不到节点时返回空字符串，不把“不存在”和数据库错误混在一起。
func findTreeNode(ctx context.Context, kind string, id int) (string, string, error) {
	if kind == treeKindOrg {
		node, err := findOrg(ctx, id)
		if err != nil || node == nil {
			return "", "", err
		}
		return node.Path, node.Name, nil
	}
	node, err := findArea(ctx, id)
	if err != nil || node == nil {
		return "", "", err
	}
	return node.Path, node.Name, nil
}

func roleNameExists(ctx context.Context, name string, excludeID int) (bool, error) {
	m := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Name, name)
	if excludeID > 0 {
		m = m.WhereNot(dao.Role.Columns().Id, excludeID)
	}
	count, err := m.Count()
	return count > 0, err
}

func saveRole(ctx context.Context, role *model.Role, permissions *rolePermissionPlan) (*model.Role, error) {
	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 第 1 步：先在事务内创建或更新角色主体，新建时取得后续关系表需要的角色 ID。
		if role.Id <= 0 {
			result, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(do.Role{
				Name: role.Name, Description: role.Description, CreatedBy: role.CreatedBy,
			}).Insert()
			if err != nil {
				return err
			}
			id, err := result.LastInsertId()
			if err != nil {
				return err
			}
			role.Id = int(id)
		} else if _, err := tx.Model(dao.Role.Table()).Ctx(ctx).
			Data(do.Role{Name: role.Name, Description: role.Description}).
			Where(dao.Role.Columns().Id, role.Id).Update(); err != nil {
			return err
		}

		// permissions 省略表示本次只保存基本信息，权限关系表完全不参与写入。
		if permissions == nil {
			return nil
		}

		// 第 2 步：系统配置菜单和应用菜单分别替换；未提交的菜单域完全不参与写入。
		replaceMenuDomain := func(domain string, menuCodes *[]string) error {
			if menuCodes == nil {
				return nil
			}
			catalog, err := currentMenuCatalog()
			if err != nil {
				return err
			}
			domainMenuCodes := make([]string, 0)
			for menuCode, menu := range catalog.byCode {
				if menu.Domain == domain {
					domainMenuCodes = append(domainMenuCodes, menuCode)
				}
			}
			if len(domainMenuCodes) > 0 {
				if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).
					Where(dao.RoleMenu.Columns().RoleId, role.Id).
					WhereIn(dao.RoleMenu.Columns().MenuCode, domainMenuCodes).Delete(); err != nil {
					return err
				}
			}
			for _, menuCode := range *menuCodes {
				if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).
					Data(do.RoleMenu{RoleId: role.Id, MenuCode: menuCode}).Insert(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := replaceMenuDomain(model.MenuDomainSys, permissions.MenuConfigCodes); err != nil {
			return err
		}
		if err := replaceMenuDomain(model.MenuDomainApp, permissions.MenuAppCodes); err != nil {
			return err
		}

		// 第 3 步：树权限只删除 dels、写入 adds，未出现在请求中的记录保持不变。
		applyChanges := func(scopeType string, changes model.DataScopeChanges) error {
			for _, scope := range changes.Dels {
				if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
					Where(dao.RoleDataScope.Columns().RoleId, role.Id).
					Where(dao.RoleDataScope.Columns().ScopeType, scopeType).
					Where(dao.RoleDataScope.Columns().NodeId, scope.NodeId).
					Where(dao.RoleDataScope.Columns().IncludeChild, scope.IncludeChild).Delete(); err != nil {
					return err
				}
			}
			for _, scope := range changes.Adds {
				// Save 以 (role_id, scope_type, node_id) 唯一键保证重试安全。
				if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
					RoleId: role.Id, ScopeType: scopeType, NodeId: scope.NodeId, IncludeChild: scope.IncludeChild,
				}).Save(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := applyChanges(model.ScopeTypeArea, permissions.Area); err != nil {
			return err
		}
		if err := applyChanges(model.ScopeTypeOrg, permissions.Org); err != nil {
			return err
		}
		return applyChanges(model.ScopeTypeResourceArea, permissions.ResourceArea)
	})
	if err != nil {
		return nil, err
	}
	return findRole(ctx, role.Id)
}

func saveUser(ctx context.Context, user *model.User, exists bool) (*model.User, error) {
	if user.Id == "" {
		user.Id = uuid.NewString()
	}
	err := dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.User{Id: user.Id, Name: user.Name, OrgId: user.OrgId, IsSuperuser: user.IsSuperuser}
		if !exists {
			if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Insert(); err != nil {
				return gerror.Wrap(err, "新增用户失败")
			}
		} else if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).
			Where(dao.User.Columns().Id, user.Id).Update(); err != nil {
			return gerror.Wrap(err, "更新用户失败")
		}
		if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Where(dao.UserRole.Columns().UserId, user.Id).Delete(); err != nil {
			return gerror.Wrap(err, "清理用户旧角色失败")
		}
		for _, roleID := range user.RoleIds {
			if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Data(do.UserRole{UserId: user.Id, RoleId: roleID}).Insert(); err != nil {
				return gerror.Wrap(err, "绑定用户角色失败")
			}
		}
		return nil
	})
	if err != nil {
		return nil, gerror.Wrap(err, "保存用户失败")
	}
	saved, err := findUser(ctx, user.Id)
	if err != nil {
		return nil, gerror.Wrap(err, "保存后查询用户失败")
	}
	return saved, nil
}

func listAllAreas(ctx context.Context) ([]*model.Area, error) {
	var rows []entity.Area
	if err := dao.Area.Ctx(ctx).Order(dao.Area.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Area, 0, len(rows))
	for _, row := range rows {
		out = append(out, &model.Area{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path, Sort: row.Sort})
	}
	return out, nil
}

func listAllOrgs(ctx context.Context) ([]*model.Org, error) {
	var rows []entity.Org
	if err := dao.Org.Ctx(ctx).Order(dao.Org.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Org, 0, len(rows))
	for _, row := range rows {
		out = append(out, &model.Org{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path})
	}
	return out, nil
}

func listUsersByIDs(ctx context.Context, ids []string) ([]*model.User, error) {
	if len(ids) == 0 {
		return []*model.User{}, nil
	}
	var rows []entity.User
	if err := dao.User.Ctx(ctx).WhereIn(dao.User.Columns().Id, ids).
		Order(dao.User.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	byID := make(map[string]*model.User, len(rows))
	for _, row := range rows {
		byID[row.Id] = &model.User{
			Id: row.Id, Name: row.Name, OrgId: int(row.OrgId), IsSuperuser: row.IsSuperuser != 0,
			RoleIds: []int{},
		}
	}
	var bindings []struct {
		UserId string
		RoleId int
	}
	if err := dao.UserRole.Ctx(ctx).Fields(
		dao.UserRole.Columns().UserId, dao.UserRole.Columns().RoleId,
	).WhereIn(dao.UserRole.Columns().UserId, ids).
		Order(dao.UserRole.Columns().UserId + "," + dao.UserRole.Columns().RoleId).
		Scan(&bindings); err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if user := byID[binding.UserId]; user != nil {
			user.RoleIds = append(user.RoleIds, binding.RoleId)
		}
	}
	users := make([]*model.User, 0, len(rows))
	for _, user := range byID {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Id < users[j].Id })
	return users, nil
}

func userNameExists(ctx context.Context, name, excludeID string) (bool, error) {
	query := dao.User.Ctx(ctx).Where(dao.User.Columns().Name, name)
	if excludeID != "" {
		query = query.Where(dao.User.Columns().Id+" <> ?", excludeID)
	}
	count, err := query.Count()
	return count > 0, err
}
