package permission

import (
	"context"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

func emptyGrantable() *model.Grantable {
	return &model.Grantable{
		MenuConfigCodes: []string{}, MenuAppCodes: []string{},
		AreaIds: []int{}, OrgIds: []int{}, ResAreaIds: []int{},
		AreaScopes: []model.DataScope{}, OrgScopes: []model.DataScope{}, ResAreaScopes: []model.DataScope{},
	}
}

func appendUniqueScope(target []model.DataScope, seen map[model.DataScope]bool, scopes []model.DataScope) []model.DataScope {
	for _, scope := range scopes {
		if scope.NodeId <= 0 || seen[scope] {
			continue
		}
		seen[scope] = true
		target = append(target, scope)
	}
	return target
}

// GrantableSet 是角色编辑页唯一需要的权限全集。
// 这里明确查完整菜单和树，普通列表接口就不用背这些大字段。
func GrantableSet(ctx context.Context) (*model.Grantable, error) {
	snapshot, err := loadPermissionSnapshot(ctx)
	if err != nil {
		return emptyGrantable(), err
	}
	if err := snapshot.requireAnyMenu(menuRoleManage); err != nil {
		return emptyGrantable(), err
	}

	grantable := emptyGrantable()
	if snapshot.isSuper() {
		grantable.Unlimited = true
		return grantable, nil
	}

	areaSeen := map[model.DataScope]bool{}
	orgSeen := map[model.DataScope]bool{}
	resAreaSeen := map[model.DataScope]bool{}
	for _, role := range snapshot.roles {
		grantable.AreaScopes = appendUniqueScope(grantable.AreaScopes, areaSeen, role.AreaScopes)
		grantable.OrgScopes = appendUniqueScope(grantable.OrgScopes, orgSeen, role.OrgScopes)
		grantable.ResAreaScopes = appendUniqueScope(grantable.ResAreaScopes, resAreaSeen, role.ResourceAreaScopes)
	}

	menus, err := catalogMenus()
	if err != nil {
		return nil, err
	}
	for _, menu := range menus {
		if !snapshot.hasMenu(menu.Code) {
			continue
		}
		switch menu.Domain {
		case model.MenuDomainSys:
			grantable.MenuConfigCodes = append(grantable.MenuConfigCodes, menu.Code)
		case model.MenuDomainApp:
			grantable.MenuAppCodes = append(grantable.MenuAppCodes, menu.Code)
		}
	}

	areas, err := listAllAreas(ctx)
	if err != nil {
		return nil, err
	}
	for _, area := range areas {
		if snapshot.covers(treeKindArea, area.Path, area.Id) {
			grantable.AreaIds = append(grantable.AreaIds, area.Id)
		}
		if snapshot.covers(treeKindResArea, area.Path, area.Id) {
			grantable.ResAreaIds = append(grantable.ResAreaIds, area.Id)
		}
	}
	orgs, err := listAllOrgs(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if snapshot.covers(treeKindOrg, org.Path, org.Id) {
			grantable.OrgIds = append(grantable.OrgIds, org.Id)
		}
	}
	return grantable, nil
}

// manageableRoles 返回当前管理员能分配给用户的角色。
// 超级管理员用 unlimited=true 表示全量，不需要再查一遍所有角色 ID。
func manageableRoles(ctx context.Context, snapshot *permissionSnapshot) (map[int]bool, bool, error) {
	set := map[int]bool{}
	if snapshot.isSuper() {
		return set, true, nil
	}
	var rows []struct{ Id int }
	if err := dao.Role.Ctx(ctx).Fields(dao.Role.Columns().Id).
		Where(dao.Role.Columns().CreatedBy, snapshot.user.Id).Scan(&rows); err != nil {
		return nil, false, err
	}
	for _, row := range rows {
		set[row.Id] = true
	}
	return set, false, nil
}
