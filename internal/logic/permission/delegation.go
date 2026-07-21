package permission

import (
	"context"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// 角色委派采用“写时限制、运行时独立生效”：创建或编辑角色时，操作者只能授予
// 自己当前拥有的权限；保存后角色不再随创建人的权限变化而自动收窄。
// 保存时只检查本次提交及旧角色中实际出现的 ID，不为了鉴权加载整张树。

func mergeScopes(old, submitted []model.DataScope, grantable map[int]bool) ([]model.DataScope, int) {
	out := make([]model.DataScope, 0, len(old)+len(submitted))
	seen := map[int]bool{}
	for _, scope := range submitted {
		if scope.NodeId > 0 && grantable[scope.NodeId] && !seen[scope.NodeId] {
			out = append(out, scope)
			seen[scope.NodeId] = true
		}
	}
	preserved := 0
	for _, scope := range old {
		if scope.NodeId > 0 && !grantable[scope.NodeId] && !seen[scope.NodeId] {
			out = append(out, scope)
			seen[scope.NodeId] = true
			preserved++
		}
	}
	return out, preserved
}

func uniqueMenuIDs(old, submitted *model.Role) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, source := range [][]int{submitted.MenuIds, old.MenuIds} {
		for _, id := range source {
			if id > 0 && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func uniqueScopeIDs(old, submitted []model.DataScope) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, source := range [][]model.DataScope{submitted, old} {
		for _, scope := range source {
			if scope.NodeId > 0 && !seen[scope.NodeId] {
				seen[scope.NodeId] = true
				out = append(out, scope.NodeId)
			}
		}
	}
	return out
}

func (e *evaluator) mergeDelegated(userID string, old, submitted *model.Role) (*model.Role, int) {
	if old == nil {
		old = &model.Role{}
	}
	user := e.user(userID)
	if user == nil {
		return submitted, 0
	}
	if user.IsSuperuser {
		return submitted, 0
	}

	menuGrant := map[int]bool{}
	for _, id := range uniqueMenuIDs(old, submitted) {
		menuGrant[id] = e.userHasMenuID(user, id)
	}
	areaGrant := map[int]bool{}
	for _, id := range uniqueScopeIDs(old.AreaScopes, submitted.AreaScopes) {
		areaGrant[id] = e.checkTree(user, id, treeKindArea).Allow
	}
	orgGrant := map[int]bool{}
	for _, id := range uniqueScopeIDs(old.OrgScopes, submitted.OrgScopes) {
		orgGrant[id] = e.checkTree(user, id, treeKindOrg).Allow
	}
	resourceAreaGrant := map[int]bool{}
	for _, id := range uniqueScopeIDs(old.ResourceAreaScopes, submitted.ResourceAreaScopes) {
		resourceAreaGrant[id] = e.userResourceAreaCovers(user, id)
	}

	result := &model.Role{
		Id:          submitted.Id,
		Name:        submitted.Name,
		Description: submitted.Description,
		CreatedBy:   submitted.CreatedBy,
	}
	preserved := 0
	seenMenu := map[int]bool{}
	for _, id := range submitted.MenuIds {
		if id > 0 && menuGrant[id] && !seenMenu[id] {
			result.MenuIds = append(result.MenuIds, id)
			seenMenu[id] = true
		}
	}
	for _, id := range old.MenuIds {
		if id > 0 && !menuGrant[id] && !seenMenu[id] {
			result.MenuIds = append(result.MenuIds, id)
			seenMenu[id] = true
			preserved++
		}
	}

	var count int
	result.AreaScopes, count = mergeScopes(old.AreaScopes, submitted.AreaScopes, areaGrant)
	preserved += count
	result.OrgScopes, count = mergeScopes(old.OrgScopes, submitted.OrgScopes, orgGrant)
	preserved += count
	result.ResourceAreaScopes, count = mergeScopes(old.ResourceAreaScopes, submitted.ResourceAreaScopes, resourceAreaGrant)
	preserved += count
	return result, preserved
}

func emptyGrantable() *model.Grantable {
	return &model.Grantable{
		MenuCodes: []string{}, AreaIds: []int{},
		OrgIds: []int{}, ResAreaIds: []int{},
	}
}

// grantableSet 是角色编辑页的显式全集接口。只有该接口需要遍历菜单和树节点；
// 数据只存在于当前请求的局部变量中，请求结束即释放。
func (e *evaluator) grantableSet(userID string) *model.Grantable {
	grantable := emptyGrantable()
	user := e.user(userID)
	if user == nil || e.err != nil {
		return grantable
	}
	if user.IsSuperuser {
		grantable.Unlimited = true
		return grantable
	}

	for _, menu := range e.menus() {
		if e.userHasMenuID(user, menu.Id) {
			grantable.MenuCodes = append(grantable.MenuCodes, menu.Code)
		}
	}
	areas, err := listAllAreas(e.ctx)
	e.fail(err)
	for _, area := range areas {
		e.areas[area.Id] = area
		e.areaLoaded[area.Id] = true
		if e.checkTree(user, area.Id, treeKindArea).Allow {
			grantable.AreaIds = append(grantable.AreaIds, area.Id)
		}
		if e.userResourceAreaCovers(user, area.Id) {
			grantable.ResAreaIds = append(grantable.ResAreaIds, area.Id)
		}
	}
	orgs, err := listAllOrgs(e.ctx)
	e.fail(err)
	for _, org := range orgs {
		e.orgs[org.Id] = org
		e.orgLoaded[org.Id] = true
		if e.checkTree(user, org.Id, treeKindOrg).Allow {
			grantable.OrgIds = append(grantable.OrgIds, org.Id)
		}
	}
	return grantable
}

func (e *evaluator) manageableRoles(userID string) (map[int]bool, bool) {
	set := map[int]bool{}
	user := e.user(userID)
	if user == nil || e.err != nil {
		return set, false
	}
	if user.IsSuperuser {
		return set, true
	}
	var rows []struct{ Id int }
	if err := dao.Role.Ctx(e.ctx).Fields(dao.Role.Columns().Id).
		Where(dao.Role.Columns().CreatedBy, userID).Scan(&rows); err != nil {
		e.fail(err)
		return set, false
	}
	for _, row := range rows {
		set[row.Id] = true
	}
	return set, false
}

func GrantableSet(ctx context.Context, userID string) (*model.Grantable, error) {
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return emptyGrantable(), ev.err
	}
	if err := ev.requireAnyMenu(user, menuRoleManage); err != nil {
		return emptyGrantable(), err
	}
	grantable := ev.grantableSet(userID)
	return grantable, ev.err
}
