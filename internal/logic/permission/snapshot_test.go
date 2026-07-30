package permission

import (
	"context"
	"strings"
	"testing"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/consts"
	"security-permission/internal/model"
)

var testTreePaths = map[string]map[int]string{
	treeKindArea:    {1: "/1/", 2: "/1/2/", 3: "/1/3/"},
	treeKindOrg:     {1: "/1/", 2: "/1/2/", 3: "/1/3/"},
	treeKindResArea: {1: "/1/", 2: "/1/2/", 3: "/1/3/"},
}

func newTestSnapshot(user *model.User, roles ...*model.Role) *permissionSnapshot {
	snapshot := &permissionSnapshot{
		user:      user,
		roles:     roles,
		menuCodes: map[string]bool{},
		filters:   map[string]treeFilter{},
		scopePaths: map[string]map[int]string{
			treeKindArea: {}, treeKindOrg: {}, treeKindResArea: {},
		},
	}
	if user.IsSuperuser {
		for _, kind := range []string{treeKindArea, treeKindOrg, treeKindResArea} {
			snapshot.filters[kind] = treeFilter{All: true}
		}
		return snapshot
	}
	for _, role := range roles {
		for _, code := range append(append([]string{}, role.MenuConfigCodes...), role.MenuAppCodes...) {
			snapshot.menuCodes[code] = true
		}
	}
	for _, kind := range []string{treeKindArea, treeKindOrg, treeKindResArea} {
		filter := treeFilter{}
		for _, role := range roles {
			for _, scope := range roleScopes(role, kind) {
				path := testTreePaths[kind][scope.NodeId]
				snapshot.scopePaths[kind][scope.NodeId] = path
				addScopeToFilter(&filter, scope, path)
			}
		}
		filter.None = len(filter.Prefixes) == 0 && len(filter.ExactIds) == 0
		snapshot.filters[kind] = filter
	}
	return snapshot
}

func TestSnapshotUsesOnlyCurrentUsersRoles(t *testing.T) {
	r1 := &model.Role{
		Id:              10,
		MenuConfigCodes: []string{menuRoleManage},
		AreaScopes:      []model.DataScope{{NodeId: 2, IncludeChild: true}},
	}
	r2 := &model.Role{
		Id: 20, CreatedBy: "deleted-user",
		MenuAppCodes:       []string{consts.MenuCodeAppVideoLive},
		AreaScopes:         []model.DataScope{{NodeId: 1, IncludeChild: true}},
		OrgScopes:          []model.DataScope{{NodeId: 1, IncludeChild: true}},
		ResourceAreaScopes: []model.DataScope{{NodeId: 1, IncludeChild: true}},
	}
	b := newTestSnapshot(&model.User{Id: "2"}, r1)
	c := newTestSnapshot(&model.User{Id: "3"}, r2)

	if b.covers(treeKindArea, "/1/3/", 3) {
		t.Fatal("R1 收紧以后，使用 R1 的用户不能再看到 B 区")
	}
	if !c.covers(treeKindArea, "/1/3/", 3) ||
		!c.covers(treeKindOrg, "/1/3/", 3) ||
		!c.covers(treeKindResArea, "/1/3/", 3) {
		t.Fatal("R2 保存过的三类范围应该独立生效")
	}
	if !c.hasMenu(consts.MenuCodeAppVideoLive) {
		t.Fatal("创建人被删掉以后，R2 自己的菜单权限仍然应该有效")
	}
}

func TestSnapshotSeparatesSingleNodeAndSubtreeGrant(t *testing.T) {
	role := &model.Role{Id: 10, AreaScopes: []model.DataScope{{NodeId: 2}}}
	snapshot := newTestSnapshot(&model.User{Id: "2"}, role)

	if !snapshot.canGrantScope(treeKindArea, "/1/2/", model.DataScope{NodeId: 2}) {
		t.Fatal("自己有单点权限时，可以继续授这个单点")
	}
	if snapshot.canGrantScope(treeKindArea, "/1/2/", model.DataScope{NodeId: 2, IncludeChild: true}) {
		t.Fatal("单点权限不能被放大成整棵子树")
	}
	if snapshot.canGrantScope(treeKindArea, "/1/3/", model.DataScope{NodeId: 3}) {
		t.Fatal("范围外的节点不能继续授权")
	}
}

func TestAreaAutoGrantOnlyForSingleNodeParent(t *testing.T) {
	exact := &model.Role{Id: 10, AreaScopes: []model.DataScope{{NodeId: 2}}}
	snapshot := newTestSnapshot(&model.User{Id: "2"}, exact)
	if roleID := snapshot.areaAutoGrantRole(&model.Area{Id: 2, Path: "/1/2/"}); roleID != 10 {
		t.Fatalf("父节点只有单点权限时，新子节点应该补到角色 10，实际是 %d", roleID)
	}

	subtree := &model.Role{Id: 20, AreaScopes: []model.DataScope{{NodeId: 1, IncludeChild: true}}}
	snapshot = newTestSnapshot(&model.User{Id: "2"}, subtree)
	if roleID := snapshot.areaAutoGrantRole(&model.Area{Id: 2, Path: "/1/2/"}); roleID != 0 {
		t.Fatalf("父级子树权限会自然覆盖新节点，不该重复加授权，实际是 %d", roleID)
	}
}

func TestReadEntryRequiresMatchingMenu(t *testing.T) {
	role := &model.Role{MenuAppCodes: []string{consts.MenuCodeAppVideoLive}}
	snapshot := newTestSnapshot(&model.User{Id: "3"}, role)
	if err := snapshot.requireAnyMenu(videoReadMenus...); err != nil {
		t.Fatalf("有视频菜单时应该放行：%v", err)
	}
	if err := snapshot.requireAnyMenu(manageAreaReadMenus...); gerror.Code(err) != gcode.CodeNotAuthorized {
		t.Fatalf("没有区域管理菜单时应该拒绝：%v", err)
	}
	if err := newTestSnapshot(&model.User{Id: "super", IsSuperuser: true}).
		requireAnyMenu("menu.not.present"); err != nil {
		t.Fatalf("超级管理员不依赖菜单记录：%v", err)
	}
}

func TestScopeChangesOnlyApplyExplicitOperations(t *testing.T) {
	old := []model.DataScope{{NodeId: 1, IncludeChild: true}, {NodeId: 2}}
	plan, err := planScopeChanges(old, model.DataScopeChanges{
		Dels: []model.DataScope{{NodeId: 1, IncludeChild: true}},
	})
	if err != nil {
		t.Fatalf("计算删除计划失败：%v", err)
	}
	if len(plan.Dels) != 1 || plan.Dels[0].NodeId != 1 || len(plan.Adds) != 0 {
		t.Fatalf("应该只删除节点 1，实际是 %+v", plan)
	}
	untouched, err := planScopeChanges(old, model.DataScopeChanges{})
	if err != nil || len(untouched.Adds) != 0 || len(untouched.Dels) != 0 {
		t.Fatalf("没提交的范围必须保持不变：plan=%+v err=%v", untouched, err)
	}
}

func TestScopeChangeRetryIsIdempotent(t *testing.T) {
	plan, err := planScopeChanges(
		[]model.DataScope{{NodeId: 1}},
		model.DataScopeChanges{
			Dels: []model.DataScope{{NodeId: 1, IncludeChild: true}},
			Adds: []model.DataScope{{NodeId: 1}},
		},
	)
	if err != nil || len(plan.Adds) != 0 || len(plan.Dels) != 0 {
		t.Fatalf("重复提交应该变成空操作：plan=%+v err=%v", plan, err)
	}
}

func TestMenuDomainsArePlannedIndependently(t *testing.T) {
	previousMenus, previousErr := processMenus, processMenusErr
	defer func() {
		processMenus, processMenusErr = previousMenus, previousErr
	}()
	var err error
	processMenus, err = buildMenuCatalog([]*model.Menu{
		{Code: consts.MenuCodeAppVideoLive, Domain: model.MenuDomainApp},
		{Code: consts.MenuCodeSysPersonRole, Domain: model.MenuDomainSys},
	})
	if err != nil {
		t.Fatalf("构造测试菜单目录失败：%v", err)
	}
	processMenusErr = nil

	old := &model.Role{
		MenuConfigCodes: []string{consts.MenuCodeSysPersonRole},
		MenuAppCodes:    []string{consts.MenuCodeAppVideoLive},
	}
	snapshot := newTestSnapshot(&model.User{Id: "2"}, &model.Role{
		MenuConfigCodes: []string{consts.MenuCodeSysPersonRole},
	})
	plan, err := prepareRolePermissions(context.Background(), snapshot, old, &model.RolePermissionChanges{
		MenuConfig: &model.MenuReplacement{Replace: []string{consts.MenuCodeSysPersonRole}},
	})
	if err != nil {
		t.Fatalf("生成系统菜单计划失败：%v", err)
	}
	if plan.MenuConfigCodes == nil || len(*plan.MenuConfigCodes) != 1 || plan.MenuAppCodes != nil {
		t.Fatalf("只提交 menuConfig 时，menuApp 不该参与写入：%+v", plan)
	}

	hidden, err := prepareRolePermissions(context.Background(), snapshot, old, &model.RolePermissionChanges{
		MenuApp: &model.MenuReplacement{Replace: []string{}},
	})
	if err != nil {
		t.Fatalf("保留范围外旧菜单失败：%v", err)
	}
	if hidden.MenuAppCodes == nil || len(*hidden.MenuAppCodes) != 1 ||
		(*hidden.MenuAppCodes)[0] != consts.MenuCodeAppVideoLive {
		t.Fatalf("编辑人看不到的旧菜单必须原样保留：%+v", hidden.MenuAppCodes)
	}

	_, err = prepareRolePermissions(context.Background(), snapshot, old, &model.RolePermissionChanges{
		MenuConfig: &model.MenuReplacement{Replace: []string{consts.MenuCodeAppVideoLive}},
	})
	if err == nil || !strings.Contains(err.Error(), "不能包含 APP 域菜单") {
		t.Fatalf("SYS 字段混入 APP 菜单应该被拒绝：%v", err)
	}
}
