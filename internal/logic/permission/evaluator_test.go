package permission

import (
	"context"
	"strings"
	"testing"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/model"
)

func newIndependentRoleEvaluator() *evaluator {
	ev := newEvaluator(context.Background())
	menu := &model.Menu{Id: 1, Code: "app.video.live", Name: "实时预览", Domain: model.MenuDomainApp}
	ev.menusByCode[menu.Code], ev.menuCodeSeen[menu.Code] = menu, true
	roleMenu := &model.Menu{Id: 2, Code: menuRoleManage, Name: "角色管理", Domain: model.MenuDomainSys}
	ev.menusByCode[roleMenu.Code], ev.menuCodeSeen[roleMenu.Code] = roleMenu, true
	for index, code := range []string{
		"app.video.playback", "app.video.picture", menuAreaManage,
		menuResourceManage, menuOrgManage, menuAccountManage,
	} {
		id := index + 3
		item := &model.Menu{Id: id, Code: code, Name: code}
		ev.menusByCode[code], ev.menuCodeSeen[code] = item, true
	}

	for _, area := range []*model.Area{
		{Id: 1, Name: "根区域", Path: "/1/"},
		{Id: 2, ParentId: 1, Name: "A区", Path: "/1/2/"},
		{Id: 3, ParentId: 1, Name: "B区", Path: "/1/3/"},
	} {
		ev.areas[area.Id], ev.areaLoaded[area.Id] = area, true
	}
	for _, org := range []*model.Org{
		{Id: 1, Name: "根组织", Path: "/1/"},
		{Id: 2, ParentId: 1, Name: "研发部", Path: "/1/2/"},
		{Id: 3, ParentId: 1, Name: "财务部", Path: "/1/3/"},
	} {
		ev.orgs[org.Id], ev.orgLoaded[org.Id] = org, true
	}
	resource := &model.Resource{Id: 100, AreaId: 2, Name: "A区摄像头"}
	ev.resources[resource.Id], ev.resLoaded[resource.Id] = resource, true

	roles := []*model.Role{
		{
			Id: 10, Name: "A 创建的 R1", CreatedBy: "1", MenuIds: []int{1, 2},
			AreaScopes:         []model.DataScope{{NodeId: 1, IncludeChild: true}},
			OrgScopes:          []model.DataScope{{NodeId: 1, IncludeChild: true}},
			ResourceAreaScopes: []model.DataScope{{NodeId: 1, IncludeChild: true}},
		},
		{
			Id: 20, Name: "B 创建的 R2", CreatedBy: "2", MenuIds: []int{1},
			AreaScopes:         []model.DataScope{{NodeId: 1, IncludeChild: true}},
			OrgScopes:          []model.DataScope{{NodeId: 1, IncludeChild: true}},
			ResourceAreaScopes: []model.DataScope{{NodeId: 1, IncludeChild: true}},
		},
	}
	for _, role := range roles {
		ev.roles[role.Id], ev.roleLoaded[role.Id] = role, true
	}
	users := []*model.User{
		{Id: "1", Name: "A"},
		{Id: "2", Name: "B", RoleIds: []int{10}},
		{Id: "3", Name: "C", RoleIds: []int{20}},
	}
	for _, user := range users {
		ev.users[user.Id], ev.userLoaded[user.Id] = user, true
	}
	ev.userLoaded["missing"] = true
	return ev
}

func shrinkR1(ev *evaluator) {
	r1 := ev.roles[10]
	r1.MenuIds = []int{2}
	r1.AreaScopes = []model.DataScope{{NodeId: 2, IncludeChild: true}}
	r1.OrgScopes = []model.DataScope{{NodeId: 2, IncludeChild: true}}
	r1.ResourceAreaScopes = []model.DataScope{{NodeId: 2, IncludeChild: true}}
}

func TestSavedR2DoesNotShrinkWhenR1IsTightened(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	shrinkR1(ev)

	b := ev.user("2")
	if decision := ev.checkTree(b, 3, treeKindArea); decision.Allow {
		t.Fatal("B must lose the area removed from R1")
	}
	if ev.userHasMenuID(b, 1) {
		t.Fatal("B must lose the menu removed from R1")
	}

	c := ev.user("3")
	if decision := ev.checkTree(c, 3, treeKindArea); !decision.Allow {
		t.Fatalf("C must retain R2's saved area permission: %s", decision.Reason)
	}
	if decision := ev.checkTree(c, 3, treeKindOrg); !decision.Allow {
		t.Fatalf("C must retain R2's saved org permission: %s", decision.Reason)
	}
	if !ev.userResourceAreaCovers(c, 3) {
		t.Fatal("C must retain R2's saved video-area permission")
	}
	if !ev.userHasMenuID(c, 1) {
		t.Fatal("C must retain R2's saved menu permission")
	}
}

func TestSavedRoleStillWorksAfterCreatorIsDeleted(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	delete(ev.users, "2")
	ev.userLoaded["2"] = true

	c := ev.user("3")
	if decision := ev.checkTree(c, 3, treeKindArea); !decision.Allow {
		t.Fatalf("creator deletion must not invalidate R2: %s", decision.Reason)
	}
	if !ev.userHasMenuID(c, 1) || !ev.userResourceAreaCovers(c, 3) {
		t.Fatal("creator deletion must not invalidate R2 menu or video-area permissions")
	}
}

func TestEditingPreservesSavedPermissionsOutsideCurrentGrantableSet(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	shrinkR1(ev)
	old := ev.roles[20]
	submitted := &model.Role{Id: 20, Name: old.Name, CreatedBy: old.CreatedBy}

	merged, preserved := ev.mergeDelegated("2", old, submitted)
	if preserved != 4 {
		t.Fatalf("expected one menu and three scopes to be preserved, got %d", preserved)
	}
	if !roleHasMenuID(merged, 1) || len(merged.AreaScopes) != 1 || merged.AreaScopes[0].NodeId != 1 ||
		len(merged.OrgScopes) != 1 || merged.OrgScopes[0].NodeId != 1 ||
		len(merged.ResourceAreaScopes) != 1 || merged.ResourceAreaScopes[0].NodeId != 1 {
		t.Fatal("opening or saving R2 must not silently remove permissions B can no longer grant")
	}
}

func TestTreeCheckUsesResourceAreaScopesForResAreaKind(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	ev.roles[20].AreaScopes = nil
	if decision := ev.checkTree(ev.user("3"), 2, treeKindResArea); !decision.Allow {
		t.Fatalf("RES_AREA check must not fall back to AREA scopes: %s", decision.Reason)
	}
}

func TestResourceRequiresActionMenuAndVideoArea(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	user := ev.user("3")
	if decision := ev.checkResource(user, 100, "live"); !decision.Allow {
		t.Fatalf("expected resource access: %s", decision.Reason)
	}
	ev.roles[20].MenuIds = nil
	if decision := ev.checkResource(user, 100, "live"); decision.Allow {
		t.Fatal("resource access must be denied without its action menu")
	}
}

func TestCompactTreeFilterUsesSavedRoleScope(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	shrinkR1(ev)
	if filter := ev.treeScopeFilter(ev.user("2"), treeKindResArea); filter.covers("/1/3/", 3) {
		t.Fatal("B's filter must reflect tightened R1")
	}
	if filter := ev.treeScopeFilter(ev.user("3"), treeKindResArea); filter.None || !filter.covers("/1/3/", 3) {
		t.Fatal("C's filter must continue using R2's saved scope")
	}
}

func TestRoleWriterRequiresIdentityAndMenu(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	if err := ev.guardRoleWriter("missing"); err == nil || !strings.Contains(err.Error(), "操作人不存在") {
		t.Fatalf("expected missing identity denial, got %v", err)
	}
	if err := ev.guardRoleWriter("3"); err == nil || !strings.Contains(err.Error(), "功能权限不足") {
		t.Fatalf("expected role menu denial, got %v", err)
	}
}

func TestReadEntryRequiresMatchingFunctionMenu(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	user := ev.user("3")
	if err := ev.requireAnyMenu(user, videoReadMenus...); err != nil {
		t.Fatalf("expected video menu gate to pass: %v", err)
	}
	if err := ev.requireAnyMenu(user, manageAreaReadMenus...); gerror.Code(err) != gcode.CodeNotAuthorized {
		t.Fatalf("expected management area gate denial, got %v", err)
	}
	if err := ev.requireAnyMenu(user, manageOrgReadMenus...); gerror.Code(err) != gcode.CodeNotAuthorized {
		t.Fatalf("expected management org gate denial, got %v", err)
	}

	ev.roles[20].MenuIds = nil
	if err := ev.requireAnyMenu(user, videoReadMenus...); gerror.Code(err) != gcode.CodeNotAuthorized {
		t.Fatalf("data scope without a video menu must be denied, got %v", err)
	}
}

func TestSuperuserPassesFunctionGateWithoutMenuRows(t *testing.T) {
	ev := newIndependentRoleEvaluator()
	super := &model.User{Id: "super", IsSuperuser: true}
	if err := ev.requireAnyMenu(super, "menu.not.present"); err != nil {
		t.Fatalf("superuser gate: %v", err)
	}
}
