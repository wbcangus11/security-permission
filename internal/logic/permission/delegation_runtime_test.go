package permission

import (
	"testing"

	"security-permission/internal/model"
)

func newRuntimeCapPermission() *PermissionService {
	store := &Store{
		menus: map[int]*model.Menu{
			1: {Id: 1, Code: "app.video.live", Name: "实时预览", Domain: model.MenuDomainApp},
			2: {Id: 2, Code: menuRoleManage, Name: "角色管理", Domain: model.MenuDomainSys},
		},
		areas: map[int]*model.Area{
			1: {Id: 1, Name: "根区域", Path: "/1/"},
			2: {Id: 2, ParentId: 1, Name: "A区", Path: "/1/2/"},
			3: {Id: 3, ParentId: 1, Name: "B区", Path: "/1/3/"},
		},
		orgs: map[int]*model.Org{
			1: {Id: 1, Name: "根组织", Path: "/1/"},
			2: {Id: 2, ParentId: 1, Name: "研发部", Path: "/1/2/"},
			3: {Id: 3, ParentId: 1, Name: "财务部", Path: "/1/3/"},
		},
		resources: map[int]*model.Resource{
			100: {Id: 100, AreaId: 2, Name: "A区摄像头"},
		},
		actions: []model.Action{{Code: "live", Name: "实时预览"}},
		roles: map[int]*model.Role{
			10: {
				Id:        10,
				Name:      "上级授权",
				CreatedBy: "0",
				MenuIds:   []int{1, 2},
				AreaScopes: []model.DataScope{
					{NodeId: 2, IncludeChild: true},
				},
				OrgScopes: []model.DataScope{
					{NodeId: 2, IncludeChild: true},
				},
				ResourceAreaScopes: []model.DataScope{
					{NodeId: 2, IncludeChild: true},
				},
			},
			20: {
				Id:        20,
				Name:      "张三创建",
				CreatedBy: "1",
				MenuIds:   []int{1},
				AreaScopes: []model.DataScope{
					{NodeId: 1, IncludeChild: true},
				},
				OrgScopes: []model.DataScope{
					{NodeId: 1, IncludeChild: true},
				},
				ResourceAreaScopes: []model.DataScope{
					{NodeId: 1, IncludeChild: true},
				},
			},
		},
		users: map[string]*model.User{
			"1": {Id: "1", Name: "张三", RoleIds: []int{10}},
			"2": {Id: "2", Name: "李四", RoleIds: []int{20}},
		},
	}
	return &PermissionService{Store: store}
}

func TestResourceRequiresFunctionAndDataPermission(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")
	s.roles[20].MenuIds = nil

	if d := s.CheckResource(li, 100, "live"); d.Allow {
		t.Fatalf("expected missing action menu to deny resource access, got allow: %s", d.Reason)
	}
}

func TestDelegatedRoleRuntimeCapForArea(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")

	if d := s.CheckArea(li, 2); !d.Allow {
		t.Fatalf("expected delegated role to keep creator-current area, got deny: %s", d.Reason)
	}
	if d := s.CheckArea(li, 3); d.Allow {
		t.Fatalf("expected delegated role to lose area outside creator-current cap, got allow: %s", d.Reason)
	}
}

func TestDelegatedRoleRuntimeCapForResourceArea(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")

	if !s.userResAreaCovers(li, 2) {
		t.Fatal("expected delegated resource area to keep creator-current area")
	}
	if s.userResAreaCovers(li, 3) {
		t.Fatal("expected delegated resource area outside creator-current cap to be denied")
	}
}

func TestDelegatedRoleRuntimeCapForOrg(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")

	if d := s.CheckOrg(li, 2); !d.Allow {
		t.Fatalf("expected delegated role to keep creator-current org, got deny: %s", d.Reason)
	}
	if d := s.CheckOrg(li, 3); d.Allow {
		t.Fatalf("expected delegated role to lose org outside creator-current cap, got allow: %s", d.Reason)
	}
}

func TestDelegatedRoleRuntimeCapForPagedTreeFilter(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")

	v := &ViewService{Store: s.Store, PermissionService: s}
	f := v.treeScopeFilter(li, treeKindResArea)
	if f.None {
		t.Fatal("expected at least one effective resource area")
	}
	if f.covers("/1/3/", 3) {
		t.Fatal("expected paged tree filter to exclude area outside creator-current cap")
	}
	if !f.covers("/1/2/", 2) {
		t.Fatal("expected paged tree filter to include creator-current area")
	}
}
