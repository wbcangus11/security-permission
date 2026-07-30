package permission

import (
	"context"
	"os"
	"testing"

	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"

	"security-permission/internal/consts"
)

func testUserContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, consts.ContextKeyUserId, userID)
}

// 这是针对当前配置数据库的只读冒烟测试。
// 测试默认关闭，避免普通单元测试依赖 MySQL。
func TestReadOnlyRepositoryIntegration(t *testing.T) {
	if os.Getenv("PERMISSION_INTEGRATION") != "1" {
		t.Skip("set PERMISSION_INTEGRATION=1 to run the read-only MySQL smoke test")
	}
	ctx := context.Background()
	if err := InitializeMenuCatalog(ctx); err != nil {
		t.Fatalf("initialize menu catalog: %v", err)
	}
	meta, err := Meta(ctx)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if len(meta.Areas) == 0 || len(meta.Orgs) == 0 || len(meta.Menus) == 0 || len(meta.Users) == 0 {
		t.Fatalf("expected seeded permission dictionaries, got areas=%d orgs=%d menus=%d users=%d",
			len(meta.Areas), len(meta.Orgs), len(meta.Menus), len(meta.Users))
	}
	var superID string
	for _, user := range meta.Users {
		if user.IsSuperuser {
			superID = user.Id
			break
		}
	}
	if superID == "" {
		t.Fatal("expected at least one superuser")
	}
	superCtx := testUserContext(ctx, superID)
	InvalidateUser(superID)
	superSnapshot, err := loadPermissionSnapshot(superCtx)
	if err != nil || !superSnapshot.hasMenu(meta.Menus[0].Code) {
		t.Fatalf("superuser menu check: err=%v", err)
	}
	cachedSuperSnapshot, err := loadPermissionSnapshot(superCtx)
	if err != nil || cachedSuperSnapshot != superSnapshot {
		t.Fatalf("superuser snapshot cache miss: same=%v err=%v", cachedSuperSnapshot == superSnapshot, err)
	}
	InvalidateUser(superID)
	reloadedSuperSnapshot, err := loadPermissionSnapshot(superCtx)
	if err != nil || reloadedSuperSnapshot == superSnapshot {
		t.Fatalf("superuser snapshot should reload after invalidation: same=%v err=%v",
			reloadedSuperSnapshot == superSnapshot, err)
	}
	access, err := ForUser(superCtx)
	if err != nil || !access.HasMenu(meta.Menus[0].Code) || !access.IsSuperuser() {
		t.Fatalf("public permission access: value=%+v err=%v", access, err)
	}
	if roles, err := ListRoles(superCtx); err != nil || len(roles) == 0 {
		t.Fatalf("superuser role list: count=%d err=%v", len(roles), err)
	}
	if users, err := ListUsers(superCtx); err != nil || len(users) == 0 {
		t.Fatalf("superuser user list: count=%d err=%v", len(users), err)
	}
	if orgs, err := ManageOrgs(superCtx); err != nil || len(orgs) == 0 {
		t.Fatalf("superuser org tree: count=%d err=%v", len(orgs), err)
	}
	if grantable, err := GrantableSet(superCtx); err != nil || !grantable.Unlimited {
		t.Fatalf("superuser grantable set: value=%+v err=%v", grantable, err)
	}
	hasAnyMenu := func(userID string, codes ...string) bool {
		t.Helper()
		snapshot, err := loadPermissionSnapshot(testUserContext(ctx, userID))
		if err != nil {
			t.Fatalf("permission snapshot for user %s: %v", userID, err)
		}
		return snapshot.hasAnyMenu(codes...)
	}
	for _, user := range meta.Users {
		userCtx := testUserContext(ctx, user.Id)
		if _, err = SysMenus(userCtx); err != nil {
			t.Fatalf("system menus for user %s: %v", user.Id, err)
		}
		if _, err = AppMenus(userCtx); err != nil {
			t.Fatalf("app menus for user %s: %v", user.Id, err)
		}
		canViewVideo := hasAnyMenu(user.Id, videoReadMenus...)
		canManageArea := hasAnyMenu(user.Id, manageAreaReadMenus...)
		canManageOrg := hasAnyMenu(user.Id, manageOrgReadMenus...)
		canManageRole := hasAnyMenu(user.Id, menuRoleManage)
		canManageAccount := hasAnyMenu(user.Id, menuAccountManage)
		if canManageOrg {
			if _, err = ManageOrgs(userCtx); err != nil {
				t.Fatalf("org tree for user %s: %v", user.Id, err)
			}
		}
		if canViewVideo {
			if _, err = AreaChildren(userCtx, 0, 1, 20); err != nil {
				t.Fatalf("app area tree for user %s: %v", user.Id, err)
			}
			if len(meta.Areas) > 0 {
				if _, err = SearchAppAreas(userCtx, meta.Areas[0].Name); err != nil {
					t.Fatalf("app area search for user %s: %v", user.Id, err)
				}
			}
		}
		if canManageArea {
			if _, err = ManageAreaChildren(userCtx, 0, 1, 20); err != nil {
				t.Fatalf("manage area tree for user %s: %v", user.Id, err)
			}
			if len(meta.Areas) > 0 {
				if _, err = SearchManageAreas(userCtx, meta.Areas[0].Name); err != nil {
					t.Fatalf("manage area search for user %s: %v", user.Id, err)
				}
			}
		}
		if canManageRole {
			if _, err = ListRoles(userCtx); err != nil {
				t.Fatalf("role list for user %s: %v", user.Id, err)
			}
			if _, err = GrantableSet(userCtx); err != nil {
				t.Fatalf("grantable set for user %s: %v", user.Id, err)
			}
		}
		if canManageAccount {
			if _, err = ListUsers(userCtx); err != nil {
				t.Fatalf("user list for user %s: %v", user.Id, err)
			}
		}
		if canViewVideo && len(meta.Areas) > 0 {
			areaID := meta.Areas[0].Id
			if _, err = AreaResourcesPaged(userCtx, areaID, 1, 20); err != nil {
				t.Fatalf("resource page for user %s: %v", user.Id, err)
			}
		}
	}
}
