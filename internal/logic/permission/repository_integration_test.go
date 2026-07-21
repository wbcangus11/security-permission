package permission

import (
	"context"
	"os"
	"testing"

	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
)

// Read-only smoke test for the configured database. It is opt-in so
// ordinary unit tests do not require MySQL.
func TestReadOnlyRepositoryIntegration(t *testing.T) {
	if os.Getenv("PERMISSION_INTEGRATION") != "1" {
		t.Skip("set PERMISSION_INTEGRATION=1 to run the read-only MySQL smoke test")
	}
	ctx := context.Background()
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
	ev := newEvaluator(ctx)
	if decision := ev.checkMenu(ev.user(superID), meta.Menus[0].Code); ev.err != nil || !decision.Allow {
		t.Fatalf("superuser menu check: decision=%+v err=%v", decision, ev.err)
	}
	if roles, err := ListRoles(ctx, superID); err != nil || len(roles) == 0 {
		t.Fatalf("superuser role list: count=%d err=%v", len(roles), err)
	}
	if users, err := ListUsers(ctx, superID); err != nil || len(users) == 0 {
		t.Fatalf("superuser user list: count=%d err=%v", len(users), err)
	}
	if orgs, err := ManageOrgs(ctx, superID); err != nil || len(orgs) == 0 {
		t.Fatalf("superuser org tree: count=%d err=%v", len(orgs), err)
	}
	if grantable, err := GrantableSet(ctx, superID); err != nil || !grantable.Unlimited {
		t.Fatalf("superuser grantable set: value=%+v err=%v", grantable, err)
	}
	hasAnyMenu := func(userID string, codes ...string) bool {
		t.Helper()
		ev := newEvaluator(ctx)
		user := ev.user(userID)
		for _, code := range codes {
			decision := ev.checkMenu(user, code)
			if ev.err != nil {
				t.Fatalf("menu decision for user %s and %s: %v", userID, code, ev.err)
			}
			if decision.Allow {
				return true
			}
		}
		return false
	}
	for _, user := range meta.Users {
		if _, err = SysMenus(ctx, user.Id); err != nil {
			t.Fatalf("system menus for user %s: %v", user.Id, err)
		}
		if _, err = AppMenus(ctx, user.Id); err != nil {
			t.Fatalf("app menus for user %s: %v", user.Id, err)
		}
		canViewVideo := hasAnyMenu(user.Id, videoReadMenus...)
		canManageArea := hasAnyMenu(user.Id, manageAreaReadMenus...)
		canManageOrg := hasAnyMenu(user.Id, manageOrgReadMenus...)
		canManageRole := hasAnyMenu(user.Id, menuRoleManage)
		if canManageOrg {
			if _, err = ManageOrgs(ctx, user.Id); err != nil {
				t.Fatalf("org tree for user %s: %v", user.Id, err)
			}
		}
		if canViewVideo {
			if _, err = AreaChildren(ctx, user.Id, 0, 1, 20); err != nil {
				t.Fatalf("app area tree for user %s: %v", user.Id, err)
			}
			if len(meta.Areas) > 0 {
				if _, err = SearchAppAreas(ctx, user.Id, meta.Areas[0].Name); err != nil {
					t.Fatalf("app area search for user %s: %v", user.Id, err)
				}
			}
		}
		if canManageArea {
			if _, err = ManageAreaChildren(ctx, user.Id, 0, 1, 20); err != nil {
				t.Fatalf("manage area tree for user %s: %v", user.Id, err)
			}
			if len(meta.Areas) > 0 {
				if _, err = SearchManageAreas(ctx, user.Id, meta.Areas[0].Name); err != nil {
					t.Fatalf("manage area search for user %s: %v", user.Id, err)
				}
			}
		}
		if _, err = ListRoles(ctx, user.Id); err != nil {
			t.Fatalf("role list for user %s: %v", user.Id, err)
		}
		if _, err = ListUsers(ctx, user.Id); err != nil {
			t.Fatalf("user list for user %s: %v", user.Id, err)
		}
		if canManageRole {
			if _, err = GrantableSet(ctx, user.Id); err != nil {
				t.Fatalf("grantable set for user %s: %v", user.Id, err)
			}
		}
		if canViewVideo && len(meta.Areas) > 0 {
			areaID := meta.Areas[0].Id
			if _, err = AreaResourcesPaged(ctx, user.Id, areaID, 1, 20); err != nil {
				t.Fatalf("resource page for user %s: %v", user.Id, err)
			}
		}
	}
}
