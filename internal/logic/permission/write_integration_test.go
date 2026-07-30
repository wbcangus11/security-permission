package permission

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// 这个测试会短暂写入一个角色和一个用户，所以默认不跑。
// 手动打开后，它会把“命中缓存 -> 修改角色 -> 立刻失效”整条链路走一遍。
func TestWritePermissionCacheInvalidationIntegration(t *testing.T) {
	if os.Getenv("PERMISSION_WRITE_INTEGRATION") != "1" {
		t.Skip("set PERMISSION_WRITE_INTEGRATION=1 to run the writable MySQL test")
	}

	ctx := context.Background()
	if err := InitializeMenuCatalog(ctx); err != nil {
		t.Fatalf("初始化菜单目录失败：%+v", err)
	}

	meta, err := Meta(ctx)
	if err != nil {
		t.Fatalf("读取基础数据失败：%+v", err)
	}
	var superID string
	for _, user := range meta.Users {
		if user.IsSuperuser {
			superID = user.Id
			break
		}
	}
	if superID == "" {
		t.Fatal("数据库里没有超级管理员")
	}
	superCtx := testUserContext(ctx, superID)

	suffix := time.Now().UnixNano()
	roleName := fmt.Sprintf("cache-role-%d", suffix)
	userInput := &model.User{
		Name:  fmt.Sprintf("cache-user-%d", suffix),
		OrgId: meta.Orgs[0].Id,
	}

	role, err := SaveRole(superCtx, &model.RoleSaveInput{
		Name:        roleName,
		Description: "cache invalidation integration test",
		Permissions: &model.RolePermissionChanges{
			MenuConfig: &model.MenuReplacement{Replace: []string{menuRoleManage}},
		},
	})
	if err != nil {
		t.Fatalf("创建测试角色失败：%+v", err)
	}

	// 就算中途失败也直接按主键清理，避免测试数据留在开发库里。
	defer func() {
		if userInput.Id != "" {
			_, _ = dao.User.Ctx(ctx).Where(dao.User.Columns().Id, userInput.Id).Delete()
			InvalidateUser(userInput.Id)
		}
		_, _ = dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, role.Id).Delete()
	}()

	userInput.RoleIds = []int{role.Id}
	savedUser, err := SaveUser(superCtx, userInput)
	if err != nil {
		t.Fatalf("创建测试用户失败：%+v", err)
	}
	if savedUser == nil {
		t.Fatal("创建用户成功后没有返回用户")
	}
	userCtx := testUserContext(ctx, savedUser.Id)

	if _, err = ListRoles(userCtx); err != nil {
		t.Fatalf("测试用户第一次读取角色失败：%+v", err)
	}
	if _, err = ListRoles(userCtx); err != nil {
		t.Fatalf("测试用户命中缓存后读取角色失败：%+v", err)
	}

	_, err = SaveRole(superCtx, &model.RoleSaveInput{
		RoleId:      role.Id,
		Name:        role.Name,
		Description: role.Description,
		Permissions: &model.RolePermissionChanges{
			MenuConfig: &model.MenuReplacement{Replace: []string{}},
		},
	})
	if err != nil {
		t.Fatalf("移除测试角色权限失败：%+v", err)
	}
	if _, err = ListRoles(userCtx); err == nil {
		t.Fatal("角色权限修改后仍然读到了旧缓存")
	}
}
