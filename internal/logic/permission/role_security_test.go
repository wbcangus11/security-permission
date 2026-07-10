package permission

import (
	"context"
	"strings"
	"testing"

	"security-permission/internal/model"
)

func TestRoleCreationRequiresRoleManagementMenu(t *testing.T) {
	permission := newRuntimeCapPermission()
	roles := &RoleService{Store: permission.Store, PermissionService: permission}

	_, err := roles.SaveBasic(context.Background(), "2", &model.Role{Name: "越权创建"})
	if err == nil || !strings.Contains(err.Error(), "功能权限不足") {
		t.Fatalf("expected role-management denial, got %v", err)
	}
}

func TestRoleCreationRejectsUnknownActor(t *testing.T) {
	permission := newRuntimeCapPermission()
	roles := &RoleService{Store: permission.Store, PermissionService: permission}

	_, err := roles.SaveBasic(context.Background(), "missing", &model.Role{Name: "无身份创建"})
	if err == nil || !strings.Contains(err.Error(), "操作人不存在") {
		t.Fatalf("expected unknown-actor denial, got %v", err)
	}
}

func TestRoleProviderFiltersListOnServer(t *testing.T) {
	permission := newRuntimeCapPermission()
	provider := &roleProvider{service: &RoleService{Store: permission.Store, PermissionService: permission}}

	visible := provider.List("1")
	if len(visible) != 1 || visible[0].Id != 20 {
		t.Fatalf("expected actor 1 to see only self-created role 20, got %+v", visible)
	}
	if got := provider.List("2"); len(got) != 0 {
		t.Fatalf("expected actor without role-management menu to see no roles, got %+v", got)
	}
}
