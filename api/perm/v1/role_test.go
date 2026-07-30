package v1

import (
	"encoding/json"
	"testing"
)

func TestRoleSaveRequestDistinguishesOmittedAndEmptyPermissions(t *testing.T) {
	var infoOnly RoleSaveReq
	if err := json.Unmarshal([]byte(`{"id":1,"name":"角色"}`), &infoOnly); err != nil {
		t.Fatalf("解析仅基本信息请求失败：%v", err)
	}
	if infoOnly.Permissions != nil {
		t.Fatal("省略 permissions 时必须保持 nil")
	}

	var clearConfigMenus RoleSaveReq
	if err := json.Unmarshal([]byte(`{"id":1,"name":"角色","permissions":{"menuConfig":{"replace":[]}}}`), &clearConfigMenus); err != nil {
		t.Fatalf("解析清空系统配置菜单请求失败：%v", err)
	}
	if clearConfigMenus.Permissions == nil || clearConfigMenus.Permissions.MenuConfig == nil ||
		clearConfigMenus.Permissions.MenuConfig.Replace == nil {
		t.Fatal("menuConfig.replace 空数组必须能与省略 menuConfig 区分")
	}
	if len(clearConfigMenus.Permissions.MenuConfig.Replace) != 0 {
		t.Fatal("清空系统配置菜单请求的 replace 应为空数组")
	}
	if clearConfigMenus.Permissions.MenuApp != nil {
		t.Fatal("只提交 menuConfig 时 menuApp 必须保持省略状态")
	}

	var appOnly RoleSaveReq
	if err := json.Unmarshal([]byte(`{"id":1,"name":"角色","permissions":{"menuApp":{"replace":["app.video"]}}}`), &appOnly); err != nil {
		t.Fatalf("解析应用菜单请求失败：%v", err)
	}
	if appOnly.Permissions == nil || appOnly.Permissions.MenuConfig != nil ||
		appOnly.Permissions.MenuApp == nil || len(appOnly.Permissions.MenuApp.Replace) != 1 {
		t.Fatal("menuConfig 与 menuApp 必须能够独立提交")
	}
}

func TestRoleListResponseWrapsItems(t *testing.T) {
	payload, err := json.Marshal(RoleListRes{Items: []RoleListItem{{Id: 1, Name: "角色"}}})
	if err != nil {
		t.Fatalf("序列化角色列表响应失败：%v", err)
	}
	var response map[string]json.RawMessage
	if err = json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("解析角色列表响应失败：%v", err)
	}
	if _, ok := response["items"]; !ok || len(response) != 1 {
		t.Fatalf("列表响应必须是仅包含 items 的对象：%s", payload)
	}
}
