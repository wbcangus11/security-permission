// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// RoleMenu is the golang structure for table role_menu.
type RoleMenu struct {
	Id     int64 `json:"id"     orm:"id"      ` // 角色菜单关系ID
	RoleId int64 `json:"roleId" orm:"role_id" ` // 角色ID
	MenuId int64 `json:"menuId" orm:"menu_id" ` // 菜单ID
}
