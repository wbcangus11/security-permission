// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// RoleMenu 是 role_menu 表对应的数据结构。
type RoleMenu struct {
	Id       int64  `json:"id"       orm:"id"       ` // 角色菜单关系ID
	RoleId   int64  `json:"roleId"   orm:"role_id"  ` // 角色ID
	MenuCode string `json:"menuCode" orm:"menu_code"` // 菜单权限码
}
