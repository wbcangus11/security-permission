// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Role is the golang structure for table role.
type Role struct {
	Id          int64  `json:"id"          orm:"id"          ` // 角色ID
	Name        string `json:"name"        orm:"name"        ` // 角色名称
	Description string `json:"description" orm:"description" ` // 描述
	CreatedBy   string `json:"createdBy"   orm:"created_by"  ` // 创建人用户ID,0表示系统内置角色
}
