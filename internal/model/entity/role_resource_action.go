// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// RoleResourceAction is the golang structure for table role_resource_action.
type RoleResourceAction struct {
	RoleId     int64  `json:"roleId"     orm:"role_id"     ` // 角色ID
	ResourceId int64  `json:"resourceId" orm:"resource_id" ` // 资源ID
	ActionCode string `json:"actionCode" orm:"action_code" ` // 操作编码
}
