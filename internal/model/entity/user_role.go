// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// UserRole is the golang structure for table user_role.
type UserRole struct {
	Id     int64  `json:"id"     orm:"id"      ` // 用户角色关系ID
	UserId string `json:"userId" orm:"user_id" ` // 用户ID
	RoleId int64  `json:"roleId" orm:"role_id" ` // 角色ID
}
