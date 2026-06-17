// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// User is the golang structure for table user.
type User struct {
	Id          int64  `json:"id"          orm:"id"           ` // 用户ID
	Name        string `json:"name"        orm:"name"         ` // 用户名
	OrgId       int64  `json:"orgId"       orm:"org_id"       ` // 所属组织ID
	IsSuperuser int    `json:"isSuperuser" orm:"is_superuser" ` // 超级管理员:1=鉴权三关直接放行(仿海康内置root)
}
