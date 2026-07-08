// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// RoleResourceAction is the golang structure of table role_resource_action for DAO operations like Where/Data.
type RoleResourceAction struct {
	g.Meta     `orm:"table:role_resource_action, do:true"`
	Id         any // 角色资源操作ID
	RoleId     any // 角色ID
	ResourceId any // 资源ID
	ActionCode any // 操作编码
}
