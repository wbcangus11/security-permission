// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// UserRole 是 user_role 表用于 DAO 的 Where/Data 等操作的数据结构。
type UserRole struct {
	g.Meta `orm:"table:user_role, do:true"`
	Id     any // 用户角色关系ID
	UserId any // 用户ID
	RoleId any // 角色ID
}
