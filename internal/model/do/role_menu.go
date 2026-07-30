// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// RoleMenu 是 role_menu 表用于 DAO 的 Where/Data 等操作的数据结构。
type RoleMenu struct {
	g.Meta   `orm:"table:role_menu, do:true"`
	Id       any // 角色菜单关系ID
	RoleId   any // 角色ID
	MenuCode any // 菜单权限码
}
