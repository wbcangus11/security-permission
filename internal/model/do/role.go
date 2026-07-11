// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import "github.com/gogf/gf/v2/frame/g"

// Role is the golang structure of table role for DAO operations like Where/Data.
type Role struct {
	g.Meta      `orm:"table:role, do:true"`
	Id          any // 角色ID
	Name        any // 角色名称
	Description any // 描述
	CreatedBy   any // 创建人用户ID,0表示系统内置角色
}
