// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import "github.com/gogf/gf/v2/frame/g"

// Role 是 role 表用于 DAO 的 Where/Data 等操作的数据结构。
type Role struct {
	g.Meta      `orm:"table:role, do:true"`
	Id          any // 角色ID
	Name        any // 角色名称
	Description any // 描述
	CreatedBy   any // 创建人用户ID,0表示系统内置角色
}
