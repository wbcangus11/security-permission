// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import "github.com/gogf/gf/v2/frame/g"

// Menu 是 menu 表用于 DAO 的 Where/Data 等操作的数据结构。
type Menu struct {
	g.Meta     `orm:"table:menu, do:true"`
	Id         any // 菜单ID
	Code       any // 菜单唯一权限码
	ParentCode any // 父菜单权限码，空字符串表示一级菜单
	Name       any // 显示名称
	Domain     any // 权限域：SYS或APP
}
