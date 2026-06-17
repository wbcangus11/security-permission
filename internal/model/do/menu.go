// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Menu is the golang structure of table menu for DAO operations like Where/Data.
type Menu struct {
	g.Meta   `orm:"table:menu, do:true"`
	Id       any // 菜单ID
	ParentId any // 父菜单ID,0为根
	Code     any // 菜单编码,唯一,鉴权用
	Name     any // 菜单名称
	Domain   any // 权限域:SYS=系统管理 / APP=应用
	Sort     any // 同级排序
}
