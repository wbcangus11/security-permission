// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Area is the golang structure of table area for DAO operations like Where/Data.
type Area struct {
	g.Meta   `orm:"table:area, do:true"`
	Id       any // 区域ID
	ParentId any // 父区域ID,0为根
	Name     any // 区域名称
	Path     any // 物化路径,含自身,形如 /1/3/4/
	Sort     any // 同级排序
}
