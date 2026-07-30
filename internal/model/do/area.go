// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Area 是 area 表用于 DAO 的 Where/Data 等操作的数据结构。
type Area struct {
	g.Meta   `orm:"table:area, do:true"`
	Id       any // 区域ID
	ParentId any // 父区域ID,0为根
	Name     any // 区域名称
	Path     any // 物化路径,含自身,形如 /1/3/4/
	Sort     any // 同级排序
}
