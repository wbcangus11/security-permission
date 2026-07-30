// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Org 是 org 表用于 DAO 的 Where/Data 等操作的数据结构。
type Org struct {
	g.Meta   `orm:"table:org, do:true"`
	Id       any // 组织ID
	ParentId any // 父组织ID,0为根
	Name     any // 组织名称
	Path     any // 物化路径,含自身
	Sort     any // 同级排序
}
