// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Org is the golang structure of table org for DAO operations like Where/Data.
type Org struct {
	g.Meta   `orm:"table:org, do:true"`
	Id       any // 组织ID
	ParentId any // 父组织ID,0为根
	Name     any // 组织名称
	Path     any // 物化路径,含自身
	Sort     any // 同级排序
}
