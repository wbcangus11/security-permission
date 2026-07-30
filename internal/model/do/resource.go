// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Resource 是 resource 表用于 DAO 的 Where/Data 等操作的数据结构。
type Resource struct {
	g.Meta `orm:"table:resource, do:true"`
	Id     any // 资源ID
	AreaId any // 所属区域ID
	Type   any // 资源类型,如 camera
	Name   any // 资源名称
}
