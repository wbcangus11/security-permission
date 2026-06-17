// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Resource is the golang structure of table resource for DAO operations like Where/Data.
type Resource struct {
	g.Meta `orm:"table:resource, do:true"`
	Id     any // 资源ID
	AreaId any // 所属区域ID
	Type   any // 资源类型,如 camera
	Name   any // 资源名称
}
