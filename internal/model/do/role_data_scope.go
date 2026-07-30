// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// RoleDataScope 是 role_data_scope 表用于 DAO 的 Where/Data 等操作的数据结构。
type RoleDataScope struct {
	g.Meta       `orm:"table:role_data_scope, do:true"`
	Id           any // 角色数据范围ID
	RoleId       any // 角色ID
	ScopeType    any // AREA / ORG / RES_AREA
	NodeId       any // 授权的树节点ID(area.id 或 org.id)
	IncludeChild any // 是否含子树
}
