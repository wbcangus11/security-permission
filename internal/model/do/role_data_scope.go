// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// RoleDataScope is the golang structure of table role_data_scope for DAO operations like Where/Data.
type RoleDataScope struct {
	g.Meta       `orm:"table:role_data_scope, do:true"`
	RoleId       any // 角色ID
	ScopeType    any // AREA / ORG / RES_AREA
	NodeId       any // 授权的树节点ID(area.id 或 org.id)
	IncludeChild any // 是否含子树
}
