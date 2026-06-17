// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// RoleDataScope is the golang structure for table role_data_scope.
type RoleDataScope struct {
	RoleId       int64  `json:"roleId"       orm:"role_id"       ` // 角色ID
	ScopeType    string `json:"scopeType"    orm:"scope_type"    ` // AREA / ORG / RES_AREA
	NodeId       int64  `json:"nodeId"       orm:"node_id"       ` // 授权的树节点ID(area.id 或 org.id)
	IncludeChild int    `json:"includeChild" orm:"include_child" ` // 是否含子树
}
