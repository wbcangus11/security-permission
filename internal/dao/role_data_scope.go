// =================================================================================
// 此文件由 GoFrame CLI 工具自动生成，可按需修改。
// =================================================================================

package dao

import (
	"security-permission/internal/dao/internal"
)

// roleDataScopeDao 是 role_data_scope 表的数据访问对象。
// 可按需为其定义自定义方法以扩展功能。
type roleDataScopeDao struct {
	*internal.RoleDataScopeDao
}

var (
	// RoleDataScope 是操作 role_data_scope 表的全局数据访问对象。
	RoleDataScope = roleDataScopeDao{internal.NewRoleDataScopeDao()}
)

// 可在下方添加自定义方法和功能。
