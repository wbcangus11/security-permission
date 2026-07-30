// =================================================================================
// 此文件由 GoFrame CLI 工具自动生成，可按需修改。
// =================================================================================

package dao

import (
	"security-permission/internal/dao/internal"
)

// roleDao 是 role 表的数据访问对象。
// 可按需为其定义自定义方法以扩展功能。
type roleDao struct {
	*internal.RoleDao
}

var (
	// Role 是操作 role 表的全局数据访问对象。
	Role = roleDao{internal.NewRoleDao()}
)

// 可在下方添加自定义方法和功能。
