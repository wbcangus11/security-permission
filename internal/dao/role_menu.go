// =================================================================================
// 此文件由 GoFrame CLI 工具自动生成，可按需修改。
// =================================================================================

package dao

import (
	"security-permission/internal/dao/internal"
)

// roleMenuDao 是 role_menu 表的数据访问对象。
// 可按需为其定义自定义方法以扩展功能。
type roleMenuDao struct {
	*internal.RoleMenuDao
}

var (
	// RoleMenu 是操作 role_menu 表的全局数据访问对象。
	RoleMenu = roleMenuDao{internal.NewRoleMenuDao()}
)

// 可在下方添加自定义方法和功能。
