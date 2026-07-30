// =================================================================================
// 此文件由 GoFrame CLI 工具自动生成，可按需修改。
// =================================================================================

package dao

import (
	"security-permission/internal/dao/internal"
)

// userDao 是 user 表的数据访问对象。
// 可按需为其定义自定义方法以扩展功能。
type userDao struct {
	*internal.UserDao
}

var (
	// User 是操作 user 表的全局数据访问对象。
	User = userDao{internal.NewUserDao()}
)

// 可在下方添加自定义方法和功能。
