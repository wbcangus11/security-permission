// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

// Role is the golang structure of table role for DAO operations like Where/Data.
type Role struct {
	g.Meta      `orm:"table:role, do:true"`
	Id          any         // 角色ID
	Name        any         // 角色名称
	Description any         // 描述
	CreatedBy   any         // 创建人(委派来源用户),0为系统创建/不受限
	CreatedAt   *gtime.Time // 创建时间
	UpdatedAt   *gtime.Time // 更新时间
}
