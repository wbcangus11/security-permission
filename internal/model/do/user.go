// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// User 是 user 表用于 DAO 的 Where/Data 等操作的数据结构。
type User struct {
	g.Meta      `orm:"table:user, do:true"`
	Id          any // 用户ID
	Name        any // 用户名
	OrgId       any // 所属组织ID
	IsSuperuser any // 超级管理员:1=鉴权三关直接放行(仿海康内置root)
}
