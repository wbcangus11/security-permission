// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

import (
	"github.com/gogf/gf/v2/os/gtime"
)

// Role is the golang structure for table role.
type Role struct {
	Id          int64       `json:"id"          orm:"id"          ` // 角色ID
	Name        string      `json:"name"        orm:"name"        ` // 角色名称
	Description string      `json:"description" orm:"description" ` // 描述
	CreatedBy   string      `json:"createdBy"   orm:"created_by"  ` // 创建人(委派来源用户),0为系统创建/不受限
	CreatedAt   *gtime.Time `json:"createdAt"   orm:"created_at"  ` // 创建时间
	UpdatedAt   *gtime.Time `json:"updatedAt"   orm:"updated_at"  ` // 更新时间
}
