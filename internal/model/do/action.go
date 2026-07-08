// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Action is the golang structure of table action for DAO operations like Where/Data.
type Action struct {
	g.Meta `orm:"table:action, do:true"`
	Id     any // 操作项ID
	Code   any // 操作编码,如 live/playback/picture
	Name   any // 操作名称
	Sort   any // 排序
}
