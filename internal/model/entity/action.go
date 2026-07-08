// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Action is the golang structure for table action.
type Action struct {
	Id   int64  `json:"id"   orm:"id"   ` // 操作项ID
	Code string `json:"code" orm:"code" ` // 操作编码,如 live/playback/picture
	Name string `json:"name" orm:"name" ` // 操作名称
	Sort int    `json:"sort" orm:"sort" ` // 排序
}
