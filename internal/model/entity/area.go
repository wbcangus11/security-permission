// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Area is the golang structure for table area.
type Area struct {
	Id       int64  `json:"id"       orm:"id"        ` // 区域ID
	ParentId int64  `json:"parentId" orm:"parent_id" ` // 父区域ID,0为根
	Name     string `json:"name"     orm:"name"      ` // 区域名称
	Path     string `json:"path"     orm:"path"      ` // 物化路径,含自身,形如 /1/3/4/
	Sort     int    `json:"sort"     orm:"sort"      ` // 同级排序
}
