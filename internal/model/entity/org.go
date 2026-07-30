// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Org 是 org 表对应的数据结构。
type Org struct {
	Id       int64  `json:"id"       orm:"id"        ` // 组织ID
	ParentId int64  `json:"parentId" orm:"parent_id" ` // 父组织ID,0为根
	Name     string `json:"name"     orm:"name"      ` // 组织名称
	Path     string `json:"path"     orm:"path"      ` // 物化路径,含自身
	Sort     int    `json:"sort"     orm:"sort"      ` // 同级排序
}
