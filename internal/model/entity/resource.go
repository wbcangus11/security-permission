// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Resource 是 resource 表对应的数据结构。
type Resource struct {
	Id     int64  `json:"id"     orm:"id"      ` // 资源ID
	AreaId int64  `json:"areaId" orm:"area_id" ` // 所属区域ID
	Type   string `json:"type"   orm:"type"    ` // 资源类型,如 camera
	Name   string `json:"name"   orm:"name"    ` // 资源名称
}
