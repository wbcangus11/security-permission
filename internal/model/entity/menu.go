// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

// Menu is the golang structure for table menu.
type Menu struct {
	Id       int64  `json:"id"       orm:"id"        ` // 菜单ID
	ParentId int64  `json:"parentId" orm:"parent_id" ` // 父菜单ID,0为根
	Code     string `json:"code"     orm:"code"      ` // 菜单编码,唯一,鉴权用
	Name     string `json:"name"     orm:"name"      ` // 菜单名称
	Domain   string `json:"domain"   orm:"domain"    ` // 权限域:SYS=系统管理 / APP=应用
	Sort     int    `json:"sort"     orm:"sort"      ` // 同级排序
}
