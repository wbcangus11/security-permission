// Package model 定义基于角色的「功能权限 + 数据权限」模型。
//
// 设计要点(仿海康安防平台):
//  1. 功能权限:角色 -> 菜单(分系统管理域 SYS / 应用域 APP 两类)。
//  2. 数据权限(管理域):角色 -> 安保区域树 / 组织树,按节点授权,支持级联子树。
//  3. 数据权限(应用域):角色 -> 业务资源范围(区域树),范围内资源默认拥有全部操作项。
//
// 树范围统一存「节点 + 是否含子节点」,运行时用 path 前缀判断目标是否落在授权子树内,
// 这样新增子节点可自动继承父节点权限,无需重新授权。
package model

const (
	MenuDomainSys = "SYS" // 系统管理菜单
	MenuDomainApp = "APP" // 应用菜单
)

const (
	ScopeTypeArea         = "AREA"
	ScopeTypeOrg          = "ORG"
	ScopeTypeResourceArea = "RES_AREA"
)

// Area 安保区域(树形)。Path 形如 "/1/4/17/",含自身,用于子树前缀判断。
type Area struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Sort     int    `json:"sort"`
}

// Org 组织(树形),结构与 Area 相同。
type Org struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// Menu 菜单/功能项(树形),Domain 区分系统管理域与应用域。
// Id 是数据库关系主键;Code 才是前后端和后端鉴权使用的稳定业务标识。
type Menu struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Code     string `json:"code"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Sort     int    `json:"sort"`
}

// Resource 业务资源(如摄像头),挂在某个区域下。
type Resource struct {
	Id     int    `json:"id"`
	AreaId int    `json:"areaId"`
	Type   string `json:"type"`
	Name   string `json:"name"`
}

// Action 资源上的操作项(实时预览/远程回放/图片查询)。
type Action struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// DataScope 树范围授权项:授权某节点,IncludeChild=true 表示含整棵子树(及未来新增节点)。
type DataScope struct {
	NodeId       int  `json:"nodeId"`
	IncludeChild bool `json:"includeChild"`
}

// Role 角色:聚合四类权限。
type Role struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"` // 创建该角色的用户,"0" 表示系统内置角色

	// 功能权限:菜单 id 列表(含系统域与应用域)
	MenuIds []int `json:"-"`
	// 功能权限:菜单 code 列表。接口层优先使用 code,避免前后端依赖数据库自增 ID。
	MenuCodes []string `json:"menuCodes"`

	// 数据权限·管理域
	AreaScopes []DataScope `json:"areaScopes"` // 安保区域管理权限
	OrgScopes  []DataScope `json:"orgScopes"`  // 组织管理权限

	// 数据权限·应用域:业务资源范围。资源落在该区域范围内时,默认拥有全部资源操作项。
	ResourceAreaScopes []DataScope `json:"resourceAreaScopes"`
}

// User 账号,可绑定多个角色,归属某组织。
type User struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	OrgId   int    `json:"orgId"`
	RoleIds []int  `json:"roleIds"`
	// IsSuperuser 超级管理员(仿海康内置 root):鉴权三关直接放行,拥有现有及将来全部权限。
	// 与数据权限模型解耦——它是引擎层面的特例,不依赖任何角色/数据范围授权。
	IsSuperuser bool `json:"isSuperuser"`
}
