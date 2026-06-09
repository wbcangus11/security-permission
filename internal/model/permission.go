// Package model 定义基于角色的「功能权限 + 数据权限」模型。
//
// 设计要点(仿海康安防平台):
//  1. 功能权限:角色 -> 菜单(分系统管理域 SYS / 应用域 APP 两类)。
//  2. 数据权限(管理域):角色 -> 安保区域树 / 组织树,按节点授权,支持级联子树。
//  3. 数据权限(应用域):角色 -> 业务资源范围(区域树)+ 资源级操作项精细覆盖。
//
// 树范围统一存「节点 + 是否含子节点」,运行时用 path 前缀判断目标是否落在授权子树内,
// 这样新增子节点可自动继承父节点权限,无需重新授权。
package model

const (
	MenuDomainSys = "SYS" // 系统管理菜单
	MenuDomainApp = "APP" // 应用菜单
)

// Area 安保区域(树形)。Path 形如 "/1/4/17/",含自身,用于子树前缀判断。
type Area struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// Org 组织(树形),结构与 Area 相同。
type Org struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// Menu 菜单/功能项(树形),Domain 区分系统管理域与应用域。
type Menu struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Code     string `json:"code"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
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

// ResourceAction 资源级操作的精细授权(高级配置,仅对已存在资源生效)。
type ResourceAction struct {
	ResourceId int    `json:"resourceId"`
	ActionCode string `json:"actionCode"`
}

// Role 角色:聚合四类权限。
type Role struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   int    `json:"createdBy"` // 创建该角色的用户(委派来源),0 表示系统创建/不受限

	// 功能权限:菜单 id 列表(含系统域与应用域)
	MenuIds []int `json:"menuIds"`

	// 数据权限·管理域
	AreaScopes []DataScope `json:"areaScopes"` // 安保区域管理权限
	OrgScopes  []DataScope `json:"orgScopes"`  // 组织管理权限

	// 数据权限·应用域
	ResourceAreaScopes []DataScope      `json:"resourceAreaScopes"` // 业务资源范围(粗粒度,继承新资源)
	ResourceActions    []ResourceAction `json:"resourceActions"`    // 资源级操作精细覆盖

	// 委派维度·显式角色范围(模型 B):该角色「可管理哪些其他角色」。
	// 复用 DataScope(node_id=被管理角色 id),角色无树故 IncludeChild 恒 false。
	RoleScopes []DataScope `json:"roleScopes"`
}

// User 账号,可绑定多个角色,归属某组织。
type User struct {
	Id      int    `json:"id"`
	Name    string `json:"name"`
	OrgId   int    `json:"orgId"`
	RoleIds []int  `json:"roleIds"`
	// IsSuperuser 超级管理员(仿海康内置 root):鉴权三关直接放行,拥有现有及将来全部权限。
	// 与数据权限模型解耦——它是引擎层面的特例,不依赖任何角色/数据范围授权。
	IsSuperuser bool `json:"isSuperuser"`
}
