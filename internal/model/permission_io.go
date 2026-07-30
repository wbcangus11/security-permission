package model

type MetaData struct {
	Areas []*Area `json:"areas"`
	Orgs  []*Org  `json:"orgs"`
	Menus []*Menu `json:"menus"`
	Users []*User `json:"users"`
}

// RoleSummary 是角色列表使用的轻量视图，不包含任何权限配置。
type RoleSummary struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
}

// Grantable 描述当前用户可二次授权的权限上限。
type Grantable struct {
	Unlimited       bool        `json:"unlimited"`
	MenuConfigCodes []string    `json:"menuConfigCodes"`
	MenuAppCodes    []string    `json:"menuAppCodes"`
	AreaIds         []int       `json:"areaIds"`
	OrgIds          []int       `json:"orgIds"`
	ResAreaIds      []int       `json:"resAreaIds"`
	AreaScopes      []DataScope `json:"areaScopes"`
	OrgScopes       []DataScope `json:"orgScopes"`
	ResAreaScopes   []DataScope `json:"resAreaScopes"`
}

// DataScopeChanges 表示用户明确执行的树权限变化。
// 同一个节点改变 includeChild 时，必须同时删除旧值并增加新值。
type DataScopeChanges struct {
	Adds []DataScope `json:"adds"`
	Dels []DataScope `json:"dels"`
}

// MenuReplacement 是当前编辑人可管理部分的菜单完整快照。
// 对象存在表示需要替换，replace 空数组表示清空可管理部分；范围外旧权限由后端保留。
type MenuReplacement struct {
	Replace []string `json:"replace"`
}

// RolePermissionChanges 是一次保存中明确提交的权限变化。
// MenuConfig、MenuApp 分别对应系统管理端和应用端菜单，省略其中任意一项都表示该域不变；
// 三类树中没有出现在 adds/dels 的记录保持不变。
type RolePermissionChanges struct {
	MenuConfig   *MenuReplacement `json:"menuConfig,omitempty"`
	MenuApp      *MenuReplacement `json:"menuApp,omitempty"`
	Area         DataScopeChanges `json:"area"`
	Org          DataScopeChanges `json:"org"`
	ResourceArea DataScopeChanges `json:"resourceArea"`
}

// RoleSaveInput 是角色保存逻辑使用的输入。
type RoleSaveInput struct {
	RoleId      int
	Name        string
	Description string
	Permissions *RolePermissionChanges
}

type AreaSaveInput struct {
	Id       int
	ParentId int
	Name     string
}

type AreaReorderInput struct {
	AreaId   int
	ToAreaId int
}

type OrgSaveInput struct {
	Id       int
	ParentId int
	Name     string
}

type ResourceSaveInput struct {
	Id     int
	AreaId int
	Name   string
	Type   string
}

type VisibleArea struct {
	Id         int    `json:"id"`
	ParentId   int    `json:"parentId"`
	Name       string `json:"name"`
	Accessible bool   `json:"accessible"`
}

type ResourceBrief struct {
	Id     int    `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	AreaId int    `json:"areaId"`
}

type ManageDetail struct {
	Accessible    bool            `json:"accessible"`
	Name          string          `json:"name"`
	ParentId      int             `json:"parentId"`
	ChildCount    int             `json:"childCount"`
	Children      []string        `json:"children"`
	ResourceItems []ResourceBrief `json:"resourceItems"`
}

type ActionAllow struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type ResourceView struct {
	Id      int           `json:"id"`
	Name    string        `json:"name"`
	Area    string        `json:"area"`
	Actions []ActionAllow `json:"actions"`
}

type AncestorRef struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type AreaNode struct {
	Id          int           `json:"id"`
	ParentId    int           `json:"parentId"`
	Name        string        `json:"name"`
	Accessible  bool          `json:"accessible"`
	HasChildren bool          `json:"hasChildren"`
	Ancestors   []AncestorRef `json:"ancestors,omitempty"`
}

type PagedAreas struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

type RoleTreeNode struct {
	Id          int    `json:"id"`
	ParentId    int    `json:"parentId"`
	Name        string `json:"name"`
	HasChildren bool   `json:"hasChildren"`
	CanCheck    bool   `json:"canCheck"`
}

type AreaResourcesPage struct {
	Accessible bool           `json:"accessible"`
	AreaName   string         `json:"areaName"`
	Resources  []ResourceView `json:"resources"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Size       int            `json:"size"`
}
