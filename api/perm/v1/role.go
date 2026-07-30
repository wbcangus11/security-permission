package v1

import "github.com/gogf/gf/v2/frame/g"

// RoleListReq 查询当前登录用户可见的角色列表。
// 当前登录用户由身份中间件从请求头解析,不属于业务请求参数。
// 返回值只包含角色基本信息，不包含菜单和数据权限。
type RoleListReq struct {
	g.Meta `path:"/role/list" method:"get" tags:"权限/角色" summary:"查询角色列表"`
}

type RoleListItem struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedBy   string `json:"createdBy"`
}

type RoleListRes struct {
	Items []RoleListItem `json:"items"`
}

// RoleDetailReq 查询单个角色对当前登录用户可编辑的配置。
// 超出当前用户可授权范围的历史权限不会返回，保存时仍由后端保留。
type RoleDetailReq struct {
	g.Meta `path:"/role/detail" method:"get" tags:"权限/角色" summary:"查询角色详情"`
	Id     int `json:"id" dc:"角色 ID"`
}

type DataScope struct {
	NodeId       int  `json:"nodeId"`
	IncludeChild bool `json:"includeChild"`
}

type RoleDetailRes struct {
	Id                 int         `json:"id"`
	Name               string      `json:"name"`
	Description        string      `json:"description"`
	CreatedBy          string      `json:"createdBy"`
	MenuConfigCodes    []string    `json:"menuConfigCodes"`
	MenuAppCodes       []string    `json:"menuAppCodes"`
	AreaScopes         []DataScope `json:"areaScopes"`
	OrgScopes          []DataScope `json:"orgScopes"`
	ResourceAreaScopes []DataScope `json:"resourceAreaScopes"`
}

type DataScopeChanges struct {
	Adds []DataScope `json:"adds"`
	Dels []DataScope `json:"dels"`
}

type MenuReplacement struct {
	Replace []string `json:"replace"`
}

type RolePermissionChanges struct {
	MenuConfig   *MenuReplacement `json:"menuConfig,omitempty"`
	MenuApp      *MenuReplacement `json:"menuApp,omitempty"`
	Area         DataScopeChanges `json:"area"`
	Org          DataScopeChanges `json:"org"`
	ResourceArea DataScopeChanges `json:"resourceArea"`
}

// RoleSaveReq 在一个事务中创建或更新角色。
// permissions 省略时只保存基本信息；其中每个权限域也只有显式传递时才会变化。
type RoleSaveReq struct {
	g.Meta      `path:"/role/save" method:"post" tags:"权限/角色" summary:"保存角色"`
	Id          int                    `json:"id" dc:"角色 ID，0 表示新建"`
	Name        string                 `json:"name" dc:"角色名称"`
	Description string                 `json:"description" dc:"角色描述"`
	Permissions *RolePermissionChanges `json:"permissions" dc:"可选权限变化；省略表示权限保持不变"`
}

type RoleSaveRes RoleDetailRes

// RoleDeleteReq 删除角色。
// 删除会清理 role_menu、role_data_scope 和 user_role 绑定。
type RoleDeleteReq struct {
	g.Meta `path:"/role/delete" method:"post" tags:"权限/角色" summary:"删除角色"`
	Id     int `json:"id" dc:"要删除的角色 ID"`
}

type RoleDeleteRes struct {
	Success bool `json:"success"`
}

// RoleGrantableReq 查询当前用户还能授出去的权限上限。
// 前端用这个结果隐藏或置灰超出当前用户权限的菜单、区域和业务资源范围。
type RoleGrantableReq struct {
	g.Meta `path:"/role/grantable" method:"get" tags:"权限/角色" summary:"查询当前用户可授权限范围"`
}

type RoleGrantableRes struct {
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

// RoleAreaChildrenReq 查询角色配置页里的区域树某一层。
// 它只展示当前用户可授权范围，用于“勾选授权树”，不是应用端可见树。
type RoleAreaChildrenReq struct {
	g.Meta   `path:"/role/area-children" method:"get" tags:"权限/角色" summary:"查询角色配置用区域树子节点"`
	ParentId int    `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Kind     string `json:"kind" dc:"区域树类型:area=安保区域管理范围,resarea=业务资源区域范围"`
	RoleId   int    `json:"roleId" dc:"正在编辑的角色 ID,新建角色时为 0"`
}

type RoleTreeNode struct {
	Id          int    `json:"id"`
	ParentId    int    `json:"parentId"`
	Name        string `json:"name"`
	HasChildren bool   `json:"hasChildren"`
	CanCheck    bool   `json:"canCheck"`
}

type RoleAreaChildrenRes struct {
	Items []RoleTreeNode `json:"items"`
}
