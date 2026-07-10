package v1

import "github.com/gogf/gf/v2/frame/g"

// CommonRes 是所有接口统一响应外壳。
// 控制器不会直接抛 HTTP 业务错误,而是把成功/失败放到 code/message/data 中。
type CommonRes struct {
	Code      int         `json:"code" dc:"业务状态码,0 表示成功,非 0 表示失败"`
	Message   string      `json:"message" dc:"响应消息,成功时通常为 ok,失败时为错误原因"`
	Data      interface{} `json:"data,omitempty" dc:"响应数据,具体结构由接口决定"`
	Preserved int         `json:"preserved,omitempty" dc:"委派保存时保留的范围外原有权限数量"`
}

// DataScope 表示一条树形数据范围授权。
// NodeId 是勾选的节点,IncludeChild 决定是否把它下面整棵子树也纳入范围。
type DataScope struct {
	NodeId       int  `json:"nodeId" dc:"授权节点 ID"`
	IncludeChild bool `json:"includeChild" dc:"是否包含该节点整棵子树,包含后未来新增子节点自动继承权限"`
}

const (
	AuthTypeMenu     = "menu"
	AuthTypeArea     = "area"
	AuthTypeOrg      = "org"
	AuthTypeResource = "resource"
)

// MetaReq 查询前端初始化需要的基础字典,包括区域、组织、菜单、资源、操作项和用户。
type MetaReq struct {
	g.Meta `path:"/meta" method:"get" tags:"权限/元数据" summary:"获取权限配置元数据"`
}

// AuthCheckReq 执行一次鉴权测试。
// 前端鉴权测试面板用它查看 allow/reason/trace,便于理解权限为什么通过或拒绝。
type AuthCheckReq struct {
	g.Meta     `path:"/auth/check" method:"post" tags:"权限/鉴权" summary:"执行一次权限判定"`
	UserId     string `json:"userId" dc:"被鉴权用户 ID"`
	Type       string `json:"type" dc:"鉴权类型:menu=功能菜单,area=安保区域,org=组织,resource=业务资源操作"`
	Code       string `json:"code" dc:"菜单权限编码,type=menu 时必填"`
	NodeId     int    `json:"nodeId" dc:"树节点 ID,type=area 或 org 时必填"`
	ResourceId int    `json:"resourceId" dc:"业务资源 ID,type=resource 时必填"`
	Action     string `json:"action" dc:"资源操作编码,type=resource 时必填"`
}

// RoleListReq 查询全部角色列表。
// 前端再结合当前用户可见角色范围过滤展示。
type RoleListReq struct {
	g.Meta `path:"/role/list" method:"get" tags:"权限/角色" summary:"查询角色列表"`
	UserId string `json:"userId" dc:"当前登录用户 ID;仅演示模式兼容,服务端以身份上下文为准"`
}

// RoleDetailReq 查询单个角色的完整配置。
type RoleDetailReq struct {
	g.Meta `path:"/role/detail" method:"get" tags:"权限/角色" summary:"查询角色详情"`
	UserId string `json:"userId" dc:"当前登录用户 ID;仅演示模式兼容,服务端以身份上下文为准"`
	Id     int    `json:"id" dc:"角色 ID"`
}

// RoleSaveReq 保存角色配置。
// 当前只保存基本信息、菜单权限和三类树范围;业务资源操作默认继承资源区域范围。
type RoleSaveReq struct {
	g.Meta             `path:"/role/save" method:"post" tags:"权限/角色" summary:"保存角色"`
	UserId             string      `json:"userId" dc:"当前登录用户 ID;演示环境由前端传入,实际项目应从 token 解析"`
	Id                 int         `json:"id" dc:"角色 ID,0 或空表示新建角色"`
	Name               string      `json:"name" dc:"角色名称"`
	Description        string      `json:"description" dc:"角色描述"`
	MenuCodes          []string    `json:"menuCodes" dc:"功能权限菜单 code 列表,包含系统管理域和应用域菜单"`
	AreaScopes         []DataScope `json:"areaScopes" dc:"安保区域管理范围,用于后台区域管理数据权限"`
	OrgScopes          []DataScope `json:"orgScopes" dc:"组织管理范围,用于后台组织管理数据权限"`
	ResourceAreaScopes []DataScope `json:"resourceAreaScopes" dc:"业务资源区域范围,用于应用端资源可见和操作继承"`
}

// RoleDeleteReq 删除角色。
// 删除会清理 role_menu、role_data_scope 和 user_role 绑定。
type RoleDeleteReq struct {
	g.Meta `path:"/role/delete" method:"post" tags:"权限/角色" summary:"删除角色"`
	UserId string `json:"userId" dc:"当前登录用户 ID;演示环境由前端传入,实际项目应从 token 解析"`
	Id     int    `json:"id" dc:"要删除的角色 ID"`
}

// RoleGrantableReq 查询当前用户还能授出去的权限上限。
// 前端用这个结果隐藏或置灰超出当前用户权限的菜单、区域和业务资源范围。
type RoleGrantableReq struct {
	g.Meta `path:"/role/grantable" method:"get" tags:"权限/角色" summary:"查询当前用户可授权限范围"`
	UserId string `json:"userId" dc:"当前登录用户 ID;演示环境由前端传入,实际项目应从 token 解析"`
}

// RoleAreaChildrenReq 查询角色配置页里的区域树某一层。
// 它按当前用户可授权范围过滤,用于“勾选授权树”,不是应用端可见树。
type RoleAreaChildrenReq struct {
	g.Meta   `path:"/role/area-children" method:"get" tags:"权限/角色" summary:"查询角色配置用区域树子节点"`
	UserId   string `json:"userId" dc:"当前登录用户 ID;用于过滤可授节点,实际项目应从 token 解析"`
	ParentId int    `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Kind     string `json:"kind" dc:"区域树类型:area=安保区域管理范围,resarea=业务资源区域范围"`
}

// UserListReq 查询全部用户列表。
type UserListReq struct {
	g.Meta `path:"/user/list" method:"get" tags:"权限/用户" summary:"查询用户列表"`
	UserId string `json:"userId" dc:"当前登录用户 ID;仅演示模式兼容,服务端以身份上下文为准"`
}

// UserDetailReq 查询单个用户详情。
type UserDetailReq struct {
	g.Meta `path:"/user/detail" method:"get" tags:"权限/用户" summary:"查询用户详情"`
	UserId string `json:"userId" dc:"当前登录用户 ID;仅演示模式兼容,服务端以身份上下文为准"`
	Id     string `json:"id" dc:"用户 ID"`
}

// UserSaveReq 保存用户和角色绑定。
// 角色绑定会按当前用户可分配角色范围做合并,防止越权分配或误删不可见绑定。
type UserSaveReq struct {
	g.Meta      `path:"/user/save" method:"post" tags:"权限/用户" summary:"保存用户"`
	UserId      string `json:"userId" dc:"操作人用户 ID,用于账号管理功能权限校验"`
	Id          string `json:"id" dc:"用户 ID,空表示新建用户"`
	Name        string `json:"name" dc:"用户名称"`
	OrgId       int    `json:"orgId" dc:"用户所属组织 ID"`
	IsSuperuser bool   `json:"isSuperuser" dc:"是否超级管理员;超级管理员绕过全部鉴权"`
	RoleIds     []int  `json:"roleIds" dc:"绑定的角色 ID 列表"`
}

// UserDeleteReq 删除用户并清理用户-角色绑定。
type UserDeleteReq struct {
	g.Meta `path:"/user/delete" method:"post" tags:"权限/用户" summary:"删除用户"`
	UserId string `json:"userId" dc:"操作人用户 ID,用于账号管理功能权限校验"`
	Id     string `json:"id" dc:"要删除的用户 ID"`
}

// AppMenuReq 查询应用端可见菜单。
// 对应前台应用页顶部的功能入口。
type AppMenuReq struct {
	g.Meta `path:"/app/menu" method:"get" tags:"权限/应用端" summary:"查询应用端可见菜单"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
}

// AppAreaTreeReq 查询应用端完整可见区域树。
// 该接口保留用于小数据量演示;大数据量场景优先用 AppAreaChildrenReq。
type AppAreaTreeReq struct {
	g.Meta `path:"/app/area-tree" method:"get" tags:"权限/应用端" summary:"查询应用端完整可见区域树"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
}

// AppAreaChildrenReq 分页查询应用端区域树某一层。
// 它使用 RES_AREA 资源范围过滤,返回“可访问节点 + 导航祖先”。
type AppAreaChildrenReq struct {
	g.Meta   `path:"/app/area-children" method:"get" tags:"权限/应用端" summary:"分页查询应用端区域树子节点"`
	UserId   string `json:"userId" dc:"当前登录用户 ID"`
	ParentId int    `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Page     int    `json:"page" dc:"页码,从 1 开始"`
	Size     int    `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

// AppAreaSearchReq 搜索应用端区域树。
// 搜索结果会带祖先链,前端按局部树展示并高亮命中节点。
type AppAreaSearchReq struct {
	g.Meta `path:"/app/area-search" method:"get" tags:"权限/应用端" summary:"搜索应用端区域树"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
	Q      string `json:"q" dc:"搜索关键字"`
	Scope  string `json:"scope" dc:"搜索范围:app=应用端资源区域,manage=后台管理区域;为空默认 app"`
	Page   int    `json:"page" dc:"页码,从 1 开始"`
	Size   int    `json:"size" dc:"每页数量,搜索最多返回前 500 条匹配"`
}

// AppResourceListReq 查询某区域子树下应用端可见资源。
// 返回每个资源对实时预览、远程回放、图片查询等操作是否可用。
type AppResourceListReq struct {
	g.Meta `path:"/app/resource-list" method:"get" tags:"权限/应用端" summary:"分页查询应用端资源列表"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
	AreaId int    `json:"areaId" dc:"区域 ID,返回该区域子树下用户可见资源"`
	Page   int    `json:"page" dc:"页码,从 1 开始"`
	Size   int    `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

// ManageMenuReq 查询后台系统管理可见菜单。
type ManageMenuReq struct {
	g.Meta `path:"/manage/menu" method:"get" tags:"权限/后台管理" summary:"查询后台可见菜单"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
}

// ManageAreaTreeReq 查询后台完整可见区域树。
// 该接口保留用于小数据量演示;大数据量场景优先用 ManageAreaChildrenReq。
type ManageAreaTreeReq struct {
	g.Meta `path:"/manage/area-tree" method:"get" tags:"权限/后台管理" summary:"查询后台完整可见区域树"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
}

// ManageAreaChildrenReq 分页查询后台区域树某一层。
// 它使用 AREA 管理范围过滤,返回可管理节点和必要的导航祖先。
type ManageAreaChildrenReq struct {
	g.Meta   `path:"/manage/area-children" method:"get" tags:"权限/后台管理" summary:"分页查询后台区域树子节点"`
	UserId   string `json:"userId" dc:"当前登录用户 ID"`
	ParentId int    `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Page     int    `json:"page" dc:"页码,从 1 开始"`
	Size     int    `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

// ManageAreaDetailReq 查询后台区域详情。
// 可管理时返回子区域数量和本区域直接资源;不可管理时返回空详情。
type ManageAreaDetailReq struct {
	g.Meta `path:"/manage/area-detail" method:"get" tags:"权限/后台管理" summary:"查询后台区域详情"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
	AreaId int    `json:"areaId" dc:"区域 ID"`
}

// ManageAreaSaveReq 新增、重命名或移动区域。
// 写操作同时检查功能菜单权限和区域数据权限。
type ManageAreaSaveReq struct {
	g.Meta   `path:"/manage/area-save" method:"post" tags:"权限/后台管理" summary:"新增或修改区域"`
	UserId   string `json:"userId" dc:"操作人用户 ID,用于安保区域管理写权限校验"`
	Id       int    `json:"id" dc:"区域 ID,0 或空表示新增区域"`
	ParentId int    `json:"parentId" dc:"父区域 ID;新增时必填,更新时非 0 且变化表示移动区域"`
	Name     string `json:"name" dc:"区域名称"`
}

// ManageAreaReorderReq 调整同父区域的排序。
type ManageAreaReorderReq struct {
	g.Meta   `path:"/manage/area-reorder" method:"post" tags:"权限/后台管理" summary:"交换同级区域排序"`
	UserId   string `json:"userId" dc:"操作人用户 ID,用于安保区域管理写权限校验"`
	AreaId   int    `json:"areaId" dc:"当前区域 ID"`
	ToAreaId int    `json:"toAreaId" dc:"目标同级区域 ID,后端会和当前区域交换排序"`
}

// ManageAreaDeleteReq 删除区域。
// 只能删除无子区域且无资源的叶子区域。
type ManageAreaDeleteReq struct {
	g.Meta `path:"/manage/area-delete" method:"post" tags:"权限/后台管理" summary:"删除区域"`
	UserId string `json:"userId" dc:"操作人用户 ID,用于安保区域管理写权限校验"`
	Id     int    `json:"id" dc:"要删除的区域 ID"`
}

// ManageOrgTreeReq 查询后台可见组织树。
type ManageOrgTreeReq struct {
	g.Meta `path:"/manage/org-tree" method:"get" tags:"权限/后台管理" summary:"查询后台可见组织树"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
}

// ManageOrgDetailReq 查询组织详情。
type ManageOrgDetailReq struct {
	g.Meta `path:"/manage/org-detail" method:"get" tags:"权限/后台管理" summary:"查询组织详情"`
	UserId string `json:"userId" dc:"当前登录用户 ID"`
	OrgId  int    `json:"orgId" dc:"组织 ID"`
}

// ManageOrgSaveReq 新增、重命名或移动组织。
// 写操作同时检查“人员信息”菜单权限和组织数据权限。
type ManageOrgSaveReq struct {
	g.Meta   `path:"/manage/org-save" method:"post" tags:"权限/后台管理" summary:"新增或修改组织"`
	UserId   string `json:"userId" dc:"操作人用户 ID,用于人员信息写权限校验"`
	Id       int    `json:"id" dc:"组织 ID,0 或空表示新增组织"`
	ParentId int    `json:"parentId" dc:"父组织 ID;新增时必填,更新时非 0 且变化表示移动组织"`
	Name     string `json:"name" dc:"组织名称"`
}

// ManageOrgDeleteReq 删除组织。
// 只能删除无子组织且无下属用户的叶子组织。
type ManageOrgDeleteReq struct {
	g.Meta `path:"/manage/org-delete" method:"post" tags:"权限/后台管理" summary:"删除组织"`
	UserId string `json:"userId" dc:"操作人用户 ID,用于人员信息写权限校验"`
	Id     int    `json:"id" dc:"要删除的组织 ID"`
}

// ManageResourceSaveReq 新增、重命名、改类型或移动业务资源。
// 资源管理写操作检查“资源管理”菜单权限和资源所在区域管理权限。
type ManageResourceSaveReq struct {
	g.Meta `path:"/manage/resource-save" method:"post" tags:"权限/后台管理" summary:"新增或修改资源"`
	UserId string `json:"userId" dc:"操作人用户 ID,用于资源管理写权限校验"`
	Id     int    `json:"id" dc:"资源 ID,0 或空表示新增资源"`
	AreaId int    `json:"areaId" dc:"资源所在区域 ID;更新时变化表示移动资源"`
	Name   string `json:"name" dc:"资源名称"`
	Type   string `json:"type" dc:"资源类型,如 gun=枪机,dome=球机"`
}

// ManageResourceDeleteReq 删除业务资源。
// 当前资源权限只来自资源区域范围,删除资源不需要清理额外授权表。
type ManageResourceDeleteReq struct {
	g.Meta `path:"/manage/resource-delete" method:"post" tags:"权限/后台管理" summary:"删除资源"`
	UserId string `json:"userId" dc:"操作人用户 ID,用于资源管理写权限校验"`
	Id     int    `json:"id" dc:"要删除的资源 ID"`
}
