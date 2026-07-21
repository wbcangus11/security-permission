package v1

import (
	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/model"
)

// RoleListReq 查询当前登录用户可见的角色列表。
// 当前登录用户由身份中间件从请求头解析,不属于业务请求参数。
type RoleListReq struct {
	g.Meta `path:"/role/list" method:"get" tags:"权限/角色" summary:"查询角色列表"`
}

// RoleDetailReq 查询单个角色的完整配置。
type RoleDetailReq struct {
	g.Meta `path:"/role/detail" method:"get" tags:"权限/角色" summary:"查询角色详情"`
	Id     int `json:"id" dc:"角色 ID"`
}

// RoleSaveReq 保存角色配置。
// 当前只保存基本信息、菜单权限和三类树范围;业务资源操作默认继承资源区域范围。
type RoleSaveReq struct {
	g.Meta             `path:"/role/save" method:"post" tags:"权限/角色" summary:"保存角色"`
	Id                 int               `json:"id" dc:"角色 ID,0 或空表示新建角色"`
	Name               string            `json:"name" dc:"角色名称"`
	Description        string            `json:"description" dc:"角色描述"`
	MenuCodes          []string          `json:"menuCodes" dc:"功能权限菜单 code 列表,包含系统管理域和应用域菜单"`
	AreaScopes         []model.DataScope `json:"areaScopes" dc:"安保区域管理范围,用于后台区域管理数据权限"`
	OrgScopes          []model.DataScope `json:"orgScopes" dc:"组织管理范围,用于后台组织管理数据权限"`
	ResourceAreaScopes []model.DataScope `json:"resourceAreaScopes" dc:"业务资源区域范围,用于应用端资源可见和操作继承"`
}

// RoleDeleteReq 删除角色。
// 删除会清理 role_menu、role_data_scope 和 user_role 绑定。
type RoleDeleteReq struct {
	g.Meta `path:"/role/delete" method:"post" tags:"权限/角色" summary:"删除角色"`
	Id     int `json:"id" dc:"要删除的角色 ID"`
}

// RoleGrantableReq 查询当前用户还能授出去的权限上限。
// 前端用这个结果隐藏或置灰超出当前用户权限的菜单、区域和业务资源范围。
type RoleGrantableReq struct {
	g.Meta `path:"/role/grantable" method:"get" tags:"权限/角色" summary:"查询当前用户可授权限范围"`
}

// RoleAreaChildrenReq 查询角色配置页里的区域树某一层。
// 它按当前用户可授权范围过滤,用于“勾选授权树”,不是应用端可见树。
type RoleAreaChildrenReq struct {
	g.Meta   `path:"/role/area-children" method:"get" tags:"权限/角色" summary:"查询角色配置用区域树子节点"`
	ParentId int    `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Kind     string `json:"kind" dc:"区域树类型:area=安保区域管理范围,resarea=业务资源区域范围"`
}
