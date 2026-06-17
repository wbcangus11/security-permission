package v1

import "github.com/gogf/gf/v2/frame/g"

type CommonRes struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	Preserved int         `json:"preserved,omitempty"`
}

type DataScope struct {
	NodeId       int  `json:"nodeId"`
	IncludeChild bool `json:"includeChild"`
}

type ResourceAction struct {
	ResourceId int    `json:"resourceId"`
	ActionCode string `json:"actionCode"`
}

type MetaReq struct {
	g.Meta `path:"/meta" method:"get" tags:"Permission" summary:"metadata"`
}

type AuthCheckReq struct {
	g.Meta     `path:"/auth/check" method:"post" tags:"Permission/Auth" summary:"check permission"`
	UserId     int    `json:"userId"`
	Type       string `json:"type"`
	Code       string `json:"code"`
	NodeId     int    `json:"nodeId"`
	ResourceId int    `json:"resourceId"`
	Action     string `json:"action"`
}

type RoleListReq struct {
	g.Meta `path:"/role/list" method:"get" tags:"Permission/Role" summary:"list roles"`
}
type RoleDetailReq struct {
	g.Meta `path:"/role/detail" method:"get" tags:"Permission/Role" summary:"role detail"`
	Id     int `json:"id"`
}
type RoleSaveReq struct {
	g.Meta             `path:"/role/save" method:"post" tags:"Permission/Role" summary:"save role"`
	Actor              int              `json:"actor"`
	Id                 int              `json:"id"`
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	CreatedBy          int              `json:"createdBy"`
	MenuIds            []int            `json:"menuIds"`
	AreaScopes         []DataScope      `json:"areaScopes"`
	OrgScopes          []DataScope      `json:"orgScopes"`
	ResourceAreaScopes []DataScope      `json:"resourceAreaScopes"`
	ResourceActions    []ResourceAction `json:"resourceActions"`
	ResourceOverrides  []int            `json:"resourceOverrides"`
}
type RoleDeleteReq struct {
	g.Meta `path:"/role/delete" method:"post" tags:"Permission/Role" summary:"delete role"`
	Actor  int `json:"actor"`
	Id     int `json:"id"`
}
type RoleGrantableReq struct {
	g.Meta `path:"/role/grantable" method:"get" tags:"Permission/Role" summary:"role grantable set"`
	Actor  int `json:"actor"`
}
type RoleAreaChildrenReq struct {
	g.Meta   `path:"/role/area-children" method:"get" tags:"Permission/Role" summary:"role area children"`
	Actor    int    `json:"actor"`
	ParentId int    `json:"parentId"`
	Kind     string `json:"kind"`
}

type UserListReq struct {
	g.Meta `path:"/user/list" method:"get" tags:"Permission/User" summary:"list users"`
}
type UserDetailReq struct {
	g.Meta `path:"/user/detail" method:"get" tags:"Permission/User" summary:"user detail"`
	Id     int `json:"id"`
}
type UserSaveReq struct {
	g.Meta      `path:"/user/save" method:"post" tags:"Permission/User" summary:"save user"`
	UserId      int    `json:"userId"`
	Id          int    `json:"id"`
	Name        string `json:"name"`
	OrgId       int    `json:"orgId"`
	IsSuperuser bool   `json:"isSuperuser"`
	RoleIds     []int  `json:"roleIds"`
}
type UserDeleteReq struct {
	g.Meta `path:"/user/delete" method:"post" tags:"Permission/User" summary:"delete user"`
	UserId int `json:"userId"`
	Id     int `json:"id"`
}

type AppMenuReq struct {
	g.Meta `path:"/app/menu" method:"get" tags:"Permission/App" summary:"app menus"`
	UserId int `json:"userId"`
}
type AppAreaTreeReq struct {
	g.Meta `path:"/app/area-tree" method:"get" tags:"Permission/App" summary:"app area tree"`
	UserId int `json:"userId"`
}
type AppAreaChildrenReq struct {
	g.Meta   `path:"/app/area-children" method:"get" tags:"Permission/App" summary:"app area children"`
	UserId   int `json:"userId"`
	ParentId int `json:"parentId"`
	Page     int `json:"page"`
	Size     int `json:"size"`
}
type AppAreaSearchReq struct {
	g.Meta `path:"/app/area-search" method:"get" tags:"Permission/App" summary:"app area search"`
	UserId int    `json:"userId"`
	Q      string `json:"q"`
	Scope  string `json:"scope"`
	Page   int    `json:"page"`
	Size   int    `json:"size"`
}
type AppResourceListReq struct {
	g.Meta `path:"/app/resource-list" method:"get" tags:"Permission/App" summary:"app resources"`
	UserId int `json:"userId"`
	AreaId int `json:"areaId"`
	Page   int `json:"page"`
	Size   int `json:"size"`
}

type ManageMenuReq struct {
	g.Meta `path:"/manage/menu" method:"get" tags:"Permission/Manage" summary:"manage menus"`
	UserId int `json:"userId"`
}
type ManageAreaTreeReq struct {
	g.Meta `path:"/manage/area-tree" method:"get" tags:"Permission/Manage" summary:"manage area tree"`
	UserId int `json:"userId"`
}
type ManageAreaChildrenReq struct {
	g.Meta   `path:"/manage/area-children" method:"get" tags:"Permission/Manage" summary:"manage area children"`
	UserId   int `json:"userId"`
	ParentId int `json:"parentId"`
	Page     int `json:"page"`
	Size     int `json:"size"`
}
type ManageAreaDetailReq struct {
	g.Meta `path:"/manage/area-detail" method:"get" tags:"Permission/Manage" summary:"manage area detail"`
	UserId int `json:"userId"`
	AreaId int `json:"areaId"`
}
type ManageAreaSaveReq struct {
	g.Meta   `path:"/manage/area-save" method:"post" tags:"Permission/Manage" summary:"save area"`
	UserId   int    `json:"userId"`
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
}
type ManageAreaReorderReq struct {
	g.Meta    `path:"/manage/area-reorder" method:"post" tags:"Permission/Manage" summary:"reorder area"`
	UserId    int    `json:"userId"`
	Id        int    `json:"id"`
	Direction string `json:"direction"`
}
type ManageAreaDeleteReq struct {
	g.Meta `path:"/manage/area-delete" method:"post" tags:"Permission/Manage" summary:"delete area"`
	UserId int `json:"userId"`
	Id     int `json:"id"`
}
type ManageOrgTreeReq struct {
	g.Meta `path:"/manage/org-tree" method:"get" tags:"Permission/Manage" summary:"manage org tree"`
	UserId int `json:"userId"`
}
type ManageOrgDetailReq struct {
	g.Meta `path:"/manage/org-detail" method:"get" tags:"Permission/Manage" summary:"manage org detail"`
	UserId int `json:"userId"`
	OrgId  int `json:"orgId"`
}
type ManageOrgSaveReq struct {
	g.Meta   `path:"/manage/org-save" method:"post" tags:"Permission/Manage" summary:"save org"`
	UserId   int    `json:"userId"`
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
}
type ManageOrgDeleteReq struct {
	g.Meta `path:"/manage/org-delete" method:"post" tags:"Permission/Manage" summary:"delete org"`
	UserId int `json:"userId"`
	Id     int `json:"id"`
}
type ManageResourceSaveReq struct {
	g.Meta `path:"/manage/resource-save" method:"post" tags:"Permission/Manage" summary:"save resource"`
	UserId int    `json:"userId"`
	Id     int    `json:"id"`
	AreaId int    `json:"areaId"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}
type ManageResourceDeleteReq struct {
	g.Meta `path:"/manage/resource-delete" method:"post" tags:"Permission/Manage" summary:"delete resource"`
	UserId int `json:"userId"`
	Id     int `json:"id"`
}
