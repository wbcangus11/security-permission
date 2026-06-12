package v1

import "github.com/gogf/gf/v2/frame/g"

type EmptyRes struct{}

type MetaReq struct {
	g.Meta `path:"/meta" method:"get" tags:"Permission" summary:"metadata"`
}

type AuthCheckReq struct {
	g.Meta `path:"/auth/check" method:"post" tags:"Permission/Auth" summary:"check permission"`
}

type RoleListReq struct {
	g.Meta `path:"/role/list" method:"get" tags:"Permission/Role" summary:"list roles"`
}
type RoleDetailReq struct {
	g.Meta `path:"/role/detail" method:"get" tags:"Permission/Role" summary:"role detail"`
}
type RoleSaveReq struct {
	g.Meta `path:"/role/save" method:"post" tags:"Permission/Role" summary:"save role"`
}
type RoleDeleteReq struct {
	g.Meta `path:"/role/delete" method:"post" tags:"Permission/Role" summary:"delete role"`
}
type RoleGrantableReq struct {
	g.Meta `path:"/role/grantable" method:"get" tags:"Permission/Role" summary:"role grantable set"`
}
type RoleAreaChildrenReq struct {
	g.Meta `path:"/role/area-children" method:"get" tags:"Permission/Role" summary:"role area children"`
}

type UserListReq struct {
	g.Meta `path:"/user/list" method:"get" tags:"Permission/User" summary:"list users"`
}
type UserDetailReq struct {
	g.Meta `path:"/user/detail" method:"get" tags:"Permission/User" summary:"user detail"`
}
type UserSaveReq struct {
	g.Meta `path:"/user/save" method:"post" tags:"Permission/User" summary:"save user"`
}
type UserDeleteReq struct {
	g.Meta `path:"/user/delete" method:"post" tags:"Permission/User" summary:"delete user"`
}

type AppMenuReq struct {
	g.Meta `path:"/app/menu" method:"get" tags:"Permission/App" summary:"app menus"`
}
type AppAreaTreeReq struct {
	g.Meta `path:"/app/area-tree" method:"get" tags:"Permission/App" summary:"app area tree"`
}
type AppAreaChildrenReq struct {
	g.Meta `path:"/app/area-children" method:"get" tags:"Permission/App" summary:"app area children"`
}
type AppAreaSearchReq struct {
	g.Meta `path:"/app/area-search" method:"get" tags:"Permission/App" summary:"app area search"`
}
type AppResourceListReq struct {
	g.Meta `path:"/app/resource-list" method:"get" tags:"Permission/App" summary:"app resources"`
}

type ManageMenuReq struct {
	g.Meta `path:"/manage/menu" method:"get" tags:"Permission/Manage" summary:"manage menus"`
}
type ManageAreaTreeReq struct {
	g.Meta `path:"/manage/area-tree" method:"get" tags:"Permission/Manage" summary:"manage area tree"`
}
type ManageAreaChildrenReq struct {
	g.Meta `path:"/manage/area-children" method:"get" tags:"Permission/Manage" summary:"manage area children"`
}
type ManageAreaDetailReq struct {
	g.Meta `path:"/manage/area-detail" method:"get" tags:"Permission/Manage" summary:"manage area detail"`
}
type ManageAreaSaveReq struct {
	g.Meta `path:"/manage/area-save" method:"post" tags:"Permission/Manage" summary:"save area"`
}
type ManageAreaReorderReq struct {
	g.Meta `path:"/manage/area-reorder" method:"post" tags:"Permission/Manage" summary:"reorder area"`
}
type ManageAreaDeleteReq struct {
	g.Meta `path:"/manage/area-delete" method:"post" tags:"Permission/Manage" summary:"delete area"`
}
type ManageOrgTreeReq struct {
	g.Meta `path:"/manage/org-tree" method:"get" tags:"Permission/Manage" summary:"manage org tree"`
}
type ManageOrgDetailReq struct {
	g.Meta `path:"/manage/org-detail" method:"get" tags:"Permission/Manage" summary:"manage org detail"`
}
type ManageOrgSaveReq struct {
	g.Meta `path:"/manage/org-save" method:"post" tags:"Permission/Manage" summary:"save org"`
}
type ManageOrgDeleteReq struct {
	g.Meta `path:"/manage/org-delete" method:"post" tags:"Permission/Manage" summary:"delete org"`
}
type ManageResourceSaveReq struct {
	g.Meta `path:"/manage/resource-save" method:"post" tags:"Permission/Manage" summary:"save resource"`
}
type ManageResourceDeleteReq struct {
	g.Meta `path:"/manage/resource-delete" method:"post" tags:"Permission/Manage" summary:"delete resource"`
}
