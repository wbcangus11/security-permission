package perm

import (
	"context"

	"security-permission/api/perm/v1"
)

// IPermV1 是权限演示系统对外暴露的 HTTP API 集合。
// GoFrame 会按 v1 请求结构体里的 g.Meta 生成路由,控制器只需要实现这里的方法。
type IPermV1 interface {
	Meta(ctx context.Context, req *v1.MetaReq) (res *v1.CommonRes, err error)

	AuthCheck(ctx context.Context, req *v1.AuthCheckReq) (res *v1.CommonRes, err error)

	RoleList(ctx context.Context, req *v1.RoleListReq) (res *v1.CommonRes, err error)
	RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (res *v1.CommonRes, err error)
	RoleSave(ctx context.Context, req *v1.RoleSaveReq) (res *v1.CommonRes, err error)
	RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (res *v1.CommonRes, err error)
	RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (res *v1.CommonRes, err error)
	RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (res *v1.CommonRes, err error)

	UserList(ctx context.Context, req *v1.UserListReq) (res *v1.CommonRes, err error)
	UserDetail(ctx context.Context, req *v1.UserDetailReq) (res *v1.CommonRes, err error)
	UserSave(ctx context.Context, req *v1.UserSaveReq) (res *v1.CommonRes, err error)
	UserDelete(ctx context.Context, req *v1.UserDeleteReq) (res *v1.CommonRes, err error)

	AppMenu(ctx context.Context, req *v1.AppMenuReq) (res *v1.CommonRes, err error)
	AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (res *v1.CommonRes, err error)
	AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (res *v1.CommonRes, err error)
	AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (res *v1.CommonRes, err error)

	ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (res *v1.CommonRes, err error)
	ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (res *v1.CommonRes, err error)
	ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (res *v1.CommonRes, err error)
	ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (res *v1.CommonRes, err error)
	ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (res *v1.CommonRes, err error)
	ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (res *v1.CommonRes, err error)
	ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (res *v1.CommonRes, err error)
	ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (res *v1.CommonRes, err error)
	ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (res *v1.CommonRes, err error)
	ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (res *v1.CommonRes, err error)
	ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (res *v1.CommonRes, err error)
	ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (res *v1.CommonRes, err error)
}
