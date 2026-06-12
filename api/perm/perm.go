package perm

import (
	"context"

	"security-permission/api/perm/v1"
)

type IPermV1 interface {
	Meta(ctx context.Context, req *v1.MetaReq) (res *v1.EmptyRes, err error)

	AuthCheck(ctx context.Context, req *v1.AuthCheckReq) (res *v1.EmptyRes, err error)

	RoleList(ctx context.Context, req *v1.RoleListReq) (res *v1.EmptyRes, err error)
	RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (res *v1.EmptyRes, err error)
	RoleSave(ctx context.Context, req *v1.RoleSaveReq) (res *v1.EmptyRes, err error)
	RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (res *v1.EmptyRes, err error)
	RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (res *v1.EmptyRes, err error)
	RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (res *v1.EmptyRes, err error)

	UserList(ctx context.Context, req *v1.UserListReq) (res *v1.EmptyRes, err error)
	UserDetail(ctx context.Context, req *v1.UserDetailReq) (res *v1.EmptyRes, err error)
	UserSave(ctx context.Context, req *v1.UserSaveReq) (res *v1.EmptyRes, err error)
	UserDelete(ctx context.Context, req *v1.UserDeleteReq) (res *v1.EmptyRes, err error)

	AppMenu(ctx context.Context, req *v1.AppMenuReq) (res *v1.EmptyRes, err error)
	AppAreaTree(ctx context.Context, req *v1.AppAreaTreeReq) (res *v1.EmptyRes, err error)
	AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (res *v1.EmptyRes, err error)
	AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (res *v1.EmptyRes, err error)
	AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (res *v1.EmptyRes, err error)

	ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (res *v1.EmptyRes, err error)
	ManageAreaTree(ctx context.Context, req *v1.ManageAreaTreeReq) (res *v1.EmptyRes, err error)
	ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (res *v1.EmptyRes, err error)
	ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (res *v1.EmptyRes, err error)
	ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (res *v1.EmptyRes, err error)
	ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (res *v1.EmptyRes, err error)
	ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (res *v1.EmptyRes, err error)
	ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (res *v1.EmptyRes, err error)
	ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (res *v1.EmptyRes, err error)
	ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (res *v1.EmptyRes, err error)
	ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (res *v1.EmptyRes, err error)
	ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (res *v1.EmptyRes, err error)
	ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (res *v1.EmptyRes, err error)
}
