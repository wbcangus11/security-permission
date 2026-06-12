package perm

import (
	"context"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	"security-permission/api/perm/v1"
)

type routeHandler func(r *ghttp.Request)

func call(ctx context.Context, h routeHandler) (*v1.EmptyRes, error) {
	h(g.RequestFromCtx(ctx))
	return nil, nil
}

func (c *ControllerV1) Meta(ctx context.Context, req *v1.MetaReq) (*v1.EmptyRes, error) {
	return call(ctx, meta)
}

func (c *ControllerV1) AuthCheck(ctx context.Context, req *v1.AuthCheckReq) (*v1.EmptyRes, error) {
	return call(ctx, check)
}

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) (*v1.EmptyRes, error) {
	return call(ctx, listRoles)
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*v1.EmptyRes, error) {
	return call(ctx, getRole)
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*v1.EmptyRes, error) {
	return call(ctx, saveRole)
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (*v1.EmptyRes, error) {
	return call(ctx, deleteRole)
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*v1.EmptyRes, error) {
	return call(ctx, grantable)
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (*v1.EmptyRes, error) {
	return call(ctx, roleAreaChildren)
}

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) (*v1.EmptyRes, error) {
	return call(ctx, listUsers)
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*v1.EmptyRes, error) {
	return call(ctx, getUser)
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*v1.EmptyRes, error) {
	return call(ctx, saveUser)
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (*v1.EmptyRes, error) {
	return call(ctx, deleteUser)
}

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) (*v1.EmptyRes, error) {
	return call(ctx, appMenus)
}

func (c *ControllerV1) AppAreaTree(ctx context.Context, req *v1.AppAreaTreeReq) (*v1.EmptyRes, error) {
	return call(ctx, visibleAreas)
}

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*v1.EmptyRes, error) {
	return call(ctx, areaChildren)
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*v1.EmptyRes, error) {
	return call(ctx, areaSearch)
}

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*v1.EmptyRes, error) {
	return call(ctx, areaResources)
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (*v1.EmptyRes, error) {
	return call(ctx, sysMenus)
}

func (c *ControllerV1) ManageAreaTree(ctx context.Context, req *v1.ManageAreaTreeReq) (*v1.EmptyRes, error) {
	return call(ctx, manageAreas)
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*v1.EmptyRes, error) {
	return call(ctx, manageAreaChildren)
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*v1.EmptyRes, error) {
	return call(ctx, manageAreaDetail)
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*v1.EmptyRes, error) {
	return call(ctx, saveArea)
}

func (c *ControllerV1) ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (*v1.EmptyRes, error) {
	return call(ctx, reorderArea)
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (*v1.EmptyRes, error) {
	return call(ctx, deleteArea)
}

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (*v1.EmptyRes, error) {
	return call(ctx, manageOrgs)
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*v1.EmptyRes, error) {
	return call(ctx, manageOrgDetail)
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*v1.EmptyRes, error) {
	return call(ctx, saveOrg)
}

func (c *ControllerV1) ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (*v1.EmptyRes, error) {
	return call(ctx, deleteOrg)
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*v1.EmptyRes, error) {
	return call(ctx, saveResource)
}

func (c *ControllerV1) ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (*v1.EmptyRes, error) {
	return call(ctx, deleteResource)
}
