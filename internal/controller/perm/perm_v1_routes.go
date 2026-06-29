package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/model"
	"security-permission/internal/service"
)

func ok(data interface{}) *v1.CommonRes {
	return &v1.CommonRes{Code: 0, Message: "ok", Data: data}
}

func fail(msg string) *v1.CommonRes {
	return &v1.CommonRes{Code: 1, Message: msg}
}

func roleFromReq(req *v1.RoleSaveReq) *model.Role {
	return &model.Role{
		Id:                 req.Id,
		Name:               req.Name,
		Description:        req.Description,
		CreatedBy:          req.CreatedBy,
		MenuIds:            req.MenuIds,
		AreaScopes:         scopesFromReq(req.AreaScopes),
		OrgScopes:          scopesFromReq(req.OrgScopes),
		ResourceAreaScopes: scopesFromReq(req.ResourceAreaScopes),
		ResourceActions:    actionsFromReq(req.ResourceActions),
		ResourceOverrides:  req.ResourceOverrides,
	}
}

func scopesFromReq(items []v1.DataScope) []model.DataScope {
	scopes := make([]model.DataScope, 0, len(items))
	for _, item := range items {
		scopes = append(scopes, model.DataScope{
			NodeId:       item.NodeId,
			IncludeChild: item.IncludeChild,
		})
	}
	return scopes
}

func actionsFromReq(items []v1.ResourceAction) []model.ResourceAction {
	actions := make([]model.ResourceAction, 0, len(items))
	for _, item := range items {
		actions = append(actions, model.ResourceAction{
			ResourceId: item.ResourceId,
			ActionCode: item.ActionCode,
		})
	}
	return actions
}

func userFromReq(req *v1.UserSaveReq) *model.User {
	return &model.User{
		Id:          req.Id,
		Name:        req.Name,
		OrgId:       req.OrgId,
		IsSuperuser: req.IsSuperuser,
		RoleIds:     req.RoleIds,
	}
}

func (c *ControllerV1) Meta(ctx context.Context, req *v1.MetaReq) (*v1.CommonRes, error) {
	s := service.S
	return ok(map[string]interface{}{
		"areas":     s.Areas(),
		"orgs":      s.Orgs(),
		"menus":     s.Menus(),
		"resources": s.Resources(),
		"actions":   s.Actions(),
		"users":     s.Users(),
	}), nil
}

func (c *ControllerV1) AuthCheck(ctx context.Context, req *v1.AuthCheckReq) (*v1.CommonRes, error) {
	user := service.S.User(req.UserId)
	if user == nil {
		return fail("用户不存在"), nil
	}
	var d *service.Decision
	switch req.Type {
	case v1.AuthTypeMenu:
		d = service.S.CheckMenu(user, req.Code)
	case v1.AuthTypeArea:
		d = service.S.CheckArea(user, req.NodeId)
	case v1.AuthTypeOrg:
		d = service.S.CheckOrg(user, req.NodeId)
	case v1.AuthTypeResource:
		d = service.S.CheckResource(user, req.ResourceId, req.Action)
	default:
		return fail("未知鉴权类型:" + req.Type), nil
	}
	return ok(d), nil
}

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) (*v1.CommonRes, error) {
	return ok(service.S.Roles()), nil
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*v1.CommonRes, error) {
	role := service.S.Role(req.Id)
	if role == nil {
		return fail("角色不存在"), nil
	}
	return ok(role), nil
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*v1.CommonRes, error) {
	role := roleFromReq(req)
	if role.Name == "" {
		return fail("角色名称不能为空"), nil
	}
	old := service.S.Role(role.Id)
	if old != nil {
		if err := service.S.GuardManageRole(req.Actor, role.Id); err != nil {
			return fail(err.Error()), nil
		}
		role.CreatedBy = old.CreatedBy
	} else {
		role.CreatedBy = req.Actor
	}
	merged, preserved := service.S.MergeDelegated(req.Actor, old, role)
	saved, err := service.S.SaveRole(ctx, merged)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return &v1.CommonRes{Code: 0, Message: "ok", Data: saved, Preserved: preserved}, nil
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.DeleteRole(ctx, req.Actor, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*v1.CommonRes, error) {
	return ok(service.S.GrantableSet(req.Actor)), nil
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.RoleAreaChildren(ctx, req.Actor, req.ParentId, req.Kind)), nil
}

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) (*v1.CommonRes, error) {
	return ok(service.S.Users()), nil
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*v1.CommonRes, error) {
	user := service.S.User(req.Id)
	if user == nil {
		return fail("用户不存在"), nil
	}
	return ok(user), nil
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*v1.CommonRes, error) {
	user := userFromReq(req)
	if user.Name == "" {
		return fail("用户名不能为空"), nil
	}
	saved, err := service.S.SaveUserManaged(ctx, req.UserId, user)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.DeleteUser(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) (*v1.CommonRes, error) {
	return ok(service.S.AppMenus(req.UserId)), nil
}

func (c *ControllerV1) AppAreaTree(ctx context.Context, req *v1.AppAreaTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.VisibleAreas(req.UserId)), nil
}

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.AreaChildren(ctx, req.UserId, req.ParentId, req.Page, req.Size)), nil
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*v1.CommonRes, error) {
	return ok(service.S.SearchAreas(ctx, req.UserId, req.Q, req.Scope, req.Page, req.Size)), nil
}

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*v1.CommonRes, error) {
	return ok(service.S.AreaResourcesPaged(ctx, req.UserId, req.AreaId, req.Page, req.Size)), nil
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (*v1.CommonRes, error) {
	return ok(service.S.SysMenus(req.UserId)), nil
}

func (c *ControllerV1) ManageAreaTree(ctx context.Context, req *v1.ManageAreaTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.ManageAreas(req.UserId)), nil
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.ManageAreaChildren(ctx, req.UserId, req.ParentId, req.Page, req.Size)), nil
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*v1.CommonRes, error) {
	return ok(service.S.ManageAreaDetail(ctx, req.UserId, req.AreaId)), nil
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.SaveArea(ctx, req.UserId, &service.AreaSaveInput{
		Id:       req.Id,
		ParentId: req.ParentId,
		Name:     req.Name,
	})
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (*v1.CommonRes, error) {
	if err := service.S.ReorderArea(ctx, req.UserId, &service.AreaReorderInput{
		Id:        req.Id,
		Direction: req.Direction,
	}); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.DeleteArea(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.ManageOrgs(req.UserId)), nil
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*v1.CommonRes, error) {
	return ok(service.S.ManageOrgDetail(req.UserId, req.OrgId)), nil
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.SaveOrg(ctx, req.UserId, &service.OrgSaveInput{
		Id:       req.Id,
		ParentId: req.ParentId,
		Name:     req.Name,
	})
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.DeleteOrg(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.SaveResource(ctx, req.UserId, &service.ResourceSaveInput{
		Id:     req.Id,
		AreaId: req.AreaId,
		Name:   req.Name,
		Type:   req.Type,
	})
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.DeleteResource(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}
