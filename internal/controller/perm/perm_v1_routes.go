package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/model"
	"security-permission/internal/service"
)

// ok 包装成功响应。
// GoFrame 外层可能还有统一响应中间件,这里保持业务层 code/message/data 一致。
func ok(data interface{}) *v1.CommonRes {
	return &v1.CommonRes{Code: 0, Message: "ok", Data: data}
}

// fail 包装业务失败响应。
// 这里返回 nil error,让前端总能拿到统一 CommonRes 结构。
func fail(msg string) *v1.CommonRes {
	return &v1.CommonRes{Code: 1, Message: msg}
}

// roleFromReq 只做请求结构到领域模型的字段搬运。
// 创建人、委派合并、可编辑校验都在 RoleService 里统一处理,避免前端伪造 createdBy。
func roleFromReq(req *v1.RoleSaveReq) *model.Role {
	return &model.Role{
		Id:                 req.Id,
		Name:               req.Name,
		Description:        req.Description,
		MenuCodes:          req.MenuCodes,
		AreaScopes:         scopesFromReq(req.AreaScopes),
		OrgScopes:          scopesFromReq(req.OrgScopes),
		ResourceAreaScopes: scopesFromReq(req.ResourceAreaScopes),
	}
}

// scopesFromReq 把接口层的数据范围转换成领域模型。
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

// actionsFromReq 把接口层资源操作转换成领域模型。
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

// userFromReq 只搬运用户基础字段和角色绑定。
// 用户保存时的功能权限、组织数据权限、角色可分配范围由服务层校验。
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
	s := service.S.Runtime
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
	user := service.S.Runtime.User(req.UserId)
	if user == nil {
		return fail("用户不存在"), nil
	}
	var d *service.Decision
	switch req.Type {
	case v1.AuthTypeMenu:
		d = service.S.Auth.CheckMenu(user, req.Code)
	case v1.AuthTypeArea:
		d = service.S.Auth.CheckArea(user, req.NodeId)
	case v1.AuthTypeOrg:
		d = service.S.Auth.CheckOrg(user, req.NodeId)
	case v1.AuthTypeResource:
		d = service.S.Auth.CheckResource(user, req.ResourceId, req.Action)
	default:
		return fail("未知鉴权类型:" + req.Type), nil
	}
	return ok(d), nil
}

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) (*v1.CommonRes, error) {
	return ok(service.S.Roles.List()), nil
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*v1.CommonRes, error) {
	role := service.S.Roles.Get(req.Id)
	if role == nil {
		return fail("角色不存在"), nil
	}
	return ok(role), nil
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*v1.CommonRes, error) {
	// 接口层只负责把请求整理成角色聚合;真正的菜单 code 转换、权限上限、保留合并和落库都放在 RoleService。
	role := roleFromReq(req)
	if role.Name == "" {
		return fail("角色名称不能为空"), nil
	}

	result, err := service.S.Roles.SaveBasic(ctx, req.UserId, role)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return &v1.CommonRes{Code: 0, Message: "ok", Data: result.Role, Preserved: result.Preserved}, nil
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.Roles.Delete(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*v1.CommonRes, error) {
	return ok(service.S.Delegate.GrantableSet(req.UserId)), nil
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.Delegate.RoleAreaChildren(ctx, req.UserId, req.ParentId, req.Kind)), nil
}

func (c *ControllerV1) RoleResourcePermission(ctx context.Context, req *v1.RoleResourcePermissionReq) (*v1.CommonRes, error) {
	permission, err := service.S.Roles.ResourcePermission(req.UserId, req.RoleId)
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(permission), nil
}

func (c *ControllerV1) RoleResourcePermissionSave(ctx context.Context, req *v1.RoleResourcePermissionSaveReq) (*v1.CommonRes, error) {
	result, err := service.S.Roles.SaveResourcePermission(ctx, req.UserId, req.RoleId, actionsFromReq(req.ResourceActions), req.ResourceOverrides)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return &v1.CommonRes{Code: 0, Message: "ok", Data: map[string]interface{}{
		"roleId":            result.Role.Id,
		"resourceActions":   result.Role.ResourceActions,
		"resourceOverrides": result.Role.ResourceOverrides,
	}, Preserved: result.Preserved}, nil
}

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) (*v1.CommonRes, error) {
	return ok(service.S.Users.List()), nil
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*v1.CommonRes, error) {
	user := service.S.Users.Get(req.Id)
	if user == nil {
		return fail("用户不存在"), nil
	}
	return ok(user), nil
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*v1.CommonRes, error) {
	// 账号保存包含两件事:用户基础信息 + 角色绑定;服务层会同时校验账号管理功能、ORG 数据范围和角色可分配范围。
	user := userFromReq(req)
	if user.Name == "" {
		return fail("用户名不能为空"), nil
	}
	saved, err := service.S.Users.SaveManaged(ctx, req.UserId, user)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.Users.Delete(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.AppMenus(req.UserId)), nil
}

func (c *ControllerV1) AppAreaTree(ctx context.Context, req *v1.AppAreaTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.VisibleAreas(req.UserId)), nil
}

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.AreaChildren(ctx, req.UserId, req.ParentId, req.Page, req.Size)), nil
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.SearchAreas(ctx, req.UserId, req.Q, req.Scope, req.Page, req.Size)), nil
}

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.AreaResourcesPaged(ctx, req.UserId, req.AreaId, req.Page, req.Size)), nil
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.SysMenus(req.UserId)), nil
}

func (c *ControllerV1) ManageAreaTree(ctx context.Context, req *v1.ManageAreaTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.ManageAreas(req.UserId)), nil
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.ManageAreaChildren(ctx, req.UserId, req.ParentId, req.Page, req.Size)), nil
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.ManageAreaDetail(ctx, req.UserId, req.AreaId)), nil
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.Areas.Save(ctx, req.UserId, &service.AreaSaveInput{
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
	if err := service.S.Areas.Reorder(ctx, req.UserId, &service.AreaReorderInput{
		AreaId:   req.AreaId,
		ToAreaId: req.ToAreaId,
	}); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (*v1.CommonRes, error) {
	if err := service.S.Areas.Delete(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.ManageOrgs(req.UserId)), nil
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*v1.CommonRes, error) {
	return ok(service.S.Views.ManageOrgDetail(req.UserId, req.OrgId)), nil
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.Orgs.Save(ctx, req.UserId, &service.OrgSaveInput{
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
	if err := service.S.Orgs.Delete(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*v1.CommonRes, error) {
	saved, err := service.S.Resources.Save(ctx, req.UserId, &service.ResourceSaveInput{
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
	if err := service.S.Resources.Delete(ctx, req.UserId, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}
