package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/middleware"
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

func requestActor(ctx context.Context) (string, *v1.CommonRes) {
	actorID, err := middleware.ActorID(ctx)
	if err != nil {
		return "", fail(err.Error())
	}
	return actorID, nil
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
	s := service.RuntimeService()
	demoMode := middleware.DemoMode(ctx)
	actorID := ""
	if !demoMode {
		var failure *v1.CommonRes
		actorID, failure = requestActor(ctx)
		if failure != nil {
			return failure, nil
		}
	}
	return ok(s.Meta(actorID, demoMode)), nil
}

func (c *ControllerV1) AuthCheck(ctx context.Context, req *v1.AuthCheckReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	actor := service.RuntimeService().User(actorID)
	if req.UserId != actorID && !actor.IsSuperuser && !service.AuthService().CheckMenu(actor, "sys.person.role").Allow {
		return fail("无权查看其他用户的鉴权结果"), nil
	}
	user := service.RuntimeService().User(req.UserId)
	if user == nil {
		return fail("用户不存在"), nil
	}
	var d *model.Decision
	switch req.Type {
	case v1.AuthTypeMenu:
		d = service.AuthService().CheckMenu(user, req.Code)
	case v1.AuthTypeArea:
		d = service.AuthService().CheckArea(user, req.NodeId)
	case v1.AuthTypeOrg:
		d = service.AuthService().CheckOrg(user, req.NodeId)
	case v1.AuthTypeResource:
		d = service.AuthService().CheckResource(user, req.ResourceId, req.Action)
	default:
		return fail("未知鉴权类型:" + req.Type), nil
	}
	return ok(d), nil
}

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.RoleService().List(actorID)), nil
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	role, err := service.RoleService().Get(actorID, req.Id)
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(role), nil
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	// 接口层只负责把请求整理成角色聚合;真正的菜单 code 转换、权限上限、保留合并和落库都放在 RoleService。
	role := roleFromReq(req)
	if role.Name == "" {
		return fail("角色名称不能为空"), nil
	}

	saved, preserved, err := service.RoleService().SaveBasic(ctx, actorID, role)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return &v1.CommonRes{Code: 0, Message: "ok", Data: saved, Preserved: preserved}, nil
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.RoleService().Delete(ctx, actorID, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.DelegationService().GrantableSet(actorID)), nil
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	items, err := service.DelegationService().RoleAreaChildren(ctx, actorID, req.ParentId, req.Kind)
	if err != nil {
		return fail("查询角色授权树失败"), err
	}
	return ok(items), nil
}

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.UserService().List(actorID)), nil
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	user, err := service.UserService().Get(actorID, req.Id)
	if err != nil {
		return fail(err.Error()), nil
	}
	return ok(user), nil
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	// 账号保存包含两件事:用户基础信息 + 角色绑定;服务层会同时校验账号管理功能、ORG 数据范围和角色可分配范围。
	user := userFromReq(req)
	if user.Name == "" {
		return fail("用户名不能为空"), nil
	}
	saved, err := service.UserService().SaveManaged(ctx, actorID, user)
	if err != nil {
		return fail("保存失败:" + err.Error()), nil
	}
	return ok(saved), nil
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.UserService().Delete(ctx, actorID, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().AppMenus(actorID)), nil
}

func (c *ControllerV1) AppAreaTree(ctx context.Context, req *v1.AppAreaTreeReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().VisibleAreas(actorID)), nil
}

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	data, err := service.ViewService().AreaChildren(ctx, actorID, req.ParentId, req.Page, req.Size)
	if err != nil {
		return fail("查询区域树失败"), err
	}
	return ok(data), nil
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	data, err := service.ViewService().SearchAreas(ctx, actorID, req.Q, req.Scope, req.Page, req.Size)
	if err != nil {
		return fail("搜索区域失败"), err
	}
	return ok(data), nil
}

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	data, err := service.ViewService().AreaResourcesPaged(ctx, actorID, req.AreaId, req.Page, req.Size)
	if err != nil {
		return fail("查询资源列表失败"), err
	}
	return ok(data), nil
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().SysMenus(actorID)), nil
}

func (c *ControllerV1) ManageAreaTree(ctx context.Context, req *v1.ManageAreaTreeReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().ManageAreas(actorID)), nil
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	data, err := service.ViewService().ManageAreaChildren(ctx, actorID, req.ParentId, req.Page, req.Size)
	if err != nil {
		return fail("查询管理区域树失败"), err
	}
	return ok(data), nil
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	data, err := service.ViewService().ManageAreaDetail(ctx, actorID, req.AreaId)
	if err != nil {
		return fail("查询区域详情失败"), err
	}
	return ok(data), nil
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	saved, err := service.AreaService().Save(ctx, actorID, &model.AreaSaveInput{
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
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.AreaService().Reorder(ctx, actorID, &model.AreaReorderInput{
		AreaId:   req.AreaId,
		ToAreaId: req.ToAreaId,
	}); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.AreaService().Delete(ctx, actorID, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().ManageOrgs(actorID)), nil
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	return ok(service.ViewService().ManageOrgDetail(actorID, req.OrgId)), nil
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	saved, err := service.OrgService().Save(ctx, actorID, &model.OrgSaveInput{
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
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.OrgService().Delete(ctx, actorID, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*v1.CommonRes, error) {
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	saved, err := service.ResourceService().Save(ctx, actorID, &model.ResourceSaveInput{
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
	actorID, failure := requestActor(ctx)
	if failure != nil {
		return failure, nil
	}
	if err := service.ResourceService().Delete(ctx, actorID, req.Id); err != nil {
		return fail(err.Error()), nil
	}
	return ok(true), nil
}
