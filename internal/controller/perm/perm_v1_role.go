package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) (*v1.RoleListRes, error) {
	roles, err := permission.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	res := &v1.RoleListRes{Items: make([]v1.RoleListItem, 0, len(roles))}
	for _, role := range roles {
		if role != nil {
			res.Items = append(res.Items, v1.RoleListItem{
				Id: role.Id, Name: role.Name, Description: role.Description, CreatedBy: role.CreatedBy,
			})
		}
	}
	return res, nil
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*v1.RoleDetailRes, error) {
	role, err := permission.GetRole(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return roleDetailRes(role), nil
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*v1.RoleSaveRes, error) {
	role, err := permission.SaveRole(ctx, &model.RoleSaveInput{
		RoleId: req.Id, Name: req.Name, Description: req.Description,
		Permissions: rolePermissionChangesInput(req.Permissions),
	})
	if err != nil {
		return nil, err
	}
	detail := roleDetailRes(role)
	res := v1.RoleSaveRes(*detail)
	return &res, nil
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (*v1.RoleDeleteRes, error) {
	if err := permission.DeleteRole(ctx, req.Id); err != nil {
		return nil, err
	}
	return &v1.RoleDeleteRes{Success: true}, nil
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*v1.RoleGrantableRes, error) {
	grantable, err := permission.GrantableSet(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.RoleGrantableRes{
		Unlimited:       grantable.Unlimited,
		MenuConfigCodes: append([]string{}, grantable.MenuConfigCodes...),
		MenuAppCodes:    append([]string{}, grantable.MenuAppCodes...),
		AreaIds:         append([]int{}, grantable.AreaIds...),
		OrgIds:          append([]int{}, grantable.OrgIds...),
		ResAreaIds:      append([]int{}, grantable.ResAreaIds...),
		AreaScopes:      dataScopeResList(grantable.AreaScopes),
		OrgScopes:       dataScopeResList(grantable.OrgScopes),
		ResAreaScopes:   dataScopeResList(grantable.ResAreaScopes),
	}, nil
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) (*v1.RoleAreaChildrenRes, error) {
	nodes, err := permission.RoleAreaChildren(ctx, req.ParentId, req.Kind, req.RoleId)
	if err != nil {
		return nil, err
	}
	res := &v1.RoleAreaChildrenRes{Items: make([]v1.RoleTreeNode, 0, len(nodes))}
	for _, node := range nodes {
		res.Items = append(res.Items, v1.RoleTreeNode{
			Id: node.Id, ParentId: node.ParentId, Name: node.Name,
			HasChildren: node.HasChildren, CanCheck: node.CanCheck,
		})
	}
	return res, nil
}

func roleDetailRes(role *model.Role) *v1.RoleDetailRes {
	if role == nil {
		return nil
	}
	return &v1.RoleDetailRes{
		Id: role.Id, Name: role.Name, Description: role.Description, CreatedBy: role.CreatedBy,
		MenuConfigCodes:    append([]string{}, role.MenuConfigCodes...),
		MenuAppCodes:       append([]string{}, role.MenuAppCodes...),
		AreaScopes:         dataScopeResList(role.AreaScopes),
		OrgScopes:          dataScopeResList(role.OrgScopes),
		ResourceAreaScopes: dataScopeResList(role.ResourceAreaScopes),
	}
}

func dataScopeResList(scopes []model.DataScope) []v1.DataScope {
	out := make([]v1.DataScope, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, v1.DataScope{NodeId: scope.NodeId, IncludeChild: scope.IncludeChild})
	}
	return out
}

func dataScopeInputList(scopes []v1.DataScope) []model.DataScope {
	out := make([]model.DataScope, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, model.DataScope{NodeId: scope.NodeId, IncludeChild: scope.IncludeChild})
	}
	return out
}

func dataScopeChangesInput(changes v1.DataScopeChanges) model.DataScopeChanges {
	return model.DataScopeChanges{
		Adds: dataScopeInputList(changes.Adds),
		Dels: dataScopeInputList(changes.Dels),
	}
}

func menuReplacementInput(replacement *v1.MenuReplacement) *model.MenuReplacement {
	if replacement == nil {
		return nil
	}
	var codes []string
	if replacement.Replace != nil {
		codes = append([]string{}, replacement.Replace...)
	}
	return &model.MenuReplacement{Replace: codes}
}

func rolePermissionChangesInput(changes *v1.RolePermissionChanges) *model.RolePermissionChanges {
	if changes == nil {
		return nil
	}
	return &model.RolePermissionChanges{
		MenuConfig:   menuReplacementInput(changes.MenuConfig),
		MenuApp:      menuReplacementInput(changes.MenuApp),
		Area:         dataScopeChangesInput(changes.Area),
		Org:          dataScopeChangesInput(changes.Org),
		ResourceArea: dataScopeChangesInput(changes.ResourceArea),
	}
}
