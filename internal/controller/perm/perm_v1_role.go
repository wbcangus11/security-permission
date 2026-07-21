package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) RoleList(ctx context.Context, req *v1.RoleListReq) ([]*model.Role, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ListRoles(ctx, userID)
}

func (c *ControllerV1) RoleDetail(ctx context.Context, req *v1.RoleDetailReq) (*model.Role, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.GetRole(ctx, userID, req.Id)
}

func (c *ControllerV1) RoleSave(ctx context.Context, req *v1.RoleSaveReq) (*model.RoleSaveResult, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	role, preserved, err := permission.SaveRole(ctx, userID, roleFromReq(req))
	if err != nil {
		return nil, err
	}
	return &model.RoleSaveResult{Role: role, Preserved: preserved}, nil
}

func (c *ControllerV1) RoleDelete(ctx context.Context, req *v1.RoleDeleteReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.DeleteRole(ctx, userID, req.Id)
	return err == nil, err
}

func (c *ControllerV1) RoleGrantable(ctx context.Context, req *v1.RoleGrantableReq) (*model.Grantable, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.GrantableSet(ctx, userID)
}

func (c *ControllerV1) RoleAreaChildren(ctx context.Context, req *v1.RoleAreaChildrenReq) ([]model.RoleTreeNode, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.RoleAreaChildren(ctx, userID, req.ParentId, req.Kind)
}
