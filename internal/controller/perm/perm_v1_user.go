package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) ([]*model.User, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ListUsers(ctx, userID)
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*model.User, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.GetUser(ctx, userID, req.Id)
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*model.User, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SaveUser(ctx, userID, userFromReq(req))
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.DeleteUser(ctx, userID, req.Id)
	return err == nil, err
}
