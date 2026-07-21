package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) ([]*model.Menu, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.AppMenus(ctx, userID)
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) ([]*model.Menu, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SysMenus(ctx, userID)
}
