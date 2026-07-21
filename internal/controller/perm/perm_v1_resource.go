package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*model.AreaResourcesPage, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.AreaResourcesPaged(ctx, userID, req.AreaId, req.Page, req.Size)
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*model.Resource, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SaveResource(ctx, userID, &model.ResourceSaveInput{
		Id: req.Id, AreaId: req.AreaId, Name: req.Name, Type: req.Type,
	})
}

func (c *ControllerV1) ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.DeleteResource(ctx, userID, req.Id)
	return err == nil, err
}
