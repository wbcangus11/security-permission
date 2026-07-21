package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*model.PagedAreas, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.AreaChildren(ctx, userID, req.ParentId, req.Page, req.Size)
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*model.PagedAreas, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SearchAppAreas(ctx, userID, req.Q)
}

func (c *ControllerV1) ManageAreaSearch(ctx context.Context, req *v1.ManageAreaSearchReq) (*model.PagedAreas, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SearchManageAreas(ctx, userID, req.Q)
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*model.PagedAreas, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ManageAreaChildren(ctx, userID, req.ParentId, req.Page, req.Size)
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*model.ManageDetail, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ManageAreaDetail(ctx, userID, req.AreaId)
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*model.Area, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SaveArea(ctx, userID, &model.AreaSaveInput{Id: req.Id, ParentId: req.ParentId, Name: req.Name})
}

func (c *ControllerV1) ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.ReorderArea(ctx, userID, &model.AreaReorderInput{AreaId: req.AreaId, ToAreaId: req.ToAreaId})
	return err == nil, err
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.DeleteArea(ctx, userID, req.Id)
	return err == nil, err
}
