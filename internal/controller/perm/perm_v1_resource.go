package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) AppResourceList(ctx context.Context, req *v1.AppResourceListReq) (*v1.AppResourceListRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	page, err := permission.AreaResourcesPaged(ctx, userID, req.AreaId, req.Page, req.Size)
	if err != nil {
		return nil, err
	}
	resources := make([]v1.ResourceViewItem, 0, len(page.Resources))
	for _, resource := range page.Resources {
		actions := make([]v1.ActionAllowItem, 0, len(resource.Actions))
		for _, action := range resource.Actions {
			actions = append(actions, v1.ActionAllowItem{
				Code: action.Code, Name: action.Name, Allowed: action.Allowed,
			})
		}
		resources = append(resources, v1.ResourceViewItem{
			Id: resource.Id, Name: resource.Name, Area: resource.Area, Actions: actions,
		})
	}
	return &v1.AppResourceListRes{
		Accessible: page.Accessible, AreaName: page.AreaName, Resources: resources,
		Total: page.Total, Page: page.Page, Size: page.Size,
	}, nil
}

func (c *ControllerV1) ManageResourceSave(ctx context.Context, req *v1.ManageResourceSaveReq) (*v1.ManageResourceSaveRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := permission.SaveResource(ctx, userID, &model.ResourceSaveInput{
		Id: req.Id, AreaId: req.AreaId, Name: req.Name, Type: req.Type,
	})
	if err != nil {
		return nil, err
	}
	return &v1.ManageResourceSaveRes{
		Id: resource.Id, AreaId: resource.AreaId, Name: resource.Name, Type: resource.Type,
	}, nil
}

func (c *ControllerV1) ManageResourceDelete(ctx context.Context, req *v1.ManageResourceDeleteReq) (*v1.ManageResourceDeleteRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	if err = permission.DeleteResource(ctx, userID, req.Id); err != nil {
		return nil, err
	}
	return &v1.ManageResourceDeleteRes{Success: true}, nil
}
