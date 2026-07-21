package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) ([]model.VisibleArea, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ManageOrgs(ctx, userID)
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*model.ManageDetail, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.ManageOrgDetail(ctx, userID, req.OrgId)
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*model.Org, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	return permission.SaveOrg(ctx, userID, &model.OrgSaveInput{Id: req.Id, ParentId: req.ParentId, Name: req.Name})
}

func (c *ControllerV1) ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (bool, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return false, err
	}
	err = permission.DeleteOrg(ctx, userID, req.Id)
	return err == nil, err
}
