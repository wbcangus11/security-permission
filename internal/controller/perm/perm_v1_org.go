package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) ManageOrgTree(ctx context.Context, req *v1.ManageOrgTreeReq) (*v1.ManageOrgTreeRes, error) {
	orgs, err := permission.ManageOrgs(ctx)
	if err != nil {
		return nil, err
	}
	res := &v1.ManageOrgTreeRes{Items: make([]v1.VisibleOrgItem, 0, len(orgs))}
	for _, org := range orgs {
		res.Items = append(res.Items, v1.VisibleOrgItem{
			Id: org.Id, ParentId: org.ParentId, Name: org.Name, Accessible: org.Accessible,
		})
	}
	return res, nil
}

func (c *ControllerV1) ManageOrgDetail(ctx context.Context, req *v1.ManageOrgDetailReq) (*v1.ManageOrgDetailRes, error) {
	detail, err := permission.ManageOrgDetail(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	resources := make([]v1.ResourceBrief, 0, len(detail.ResourceItems))
	for _, resource := range detail.ResourceItems {
		resources = append(resources, v1.ResourceBrief{
			Id: resource.Id, Name: resource.Name, Type: resource.Type, AreaId: resource.AreaId,
		})
	}
	return &v1.ManageOrgDetailRes{
		Accessible: detail.Accessible, Name: detail.Name, ParentId: detail.ParentId,
		ChildCount: detail.ChildCount, Children: append([]string{}, detail.Children...),
		ResourceItems: resources,
	}, nil
}

func (c *ControllerV1) ManageOrgSave(ctx context.Context, req *v1.ManageOrgSaveReq) (*v1.ManageOrgSaveRes, error) {
	org, err := permission.SaveOrg(ctx, &model.OrgSaveInput{
		Id: req.Id, ParentId: req.ParentId, Name: req.Name,
	})
	if err != nil {
		return nil, err
	}
	return &v1.ManageOrgSaveRes{
		Id: org.Id, ParentId: org.ParentId, Name: org.Name, Path: org.Path,
	}, nil
}

func (c *ControllerV1) ManageOrgDelete(ctx context.Context, req *v1.ManageOrgDeleteReq) (*v1.ManageOrgDeleteRes, error) {
	if err := permission.DeleteOrg(ctx, req.Id); err != nil {
		return nil, err
	}
	return &v1.ManageOrgDeleteRes{Success: true}, nil
}
