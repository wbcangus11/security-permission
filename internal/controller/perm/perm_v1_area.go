package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) AppAreaChildren(ctx context.Context, req *v1.AppAreaChildrenReq) (*v1.AppAreaChildrenRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	page, err := permission.AreaChildren(ctx, userID, req.ParentId, req.Page, req.Size)
	if err != nil {
		return nil, err
	}
	return &v1.AppAreaChildrenRes{
		Items: areaNodeResList(page.Items), Total: page.Total, Page: page.Page, Size: page.Size,
	}, nil
}

func (c *ControllerV1) AppAreaSearch(ctx context.Context, req *v1.AppAreaSearchReq) (*v1.AppAreaSearchRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	page, err := permission.SearchAppAreas(ctx, userID, req.Q)
	if err != nil {
		return nil, err
	}
	return &v1.AppAreaSearchRes{
		Items: areaNodeResList(page.Items), Total: page.Total, Page: page.Page, Size: page.Size,
	}, nil
}

func (c *ControllerV1) ManageAreaSearch(ctx context.Context, req *v1.ManageAreaSearchReq) (*v1.ManageAreaSearchRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	page, err := permission.SearchManageAreas(ctx, userID, req.Q)
	if err != nil {
		return nil, err
	}
	return &v1.ManageAreaSearchRes{
		Items: areaNodeResList(page.Items), Total: page.Total, Page: page.Page, Size: page.Size,
	}, nil
}

func (c *ControllerV1) ManageAreaChildren(ctx context.Context, req *v1.ManageAreaChildrenReq) (*v1.ManageAreaChildrenRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	page, err := permission.ManageAreaChildren(ctx, userID, req.ParentId, req.Page, req.Size)
	if err != nil {
		return nil, err
	}
	return &v1.ManageAreaChildrenRes{
		Items: areaNodeResList(page.Items), Total: page.Total, Page: page.Page, Size: page.Size,
	}, nil
}

func (c *ControllerV1) ManageAreaDetail(ctx context.Context, req *v1.ManageAreaDetailReq) (*v1.ManageAreaDetailRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	detail, err := permission.ManageAreaDetail(ctx, userID, req.AreaId)
	if err != nil {
		return nil, err
	}
	resources := make([]v1.ResourceBrief, 0, len(detail.ResourceItems))
	for _, resource := range detail.ResourceItems {
		resources = append(resources, v1.ResourceBrief{
			Id: resource.Id, Name: resource.Name, Type: resource.Type, AreaId: resource.AreaId,
		})
	}
	return &v1.ManageAreaDetailRes{
		Accessible: detail.Accessible, Name: detail.Name, ParentId: detail.ParentId,
		ChildCount: detail.ChildCount, Children: append([]string{}, detail.Children...),
		ResourceItems: resources,
	}, nil
}

func (c *ControllerV1) ManageAreaSave(ctx context.Context, req *v1.ManageAreaSaveReq) (*v1.ManageAreaSaveRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	area, err := permission.SaveArea(ctx, userID, &model.AreaSaveInput{
		Id: req.Id, ParentId: req.ParentId, Name: req.Name,
	})
	if err != nil {
		return nil, err
	}
	return &v1.ManageAreaSaveRes{
		Id: area.Id, ParentId: area.ParentId, Name: area.Name, Path: area.Path, Sort: area.Sort,
	}, nil
}

func (c *ControllerV1) ManageAreaReorder(ctx context.Context, req *v1.ManageAreaReorderReq) (*v1.ManageAreaReorderRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	if err = permission.ReorderArea(ctx, userID, &model.AreaReorderInput{
		AreaId: req.AreaId, ToAreaId: req.ToAreaId,
	}); err != nil {
		return nil, err
	}
	return &v1.ManageAreaReorderRes{Success: true}, nil
}

func (c *ControllerV1) ManageAreaDelete(ctx context.Context, req *v1.ManageAreaDeleteReq) (*v1.ManageAreaDeleteRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	if err = permission.DeleteArea(ctx, userID, req.Id); err != nil {
		return nil, err
	}
	return &v1.ManageAreaDeleteRes{Success: true}, nil
}

func areaNodeResList(nodes []model.AreaNode) []v1.AreaNode {
	out := make([]v1.AreaNode, 0, len(nodes))
	for _, node := range nodes {
		ancestors := make([]v1.AncestorRef, 0, len(node.Ancestors))
		for _, ancestor := range node.Ancestors {
			ancestors = append(ancestors, v1.AncestorRef{Id: ancestor.Id, Name: ancestor.Name})
		}
		out = append(out, v1.AreaNode{
			Id: node.Id, ParentId: node.ParentId, Name: node.Name,
			Accessible: node.Accessible, HasChildren: node.HasChildren, Ancestors: ancestors,
		})
	}
	return out
}
