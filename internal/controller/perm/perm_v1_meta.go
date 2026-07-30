package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
)

func (c *ControllerV1) Meta(ctx context.Context, req *v1.MetaReq) (*v1.MetaRes, error) {
	meta, err := permission.Meta(ctx)
	if err != nil {
		return nil, err
	}
	res := &v1.MetaRes{
		Areas: make([]v1.AreaItem, 0, len(meta.Areas)),
		Orgs:  make([]v1.OrgItem, 0, len(meta.Orgs)),
		Menus: make([]v1.MenuItem, 0, len(meta.Menus)),
		Users: make([]v1.UserItem, 0, len(meta.Users)),
	}
	for _, area := range meta.Areas {
		if area != nil {
			res.Areas = append(res.Areas, v1.AreaItem{
				Id: area.Id, ParentId: area.ParentId, Name: area.Name, Path: area.Path, Sort: area.Sort,
			})
		}
	}
	for _, org := range meta.Orgs {
		if org != nil {
			res.Orgs = append(res.Orgs, v1.OrgItem{
				Id: org.Id, ParentId: org.ParentId, Name: org.Name, Path: org.Path,
			})
		}
	}
	for _, menu := range meta.Menus {
		if menu != nil {
			res.Menus = append(res.Menus, v1.MenuItem{
				Code: menu.Code, ParentCode: menu.ParentCode, Name: menu.Name, Domain: menu.Domain,
			})
		}
	}
	for _, user := range meta.Users {
		if user != nil {
			res.Users = append(res.Users, userItemRes(user))
		}
	}
	return res, nil
}
