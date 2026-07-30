package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
)

func (c *ControllerV1) AppMenu(ctx context.Context, req *v1.AppMenuReq) (*v1.AppMenuRes, error) {
	menus, err := permission.AppMenus(ctx)
	if err != nil {
		return nil, err
	}
	res := &v1.AppMenuRes{Items: make([]v1.MenuItem, 0, len(menus))}
	for _, menu := range menus {
		if menu != nil {
			res.Items = append(res.Items, v1.MenuItem{
				Code: menu.Code, ParentCode: menu.ParentCode, Name: menu.Name, Domain: menu.Domain,
			})
		}
	}
	return res, nil
}

func (c *ControllerV1) ManageMenu(ctx context.Context, req *v1.ManageMenuReq) (*v1.ManageMenuRes, error) {
	menus, err := permission.SysMenus(ctx)
	if err != nil {
		return nil, err
	}
	res := &v1.ManageMenuRes{Items: make([]v1.MenuItem, 0, len(menus))}
	for _, menu := range menus {
		if menu != nil {
			res.Items = append(res.Items, v1.MenuItem{
				Code: menu.Code, ParentCode: menu.ParentCode, Name: menu.Name, Domain: menu.Domain,
			})
		}
	}
	return res, nil
}
