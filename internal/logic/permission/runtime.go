package permission

import (
	"context"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/entity"
)

func allUsers(ctx context.Context) ([]*model.User, error) {
	var rows []struct{ Id string }
	if err := dao.User.Ctx(ctx).Fields(dao.User.Columns().Id).
		Order(dao.User.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.Id)
	}
	return listUsersByIDs(ctx, ids)
}

func visibleOrgs(ctx context.Context, filter treeFilter) ([]*model.Org, error) {
	where, args, visible := visibilityWhere(filter, treeNavAncestors(filter))
	if !visible {
		return []*model.Org{}, nil
	}
	query := dao.Org.Ctx(ctx).Order(dao.Org.Columns().Id)
	if where != "" {
		query = query.Where(where, args...)
	}
	var rows []entity.Org
	if err := query.Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Org, 0, len(rows))
	for _, row := range rows {
		out = append(out, &model.Org{
			Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path,
		})
	}
	return out, nil
}

// visibleMenusWithAncestors 先标出用户真正拥有的菜单，再把父菜单补齐。
// 这样前端能直接渲染完整导航树，不用自己猜哪些父节点该显示。
func visibleMenusWithAncestors(snapshot *permissionSnapshot, domain string) ([]*model.Menu, error) {
	menus, err := catalogMenus()
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]*model.Menu, len(menus))
	visible := make(map[string]bool, len(menus))
	for _, menu := range menus {
		byCode[menu.Code] = menu
	}
	var mark func(*model.Menu)
	mark = func(menu *model.Menu) {
		if menu == nil || visible[menu.Code] || (domain != "" && menu.Domain != domain) {
			return
		}
		visible[menu.Code] = true
		mark(byCode[menu.ParentCode])
	}
	for _, menu := range menus {
		if (domain == "" || menu.Domain == domain) && snapshot.hasMenu(menu.Code) {
			mark(menu)
		}
	}
	out := make([]*model.Menu, 0, len(visible))
	for _, menu := range menus {
		if visible[menu.Code] {
			out = append(out, menu)
		}
	}
	return out, nil
}

func fullMeta(ctx context.Context) (*model.MetaData, error) {
	areas, err := listAllAreas(ctx)
	if err != nil {
		return nil, err
	}
	orgs, err := listAllOrgs(ctx)
	if err != nil {
		return nil, err
	}
	menus, err := catalogMenus()
	if err != nil {
		return nil, err
	}
	users, err := allUsers(ctx)
	if err != nil {
		return nil, err
	}
	return &model.MetaData{Areas: areas, Orgs: orgs, Menus: menus, Users: users}, nil
}

// Meta 返回角色和用户管理需要的小字典，不把资源大表一起塞进来。
func Meta(ctx context.Context) (*model.MetaData, error) {
	return fullMeta(ctx)
}

func ManageOrgs(ctx context.Context) ([]model.VisibleArea, error) {
	snapshot, err := loadAuthorizedSnapshot(ctx, manageOrgReadMenus...)
	if err != nil {
		return []model.VisibleArea{}, err
	}
	filter := snapshot.treeFilter(treeKindOrg)
	orgs, err := visibleOrgs(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]model.VisibleArea, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, model.VisibleArea{
			Id: org.Id, ParentId: org.ParentId, Name: org.Name,
			Accessible: filter.covers(org.Path, org.Id),
		})
	}
	return out, nil
}

func ManageAreaDetail(ctx context.Context, areaID int) (*model.ManageDetail, error) {
	out := &model.ManageDetail{Children: []string{}, ResourceItems: []model.ResourceBrief{}}
	snapshot, err := loadAuthorizedSnapshot(ctx, manageAreaReadMenus...)
	if err != nil {
		return out, err
	}
	area, err := findArea(ctx, areaID)
	if err != nil {
		return nil, err
	}
	if area == nil {
		return out, nil
	}
	out.Name, out.ParentId = area.Name, area.ParentId
	if !snapshot.covers(treeKindArea, area.Path, area.Id) {
		return out, nil
	}
	out.Accessible = true
	out.ChildCount, err = dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, areaID).Count()
	if err != nil {
		return nil, err
	}
	if err := dao.Resource.Ctx(ctx).Fields("id,name,type,area_id").
		Where(dao.Resource.Columns().AreaId, areaID).Order(dao.Resource.Columns().Id).
		Limit(manageDetailResourceLimit).Scan(&out.ResourceItems); err != nil {
		return nil, err
	}
	return out, nil
}

func ManageOrgDetail(ctx context.Context, orgID int) (*model.ManageDetail, error) {
	out := &model.ManageDetail{Children: []string{}, ResourceItems: []model.ResourceBrief{}}
	snapshot, err := loadAuthorizedSnapshot(ctx, manageOrgReadMenus...)
	if err != nil {
		return out, err
	}
	org, err := findOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return out, nil
	}
	out.Name, out.ParentId = org.Name, org.ParentId
	if !snapshot.covers(treeKindOrg, org.Path, org.Id) {
		return out, nil
	}
	out.Accessible = true

	var rows []struct{ Name string }
	if err := dao.Org.Ctx(ctx).Fields(dao.Org.Columns().Name).
		Where(dao.Org.Columns().ParentId, orgID).Order(dao.Org.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	out.ChildCount = len(rows)
	for _, row := range rows {
		out.Children = append(out.Children, row.Name)
	}
	return out, nil
}

func SysMenus(ctx context.Context) ([]*model.Menu, error) {
	return visibleMenus(ctx, model.MenuDomainSys)
}

func AppMenus(ctx context.Context) ([]*model.Menu, error) {
	return visibleMenus(ctx, model.MenuDomainApp)
}

func visibleMenus(ctx context.Context, domain string) ([]*model.Menu, error) {
	snapshot, err := loadPermissionSnapshot(ctx)
	if err != nil {
		return []*model.Menu{}, err
	}
	return visibleMenusWithAncestors(snapshot, domain)
}
