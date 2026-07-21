package permission

import (
	"context"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/entity"
)

func UserByID(ctx context.Context, id string) (*model.User, error) {
	return cachedUser(ctx, id)
}

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
		out = append(out, &model.Org{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path})
	}
	return out, nil
}

func (e *evaluator) visibleMenusWithAncestors(user *model.User, domain string) []*model.Menu {
	menus := e.menus()
	byID := make(map[int]*model.Menu, len(menus))
	visible := make(map[int]bool, len(menus))
	for _, menu := range menus {
		byID[menu.Id] = menu
	}
	var mark func(*model.Menu)
	mark = func(menu *model.Menu) {
		if menu == nil || visible[menu.Id] || (domain != "" && menu.Domain != domain) {
			return
		}
		visible[menu.Id] = true
		mark(byID[menu.ParentId])
	}
	for _, menu := range menus {
		if (domain == "" || menu.Domain == domain) && e.userHasMenuID(user, menu.Id) {
			mark(menu)
		}
	}
	out := make([]*model.Menu, 0, len(visible))
	for _, menu := range menus {
		if visible[menu.Id] {
			out = append(out, menu)
		}
	}
	return out
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
	menus, err := cachedMenus(ctx)
	if err != nil {
		return nil, err
	}
	users, err := allUsers(ctx)
	if err != nil {
		return nil, err
	}
	return &model.MetaData{
		Areas: areas, Orgs: orgs, Menus: menus, Users: users,
	}, nil
}

// Meta 返回前端初始化角色和用户管理所需的小型字典，不包含资源等大表。
func Meta(ctx context.Context) (*model.MetaData, error) {
	return fullMeta(ctx)
}

func ManageOrgs(ctx context.Context, userID string) ([]model.VisibleArea, error) {
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return []model.VisibleArea{}, ev.err
	}
	if err := ev.requireAnyMenu(user, manageOrgReadMenus...); err != nil {
		return []model.VisibleArea{}, err
	}
	filter := ev.treeScopeFilter(user, treeKindOrg)
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
	return out, ev.err
}

func ManageAreaDetail(ctx context.Context, userID string, areaID int) (*model.ManageDetail, error) {
	out := &model.ManageDetail{Children: []string{}, ResourceItems: []model.ResourceBrief{}}
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	if err := ev.requireAnyMenu(user, manageAreaReadMenus...); err != nil {
		return out, err
	}
	area := ev.area(areaID)
	if ev.err != nil {
		return out, ev.err
	}
	if area == nil {
		return out, nil
	}
	out.Name, out.ParentId = area.Name, area.ParentId
	if !ev.checkTree(user, areaID, treeKindArea).Allow {
		return out, ev.err
	}
	out.Accessible = true
	var err error
	out.ChildCount, err = dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, areaID).Count()
	if err != nil {
		return nil, err
	}
	var resources []model.ResourceBrief
	if err = dao.Resource.Ctx(ctx).Fields("id,name,type,area_id").
		Where(dao.Resource.Columns().AreaId, areaID).Order(dao.Resource.Columns().Id).
		Limit(manageDetailResourceLimit).Scan(&resources); err != nil {
		return nil, err
	}
	for _, resource := range resources {
		out.ResourceItems = append(out.ResourceItems, resource)
	}
	return out, ev.err
}

func ManageOrgDetail(ctx context.Context, userID string, orgID int) (*model.ManageDetail, error) {
	out := &model.ManageDetail{Children: []string{}, ResourceItems: []model.ResourceBrief{}}
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	if err := ev.requireAnyMenu(user, manageOrgReadMenus...); err != nil {
		return out, err
	}
	org := ev.org(orgID)
	if ev.err != nil {
		return out, ev.err
	}
	if org == nil {
		return out, nil
	}
	out.Name, out.ParentId = org.Name, org.ParentId
	if !ev.checkTree(user, orgID, treeKindOrg).Allow {
		return out, ev.err
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
	return out, ev.err
}

func SysMenus(ctx context.Context, userID string) ([]*model.Menu, error) {
	return visibleMenus(ctx, userID, model.MenuDomainSys)
}

func AppMenus(ctx context.Context, userID string) ([]*model.Menu, error) {
	return visibleMenus(ctx, userID, model.MenuDomainApp)
}

func visibleMenus(ctx context.Context, userID, domain string) ([]*model.Menu, error) {
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil || user == nil {
		return []*model.Menu{}, ev.err
	}
	out := ev.visibleMenusWithAncestors(user, domain)
	return out, ev.err
}
