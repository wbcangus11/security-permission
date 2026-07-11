package permission

import (
	"context"
	"strconv"
	"strings"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// Meta returns the frontend bootstrap dictionary. Demo mode intentionally keeps
// the full dataset for the permission simulator. Production mode returns only
// data reachable by the authenticated actor.
func (s *RuntimeService) Meta(actorID string, demoMode bool) *model.MetaData {
	if demoMode {
		return &model.MetaData{
			Areas: s.Areas(), Orgs: s.Orgs(), Menus: s.Menus(), Resources: s.Resources(),
			Actions: s.Actions(), Users: s.Users(),
		}
	}
	out := &model.MetaData{
		Areas: []*model.Area{}, Orgs: []*model.Org{}, Menus: []*model.Menu{},
		Resources: []*model.Resource{}, Actions: s.Actions(), Users: []*model.User{},
	}
	actor := s.User(actorID)
	if actor == nil {
		return out
	}
	if actor.IsSuperuser {
		out.Areas, out.Orgs, out.Menus = s.Areas(), s.Orgs(), s.Menus()
		out.Resources, out.Users = s.Resources(), s.Users()
		return out
	}

	grant := s.GrantableSet(actorID)
	menuByID := make(map[int]*model.Menu)
	menuVisible := make(map[int]bool)
	for _, menu := range s.Menus() {
		menuByID[menu.Id] = menu
	}
	var markMenu func(int)
	markMenu = func(id int) {
		if id == 0 || menuVisible[id] {
			return
		}
		menu := menuByID[id]
		if menu == nil {
			return
		}
		menuVisible[id] = true
		markMenu(menu.ParentId)
	}
	for _, id := range grant.MenuIds {
		markMenu(id)
	}
	for _, menu := range s.Menus() {
		if menuVisible[menu.Id] {
			out.Menus = append(out.Menus, menu)
		}
	}

	areaVisible := make(map[int]bool)
	for _, id := range append(append([]int{}, grant.AreaIds...), grant.ResAreaIds...) {
		if area := s.AreaById(id); area != nil {
			markPathIDs(areaVisible, area.Path)
		}
	}
	for _, area := range s.Areas() {
		if areaVisible[area.Id] {
			out.Areas = append(out.Areas, area)
		}
	}

	orgVisible := make(map[int]bool)
	for _, id := range grant.OrgIds {
		if org := s.OrgById(id); org != nil {
			markPathIDs(orgVisible, org.Path)
		}
	}
	for _, org := range s.Orgs() {
		if orgVisible[org.Id] {
			out.Orgs = append(out.Orgs, org)
		}
	}
	for _, resource := range s.Resources() {
		if s.userResAreaCovers(actor, resource.AreaId) {
			out.Resources = append(out.Resources, resource)
		}
	}

	canManageUsers := s.CheckMenu(actor, menuAccountManage).Allow
	for _, user := range s.Users() {
		if user.Id == actorID || (canManageUsers && !user.IsSuperuser && s.CheckOrg(actor, user.OrgId).Allow) {
			out.Users = append(out.Users, user)
		}
	}
	return out
}

func markPathIDs(set map[int]bool, path string) {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if id, err := strconv.Atoi(segment); err == nil {
			set[id] = true
		}
	}
}

type visibilityNode struct {
	Id       int
	ParentId int
	Name     string
	Path     string
}

// buildVisibleTree marks ancestors by materialized path. This is O(n*depth)
// instead of comparing every node with every accessible node.
func buildVisibleTree(nodes []visibilityNode, accessible map[int]bool) []model.VisibleArea {
	visible := make(map[int]bool, len(accessible))
	for _, node := range nodes {
		if !accessible[node.Id] {
			continue
		}
		for _, segment := range strings.Split(strings.Trim(node.Path, "/"), "/") {
			if id, err := strconv.Atoi(segment); err == nil {
				visible[id] = true
			}
		}
	}
	out := make([]model.VisibleArea, 0, len(visible))
	for _, node := range nodes {
		if visible[node.Id] {
			out = append(out, model.VisibleArea{Id: node.Id, ParentId: node.ParentId, Name: node.Name, Accessible: accessible[node.Id]})
		}
	}
	return out
}

// ManageOrgs 后台管理域可见组织树(accessible=组织管理权限 ORG 覆盖)。
func (s *ViewService) ManageOrgs(userId string) []model.VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []model.VisibleArea{}
	}
	orgs := s.Orgs()
	acc := make(map[int]bool)
	nodes := make([]visibilityNode, 0, len(orgs))
	for _, o := range orgs {
		nodes = append(nodes, visibilityNode{Id: o.Id, ParentId: o.ParentId, Name: o.Name, Path: o.Path})
		if s.CheckOrg(u, o.Id).Allow {
			acc[o.Id] = true
		}
	}
	return buildVisibleTree(nodes, acc)
}

// ManageAreaDetail 点击安保区域:可管理则给出子区域数量 + 本区域直接资源;否则暂无管理权限。
// 子区域由左侧树懒加载展开,不在详情里平铺;子区域数量与资源都走 DB 索引查询,避免全表扫描(支撑大数据量)。
func (s *ViewService) ManageAreaDetail(ctx context.Context, userId string, areaId int) (*model.ManageDetail, error) {
	u := s.User(userId)
	d := &model.ManageDetail{Children: []string{}, Resources: []string{}, ResourceItems: []model.ResourceBrief{}}
	if u == nil {
		return d, nil
	}
	area := s.AreaById(areaId)
	if area == nil {
		return d, nil
	}
	d.Name = area.Name
	d.ParentId = area.ParentId
	if !s.CheckArea(u, areaId).Allow {
		return d, nil // accessible=false
	}
	d.Accessible = true
	// 子区域数量:cheap COUNT 走 idx_parent(不平铺,左树懒加载展开)
	var err error
	d.ChildCount, err = dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, areaId).Count()
	if err != nil {
		return nil, err
	}
	// 本区域直接挂的资源:走 idx_area;直接资源通常很少,封顶 500 防御
	var rs []model.ResourceBrief
	if err = dao.Resource.Ctx(ctx).
		Fields("id,name,type,area_id").
		Where(dao.Resource.Columns().AreaId, areaId).
		Order(dao.Resource.Columns().Id + " asc").
		Limit(manageDetailResourceLimit).
		Scan(&rs); err != nil {
		return nil, err
	}
	for _, r := range rs {
		d.Resources = append(d.Resources, r.Name)
		d.ResourceItems = append(d.ResourceItems, r)
	}
	return d, nil
}

// ManageOrgDetail 点击组织:可管理则列出直接子组织;否则暂无管理权限。
func (s *ViewService) ManageOrgDetail(userId string, orgId int) *model.ManageDetail {
	u := s.User(userId)
	d := &model.ManageDetail{Children: []string{}, Resources: []string{}}
	if u == nil {
		return d
	}
	for _, o := range s.Orgs() {
		if o.Id == orgId {
			d.Name = o.Name
		}
	}
	if !s.CheckOrg(u, orgId).Allow {
		return d
	}
	d.Accessible = true
	for _, o := range s.Orgs() {
		if o.ParentId == orgId {
			d.Children = append(d.Children, o.Name)
		}
	}
	return d
}

// SysMenus 某用户可见的系统管理菜单(功能权限 SYS)。
func (s *ViewService) SysMenus(userId string) []*model.Menu {
	u := s.User(userId)
	if u == nil {
		return []*model.Menu{}
	}
	return s.visibleMenusWithAncestors(u, model.MenuDomainSys)
}

// AppMenus 返回某用户在应用域可见的菜单(功能权限),用于应用端顶部菜单。
func (s *ViewService) AppMenus(userId string) []*model.Menu {
	u := s.User(userId)
	if u == nil {
		return []*model.Menu{}
	}
	return s.visibleMenusWithAncestors(u, model.MenuDomainApp)
}

func (s *ViewService) visibleMenusWithAncestors(u *model.User, domain string) []*model.Menu {
	menus := s.Menus()
	byId := make(map[int]*model.Menu, len(menus))
	visible := make(map[int]bool, len(menus))
	for _, m := range menus {
		byId[m.Id] = m
	}
	// 用户只拿到子菜单权限时,父菜单也要返回给前端当分组节点,否则左侧树会缺层级。
	var mark func(*model.Menu)
	mark = func(m *model.Menu) {
		if m == nil || m.Domain != domain || visible[m.Id] {
			return
		}
		visible[m.Id] = true
		if m.ParentId > 0 {
			mark(byId[m.ParentId])
		}
	}
	for _, m := range menus {
		if m.Domain == domain && s.userHasMenuId(u, m.Id) {
			mark(m)
		}
	}
	out := make([]*model.Menu, 0, len(visible))
	for _, m := range menus {
		if m.Domain == domain && visible[m.Id] {
			out = append(out, m)
		}
	}
	return out
}
