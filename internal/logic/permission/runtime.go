package permission

import (
	"context"
	"strconv"
	"strings"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// 应用端(使用界面)运行时数据。基于应用域(RES_AREA 资源范围 + 资源操作)。
//
// 关键区分:
//   - accessible(可访问):用户的资源范围覆盖该区域,点击能看资源。
//   - visible(可见):自己可访问,或它有可访问的后代 —— 后者是"仅导航的祖先",
//     点击会提示「暂无操作权限」(其本身资源不授权)。

// VisibleArea 可见区域树节点。
type VisibleArea = model.VisibleArea

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
func buildVisibleTree(nodes []visibilityNode, accessible map[int]bool) []VisibleArea {
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
	out := make([]VisibleArea, 0, len(visible))
	for _, node := range nodes {
		if visible[node.Id] {
			out = append(out, VisibleArea{Id: node.Id, ParentId: node.ParentId, Name: node.Name, Accessible: accessible[node.Id]})
		}
	}
	return out
}

// visibleAreaTree 通用:按 accessible 判定函数算出可见区域树(可见=自己可访问或有可访问后代)。
func (s *ViewService) visibleAreaTree(accessible func(areaId int) bool) []VisibleArea {
	areas := s.Areas()
	acc := make(map[int]bool)
	nodes := make([]visibilityNode, 0, len(areas))
	for _, a := range areas {
		nodes = append(nodes, visibilityNode{Id: a.Id, ParentId: a.ParentId, Name: a.Name, Path: a.Path})
		if accessible(a.Id) {
			acc[a.Id] = true
		}
	}
	return buildVisibleTree(nodes, acc)
}

// VisibleAreas 应用端可见区域树(accessible=资源域 RES_AREA 覆盖)。
func (s *ViewService) VisibleAreas(userId string) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	return s.visibleAreaTree(func(id int) bool { return s.userResAreaCovers(u, id) })
}

// ManageAreas 后台管理域可见区域树(accessible=安保区域管理权限 AREA 覆盖)。
func (s *ViewService) ManageAreas(userId string) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	return s.visibleAreaTree(func(id int) bool { return s.CheckArea(u, id).Allow })
}

// ManageOrgs 后台管理域可见组织树(accessible=组织管理权限 ORG 覆盖)。
func (s *ViewService) ManageOrgs(userId string) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
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

// ResourceBrief 资源管理用的精简条目(带 id/type,供后台增删改)。
type ResourceBrief = model.ResourceBrief

// ManageDetail 后台管理域:点击某节点的详情。
type ManageDetail = model.ManageDetail

// ManageAreaDetail 点击安保区域:可管理则给出子区域数量 + 本区域直接资源;否则暂无管理权限。
// 子区域由左侧树懒加载展开,不在详情里平铺;子区域数量与资源都走 DB 索引查询,避免全表扫描(支撑大数据量)。
func (s *ViewService) ManageAreaDetail(ctx context.Context, userId string, areaId int) (*ManageDetail, error) {
	u := s.User(userId)
	d := &ManageDetail{Children: []string{}, Resources: []string{}, ResourceItems: []ResourceBrief{}}
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
	var rs []ResourceBrief
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
func (s *ViewService) ManageOrgDetail(userId string, orgId int) *ManageDetail {
	u := s.User(userId)
	d := &ManageDetail{Children: []string{}, Resources: []string{}}
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

// ActionAllow 资源上的某操作及当前用户是否有权。
type ActionAllow = model.ActionAllow

// ResourceView 应用端资源条目。
type ResourceView = model.ResourceView

// AreaResourcesView 点击某区域后的资源面板数据。
type AreaResourcesView = model.AreaResourcesView

// AreaResources 返回某用户点击某区域时该看到的资源(含其子树),及每个操作是否有权。
// 若该区域对用户不可访问(仅导航祖先),Accessible=false。
func (s *ViewService) AreaResources(userId string, areaId int) *AreaResourcesView {
	u := s.User(userId)
	if u == nil {
		return &AreaResourcesView{}
	}
	areas := s.Areas()
	var area *model.Area
	pathById := make(map[int]string, len(areas))
	for _, a := range areas {
		pathById[a.Id] = a.Path
		if a.Id == areaId {
			area = a
		}
	}
	if area == nil {
		return &AreaResourcesView{}
	}
	v := &AreaResourcesView{AreaName: area.Name, Resources: []ResourceView{}}
	if !s.userResAreaCovers(u, areaId) {
		v.Accessible = false // 仅导航的祖先 / 无权区域
		return v
	}
	v.Accessible = true
	acts := s.Actions()
	for _, r := range s.Resources() {
		rp := pathById[r.AreaId]
		if rp == "" || !strings.HasPrefix(rp, area.Path) { // 仅本区域子树内的资源
			continue
		}
		rv := ResourceView{Id: r.Id, Name: r.Name, Area: s.nodeName(treeKindArea, r.AreaId)}
		for _, act := range acts {
			ok := s.CheckResource(u, r.Id, act.Code).Allow
			rv.Actions = append(rv.Actions, ActionAllow{Code: act.Code, Name: act.Name, Allowed: ok})
		}
		// 资源可见性只由 RES_AREA 区域范围决定;范围内资源直接展示。
		v.Resources = append(v.Resources, rv)
	}
	return v
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
