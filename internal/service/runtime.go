package service

import (
	"strings"

	"security-permission/internal/model"
)

// 应用端(使用界面)运行时数据。基于应用域(RES_AREA 资源范围 + 资源操作)。
//
// 关键区分:
//   - accessible(可访问):用户的资源范围覆盖该区域,点击能看资源。
//   - visible(可见):自己可访问,或它有可访问的后代 —— 后者是"仅导航的祖先",
//     点击会提示「暂无操作权限」(其本身资源不授权)。

// VisibleArea 可见区域树节点。
type VisibleArea struct {
	Id         int    `json:"id"`
	ParentId   int    `json:"parentId"`
	Name       string `json:"name"`
	Accessible bool   `json:"accessible"` // 是否可访问其资源(否=仅导航祖先)
}

// visibleAreaTree 通用:按 accessible 判定函数算出可见区域树(可见=自己可访问或有可访问后代)。
func (s *Store) visibleAreaTree(accessible func(areaId int) bool) []VisibleArea {
	areas := s.Areas()
	acc := make(map[int]bool)
	for _, a := range areas {
		if accessible(a.Id) {
			acc[a.Id] = true
		}
	}
	out := []VisibleArea{}
	for _, a := range areas {
		visible := acc[a.Id]
		if !visible {
			for _, b := range areas {
				if acc[b.Id] && b.Id != a.Id && strings.HasPrefix(b.Path, a.Path) {
					visible = true
					break
				}
			}
		}
		if visible {
			out = append(out, VisibleArea{Id: a.Id, ParentId: a.ParentId, Name: a.Name, Accessible: acc[a.Id]})
		}
	}
	return out
}

// VisibleAreas 应用端可见区域树(accessible=资源域 RES_AREA 覆盖)。
func (s *Store) VisibleAreas(userId int) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	return s.visibleAreaTree(func(id int) bool { return s.userResAreaCovers(u, id) })
}

// ManageAreas 后台管理域可见区域树(accessible=安保区域管理权限 AREA 覆盖)。
func (s *Store) ManageAreas(userId int) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	return s.visibleAreaTree(func(id int) bool { return s.CheckArea(u, id).Allow })
}

// ManageOrgs 后台管理域可见组织树(accessible=组织管理权限 ORG 覆盖)。
func (s *Store) ManageOrgs(userId int) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	orgs := s.Orgs()
	acc := make(map[int]bool)
	for _, o := range orgs {
		if s.CheckOrg(u, o.Id).Allow {
			acc[o.Id] = true
		}
	}
	out := []VisibleArea{}
	for _, o := range orgs {
		visible := acc[o.Id]
		if !visible {
			for _, b := range orgs {
				if acc[b.Id] && b.Id != o.Id && strings.HasPrefix(b.Path, o.Path) {
					visible = true
					break
				}
			}
		}
		if visible {
			out = append(out, VisibleArea{Id: o.Id, ParentId: o.ParentId, Name: o.Name, Accessible: acc[o.Id]})
		}
	}
	return out
}

// ManageDetail 后台管理域:点击某节点的详情。
type ManageDetail struct {
	Accessible bool     `json:"accessible"` // false => 暂无管理权限
	Name       string   `json:"name"`
	Children   []string `json:"children"`  // 直接子节点
	Resources  []string `json:"resources"` // 区域直接挂的资源(组织无)
}

// ManageAreaDetail 点击安保区域:可管理则列出直接子区域与本区域资源;否则暂无管理权限。
func (s *Store) ManageAreaDetail(userId, areaId int) *ManageDetail {
	u := s.User(userId)
	d := &ManageDetail{Children: []string{}, Resources: []string{}}
	if u == nil {
		return d
	}
	for _, a := range s.Areas() {
		if a.Id == areaId {
			d.Name = a.Name
		}
	}
	if !s.CheckArea(u, areaId).Allow {
		return d // accessible=false
	}
	d.Accessible = true
	for _, a := range s.Areas() {
		if a.ParentId == areaId {
			d.Children = append(d.Children, a.Name)
		}
	}
	for _, r := range s.Resources() {
		if r.AreaId == areaId {
			d.Resources = append(d.Resources, r.Name)
		}
	}
	return d
}

// ManageOrgDetail 点击组织:可管理则列出直接子组织;否则暂无管理权限。
func (s *Store) ManageOrgDetail(userId, orgId int) *ManageDetail {
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
func (s *Store) SysMenus(userId int) []*model.Menu {
	u := s.User(userId)
	out := []*model.Menu{}
	if u == nil {
		return out
	}
	for _, m := range s.Menus() {
		if m.Domain == model.MenuDomainSys && s.userHasMenuId(u, m.Id) {
			out = append(out, m)
		}
	}
	return out
}

// ActionAllow 资源上的某操作及当前用户是否有权。
type ActionAllow struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

// ResourceView 应用端资源条目。
type ResourceView struct {
	Id      int           `json:"id"`
	Name    string        `json:"name"`
	Area    string        `json:"area"`
	Actions []ActionAllow `json:"actions"`
}

// AreaResourcesView 点击某区域后的资源面板数据。
type AreaResourcesView struct {
	Accessible bool           `json:"accessible"` // false => 前端显示「暂无操作权限」
	AreaName   string         `json:"areaName"`
	Resources  []ResourceView `json:"resources"`
}

// AreaResources 返回某用户点击某区域时该看到的资源(含其子树),及每个操作是否有权。
// 若该区域对用户不可访问(仅导航祖先),Accessible=false。
func (s *Store) AreaResources(userId, areaId int) *AreaResourcesView {
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
		rv := ResourceView{Id: r.Id, Name: r.Name, Area: s.nodeName("area", r.AreaId)}
		for _, act := range acts {
			rv.Actions = append(rv.Actions, ActionAllow{Code: act.Code, Name: act.Name, Allowed: s.CheckResource(u, r.Id, act.Code).Allow})
		}
		v.Resources = append(v.Resources, rv)
	}
	return v
}

// AppMenus 返回某用户在应用域可见的菜单(功能权限),用于应用端顶部菜单。
func (s *Store) AppMenus(userId int) []*model.Menu {
	u := s.User(userId)
	out := []*model.Menu{}
	if u == nil {
		return out
	}
	for _, m := range s.Menus() {
		if m.Domain != model.MenuDomainApp {
			continue
		}
		if s.userHasMenuId(u, m.Id) {
			out = append(out, m)
		}
	}
	return out
}
