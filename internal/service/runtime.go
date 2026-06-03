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

// VisibleAreas 返回某用户在应用端可见的区域树(含 accessible 标记)。
func (s *Store) VisibleAreas(userId int) []VisibleArea {
	u := s.User(userId)
	if u == nil {
		return []VisibleArea{}
	}
	areas := s.Areas()
	acc := make(map[int]bool)
	for _, a := range areas {
		if s.userResAreaCovers(u, a.Id) {
			acc[a.Id] = true
		}
	}
	out := []VisibleArea{}
	for _, a := range areas {
		visible := acc[a.Id]
		if !visible {
			for _, b := range areas { // 是否为某可访问节点的祖先
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
