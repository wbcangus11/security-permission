package service

import (
	"strings"

	"security-permission/internal/model"
)

// Decision 鉴权结果,带可读的判定轨迹,便于前端展示「为什么允许/拒绝」。
type Decision struct {
	Allow  bool     `json:"allow"`
	Reason string   `json:"reason"`
	Trace  []string `json:"trace"`
}

// isSuper 超级管理员判定(仿海康内置 root):鉴权三关对其直接放行。
func isSuper(u *model.User) bool { return u != nil && u.IsSuperuser }

// superDecision 超级管理员放行结果。
func superDecision(what string) *Decision {
	r := "超级管理员,拥有全部" + what
	return &Decision{Allow: true, Reason: r, Trace: []string{r}}
}

// effectiveRoles 取用户绑定的全部角色实体。
func (s *Store) effectiveRoles(u *model.User) []*model.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles := make([]*model.Role, 0, len(u.RoleIds))
	for _, rid := range u.RoleIds {
		if r := s.roles[rid]; r != nil {
			roles = append(roles, r)
		}
	}
	return roles
}

func withSkippedRole(skip map[int]bool, roleId int) map[int]bool {
	next := make(map[int]bool, len(skip)+1)
	for id, ok := range skip {
		next[id] = ok
	}
	next[roleId] = true
	return next
}

func roleSkipped(skip map[int]bool, roleId int) bool {
	return skip != nil && skip[roleId]
}

func (s *Store) creatorByRole(r *model.Role) *model.User {
	if r == nil || r.CreatedBy <= 0 {
		return nil
	}
	return s.User(r.CreatedBy)
}

// delegatedRoleUncapped 判断角色是否无需被创建人当前权限收窄。
// created_by=0 表示系统/超管创建;创建人是超管时也不收窄。
func (s *Store) delegatedRoleUncapped(r *model.Role) bool {
	if r == nil || r.CreatedBy <= 0 {
		return true
	}
	creator := s.User(r.CreatedBy)
	return creator != nil && creator.IsSuperuser
}

func (s *Store) creatorAllowsMenu(r *model.Role, menuId int, skip map[int]bool) bool {
	if s.delegatedRoleUncapped(r) {
		return true
	}
	creator := s.creatorByRole(r)
	if creator == nil {
		return false
	}
	return s.userHasMenuIdWithSkip(creator, menuId, withSkippedRole(skip, r.Id))
}

func (s *Store) creatorAllowsTree(r *model.Role, kind string, nodeId int, skip map[int]bool) bool {
	if s.delegatedRoleUncapped(r) {
		return true
	}
	creator := s.creatorByRole(r)
	if creator == nil {
		return false
	}
	d := s.checkTreeScopeWithSkip(creator, nodeId, kind, func(x *model.Role) []model.DataScope {
		if kind == "area" {
			return x.AreaScopes
		}
		return x.OrgScopes
	}, withSkippedRole(skip, r.Id))
	return d.Allow
}

func (s *Store) creatorAllowsResArea(r *model.Role, areaId int, skip map[int]bool) bool {
	if s.delegatedRoleUncapped(r) {
		return true
	}
	creator := s.creatorByRole(r)
	if creator == nil {
		return false
	}
	return s.userResAreaCoversWithSkip(creator, areaId, withSkippedRole(skip, r.Id))
}

func (s *Store) creatorAllowsResourceAction(r *model.Role, resourceId int, actionCode string, skip map[int]bool) bool {
	if s.delegatedRoleUncapped(r) {
		return true
	}
	creator := s.creatorByRole(r)
	if creator == nil {
		return false
	}
	return s.checkResourceWithSkip(creator, resourceId, actionCode, withSkippedRole(skip, r.Id)).Allow
}

// CheckMenu 功能关:用户任一角色拥有该菜单 code 即放行。
func (s *Store) CheckMenu(u *model.User, menuCode string) *Decision {
	if isSuper(u) {
		return superDecision("功能权限")
	}
	d := &Decision{}
	menu := s.menuByCode(menuCode)
	if menu == nil {
		d.Reason = "菜单不存在:" + menuCode
		return d
	}
	for _, r := range s.effectiveRoles(u) {
		for _, mid := range r.MenuIds {
			if mid == menu.Id {
				if !s.creatorAllowsMenu(r, mid, nil) {
					d.Trace = append(d.Trace, "角色「"+r.Name+"」拥有该菜单,但已超出创建人当前可授权范围")
					continue
				}
				d.Allow = true
				d.Reason = "角色「" + r.Name + "」拥有菜单「" + menu.Name + "」"
				d.Trace = append(d.Trace, d.Reason)
				return d
			}
		}
	}
	d.Reason = "没有任何角色授予菜单「" + menu.Name + "」"
	return d
}

// CheckArea 数据关(管理域):目标区域是否落在某角色的安保区域授权范围内。
func (s *Store) CheckArea(u *model.User, areaId int) *Decision {
	return s.checkTreeScopeWithSkip(u, areaId, "area", func(r *model.Role) []model.DataScope { return r.AreaScopes }, nil)
}

// CheckOrg 数据关(管理域):目标组织是否落在某角色的组织授权范围内。
func (s *Store) CheckOrg(u *model.User, orgId int) *Decision {
	return s.checkTreeScopeWithSkip(u, orgId, "org", func(r *model.Role) []model.DataScope { return r.OrgScopes }, nil)
}

// checkTreeScope 树范围判断的通用实现:精确命中节点,或在含子节点的授权子树内(path 前缀)。
func (s *Store) checkTreeScopeWithSkip(u *model.User, nodeId int, kind string, pick func(*model.Role) []model.DataScope, skip map[int]bool) *Decision {
	if isSuper(u) {
		return superDecision("数据权限")
	}
	d := &Decision{}
	targetPath := s.nodePath(kind, nodeId)
	if targetPath == "" {
		d.Reason = "目标节点不存在"
		return d
	}
	for _, r := range s.effectiveRoles(u) {
		if roleSkipped(skip, r.Id) {
			continue
		}
		for _, sc := range pick(r) {
			if sc.NodeId == nodeId {
				if !s.creatorAllowsTree(r, kind, nodeId, skip) {
					d.Trace = append(d.Trace, "角色「"+r.Name+"」直接授权了该节点,但已超出创建人当前可授权范围")
					continue
				}
				d.Allow, d.Reason = true, "角色「"+r.Name+"」直接授权了该节点"
				d.Trace = append(d.Trace, d.Reason)
				return d
			}
			if sc.IncludeChild {
				if scPath := s.nodePath(kind, sc.NodeId); scPath != "" && strings.HasPrefix(targetPath, scPath) {
					if !s.creatorAllowsTree(r, kind, nodeId, skip) {
						d.Trace = append(d.Trace, "角色「"+r.Name+"」授权的子树「"+s.nodeName(kind, sc.NodeId)+"」包含该节点,但已超出创建人当前可授权范围")
						continue
					}
					d.Allow = true
					d.Reason = "角色「" + r.Name + "」授权的子树「" + s.nodeName(kind, sc.NodeId) + "」包含该节点"
					d.Trace = append(d.Trace, d.Reason)
					return d
				}
			}
		}
	}
	d.Reason = "没有任何角色的数据范围覆盖该节点"
	return d
}

// CheckResource 应用域:资源所在区域在业务范围内,且该操作被授予。
//
// 操作判定规则(对齐海康):
//   - 若该资源存在精细配置(ResourceActions 里有该资源的条目),则仅授予列出的操作(覆盖模式);
//   - 否则,资源所在区域在业务范围内即默认授予全部操作(继承模式,新增资源自动生效)。
func (s *Store) CheckResource(u *model.User, resourceId int, actionCode string) *Decision {
	return s.checkResourceWithSkip(u, resourceId, actionCode, nil)
}

func (s *Store) checkResourceWithSkip(u *model.User, resourceId int, actionCode string, skip map[int]bool) *Decision {
	if isSuper(u) {
		return superDecision("业务资源操作权限")
	}
	d := &Decision{}
	res := func() *model.Resource { s.mu.RLock(); defer s.mu.RUnlock(); return s.resource(resourceId) }()
	if res == nil {
		d.Reason = "资源不存在"
		return d
	}
	areaPath := s.nodePath("area", res.AreaId)

	for _, r := range s.effectiveRoles(u) {
		if roleSkipped(skip, r.Id) {
			continue
		}
		// 1) 资源所在区域是否在该角色的业务资源范围内
		inScope := false
		var scopeName string
		for _, sc := range r.ResourceAreaScopes {
			if sc.NodeId == res.AreaId {
				inScope, scopeName = true, s.nodeName("area", sc.NodeId)
				break
			}
			if sc.IncludeChild {
				if scPath := s.nodePath("area", sc.NodeId); scPath != "" && strings.HasPrefix(areaPath, scPath) {
					inScope, scopeName = true, s.nodeName("area", sc.NodeId)
					break
				}
			}
		}
		if !inScope {
			continue
		}
		if !s.creatorAllowsResArea(r, res.AreaId, skip) {
			d.Trace = append(d.Trace, "角色「"+r.Name+"」业务范围「"+scopeName+"」覆盖资源所在区域,但已超出创建人当前资源范围")
			continue
		}
		d.Trace = append(d.Trace, "角色「"+r.Name+"」业务范围「"+scopeName+"」覆盖资源所在区域")

		// 2) 精细配置覆盖 or 继承
		//    精细模式判定:显式 ResourceOverrides ∪ 有操作行(兼容旧数据)。
		//    精细且零操作 → granted 恒 false → 该资源零权限 → 应用端资源级不可见(AreaResources 过滤)。
		hasOverride, granted := false, false
		for _, id := range r.ResourceOverrides {
			if id == resourceId {
				hasOverride = true
				break
			}
		}
		for _, ra := range r.ResourceActions {
			if ra.ResourceId == resourceId {
				hasOverride = true
				if ra.ActionCode == actionCode {
					granted = true
				}
			}
		}
		if hasOverride {
			if granted {
				if !s.creatorAllowsResourceAction(r, resourceId, actionCode, skip) {
					d.Trace = append(d.Trace, "角色「"+r.Name+"」精细授权了该资源的「"+s.actionName(actionCode)+"」,但已超出创建人当前可授权操作")
					continue
				}
				d.Allow, d.Reason = true, "角色「"+r.Name+"」精细授权了该资源的「"+s.actionName(actionCode)+"」"
				d.Trace = append(d.Trace, d.Reason)
				return d
			}
			d.Trace = append(d.Trace, "角色「"+r.Name+"」对该资源有精细配置但未含「"+s.actionName(actionCode)+"」")
			continue
		}
		if !s.creatorAllowsResourceAction(r, resourceId, actionCode, skip) {
			d.Trace = append(d.Trace, "角色「"+r.Name+"」按区域范围继承该操作,但已超出创建人当前可授权操作")
			continue
		}
		d.Allow, d.Reason = true, "角色「"+r.Name+"」按区域范围继承,默认授予全部操作"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	if d.Reason == "" {
		d.Reason = "资源不在任何角色的业务范围内,或操作被精细配置排除"
	}
	return d
}

// ---------- 树/菜单查找辅助 ----------

func (s *Store) menuByCode(code string) *model.Menu {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.menus {
		if m.Code == code {
			return m
		}
	}
	return nil
}

func (s *Store) nodePath(kind string, id int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kind == "area" {
		if a := s.area(id); a != nil {
			return a.Path
		}
	} else {
		if o := s.org(id); o != nil {
			return o.Path
		}
	}
	return ""
}

func (s *Store) nodeName(kind string, id int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kind == "area" {
		if a := s.area(id); a != nil {
			return a.Name
		}
	} else {
		if o := s.org(id); o != nil {
			return o.Name
		}
	}
	return ""
}

func (s *Store) actionName(code string) string {
	for _, a := range s.actions {
		if a.Code == code {
			return a.Name
		}
	}
	return code
}
