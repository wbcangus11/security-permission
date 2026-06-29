package service

import (
	"strings"

	"security-permission/internal/model"
)

// Decision is the authorization result returned to the UI test panel.
type Decision struct {
	Allow  bool     `json:"allow"`
	Reason string   `json:"reason"`
	Trace  []string `json:"trace"`
}

func isSuper(u *model.User) bool { return u != nil && u.IsSuperuser }

func superDecision(what string) *Decision {
	r := "超级管理员拥有全部" + what
	return &Decision{Allow: true, Reason: r, Trace: []string{r}}
}

func (s *Store) effectiveRoles(u *model.User) []*model.Role {
	if u == nil {
		return nil
	}
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

// created_by=0 means system-created. Roles created by a superuser are also
// not narrowed by creator permissions.
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
	return s.userHasMenuIdUncachedWithSkip(creator, menuId, withSkippedRole(skip, r.Id))
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
		if kind == treeKindArea {
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
	return s.userResAreaCoversUncachedWithSkip(creator, areaId, withSkippedRole(skip, r.Id))
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

func (s *Store) CheckMenu(u *model.User, menuCode string) *Decision {
	if isSuper(u) {
		return superDecision("功能权限")
	}
	d := &Decision{}
	menu := s.menuByCode(menuCode)
	if menu == nil {
		d.Reason = "菜单不存在: " + menuCode
		return d
	}
	if p := s.userPermissions(u); p != nil && p.MenuCodes[menuCode] {
		d.Allow = true
		d.Reason = "用户有效权限包含菜单「" + menu.Name + "」"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	d.Reason = "没有任何有效权限授予菜单「" + menu.Name + "」"
	return d
}

func (s *Store) CheckArea(u *model.User, areaId int) *Decision {
	return s.checkCachedTree(u, areaId, treeKindArea)
}

func (s *Store) CheckOrg(u *model.User, orgId int) *Decision {
	return s.checkCachedTree(u, orgId, treeKindOrg)
}

func (s *Store) checkCachedTree(u *model.User, nodeId int, kind string) *Decision {
	if isSuper(u) {
		return superDecision("数据权限")
	}
	d := &Decision{}
	name := s.nodeName(kind, nodeId)
	if name == "" {
		d.Reason = "目标节点不存在"
		return d
	}
	p := s.userPermissions(u)
	if p != nil {
		if kind == treeKindArea && p.AreaIds[nodeId] {
			d.Allow = true
		}
		if kind == treeKindOrg && p.OrgIds[nodeId] {
			d.Allow = true
		}
	}
	if d.Allow {
		d.Reason = "用户有效权限覆盖节点「" + name + "」"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	d.Reason = "没有任何有效权限覆盖该节点"
	return d
}

// checkTreeScopeWithSkip is the uncached tree evaluator used to rebuild
// per-user snapshots and to apply creator-based delegation narrowing.
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
					d.Trace = append(d.Trace, "角色「"+r.Name+"」直接授权了该节点, 但已超出创建人当前可授权范围")
					continue
				}
				d.Allow = true
				d.Reason = "角色「" + r.Name + "」直接授权了该节点"
				d.Trace = append(d.Trace, d.Reason)
				return d
			}
			if sc.IncludeChild {
				if scPath := s.nodePath(kind, sc.NodeId); scPath != "" && strings.HasPrefix(targetPath, scPath) {
					if !s.creatorAllowsTree(r, kind, nodeId, skip) {
						d.Trace = append(d.Trace, "角色「"+r.Name+"」授权的子树包含该节点, 但已超出创建人当前可授权范围")
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

func (s *Store) CheckResource(u *model.User, resourceId int, actionCode string) *Decision {
	if isSuper(u) {
		return superDecision("业务资源操作权限")
	}
	d := &Decision{}
	res := func() *model.Resource {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.resource(resourceId)
	}()
	if res == nil {
		d.Reason = "资源不存在"
		return d
	}
	actionName := s.actionName(actionCode)
	if p := s.userPermissions(u); p != nil {
		if actions := p.ResourceActions[resourceId]; actions != nil && actions[actionCode] {
			d.Allow = true
			d.Reason = "用户有效权限授予资源「" + res.Name + "」的「" + actionName + "」"
			d.Trace = append(d.Trace, d.Reason)
			return d
		}
	}
	d.Reason = "资源不在任何有效业务范围内, 或操作被精细配置排除"
	return d
}

// checkResourceWithSkip is the uncached resource evaluator used to rebuild
// snapshots and to apply creator-based delegation narrowing.
func (s *Store) checkResourceWithSkip(u *model.User, resourceId int, actionCode string, skip map[int]bool) *Decision {
	if isSuper(u) {
		return superDecision("业务资源操作权限")
	}
	d := &Decision{}
	res := func() *model.Resource {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.resource(resourceId)
	}()
	if res == nil {
		d.Reason = "资源不存在"
		return d
	}
	areaPath := s.nodePath(treeKindArea, res.AreaId)

	for _, r := range s.effectiveRoles(u) {
		if roleSkipped(skip, r.Id) {
			continue
		}
		inScope := false
		var scopeName string
		for _, sc := range r.ResourceAreaScopes {
			if sc.NodeId == res.AreaId {
				inScope, scopeName = true, s.nodeName(treeKindArea, sc.NodeId)
				break
			}
			if sc.IncludeChild {
				if scPath := s.nodePath(treeKindArea, sc.NodeId); scPath != "" && strings.HasPrefix(areaPath, scPath) {
					inScope, scopeName = true, s.nodeName(treeKindArea, sc.NodeId)
					break
				}
			}
		}
		if !inScope {
			continue
		}
		if !s.creatorAllowsResArea(r, res.AreaId, skip) {
			d.Trace = append(d.Trace, "角色「"+r.Name+"」业务范围「"+scopeName+"」覆盖资源所在区域, 但已超出创建人当前资源范围")
			continue
		}
		d.Trace = append(d.Trace, "角色「"+r.Name+"」业务范围「"+scopeName+"」覆盖资源所在区域")

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
					d.Trace = append(d.Trace, "角色「"+r.Name+"」精细授权了该操作, 但已超出创建人当前可授权操作")
					continue
				}
				d.Allow = true
				d.Reason = "角色「" + r.Name + "」精细授权了该资源的「" + s.actionName(actionCode) + "」"
				d.Trace = append(d.Trace, d.Reason)
				return d
			}
			d.Trace = append(d.Trace, "角色「"+r.Name+"」对该资源有精细配置但未包含「"+s.actionName(actionCode)+"」")
			continue
		}
		if !s.creatorAllowsResourceAction(r, resourceId, actionCode, skip) {
			d.Trace = append(d.Trace, "角色「"+r.Name+"」按区域范围继承该操作, 但已超出创建人当前可授权操作")
			continue
		}
		d.Allow = true
		d.Reason = "角色「" + r.Name + "」按区域范围继承, 默认授予全部操作"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	if d.Reason == "" {
		d.Reason = "资源不在任何角色的业务范围内, 或操作被精细配置排除"
	}
	return d
}

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
	if kind == treeKindArea {
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
	if kind == treeKindArea {
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
