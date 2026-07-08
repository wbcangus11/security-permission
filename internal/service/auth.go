package service

import (
	"strings"

	"security-permission/internal/model"
)

// Decision 是鉴权结果,会返回给前端鉴权测试面板展示。
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
	if r == nil || r.CreatedBy == "" || r.CreatedBy == "0" {
		return nil
	}
	return s.User(r.CreatedBy)
}

// created_by=0 表示系统创建/不受限角色;超级管理员创建的角色也不受创建人当前权限收窄。
func (s *Store) delegatedRoleUncapped(r *model.Role) bool {
	if r == nil || r.CreatedBy == "" || r.CreatedBy == "0" {
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
	// 运行时动态收窄:角色存着的权限还要再受创建人当前权限约束。
	// skip 当前角色是为了避免“角色通过自己证明创建人仍有权限”的递归闭环。
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

// CheckMenu 判断用户是否拥有某个菜单/功能权限。
// 这是“功能关”:只看角色里有没有该菜单 code;超级管理员直接通过。
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

// CheckArea 判断用户是否覆盖某个安保区域。
// 这是后台管理域的数据关,用于区域管理、资源管理等写操作。
func (s *Store) CheckArea(u *model.User, areaId int) *Decision {
	return s.checkCachedTree(u, areaId, treeKindArea)
}

// CheckOrg 判断用户是否覆盖某个组织节点。
// 这是后台人员/组织管理的数据关。
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

// checkTreeScopeWithSkip 是不读缓存的树范围判定,用于重建用户权限快照和应用创建人动态收窄。
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
			// include_child=false 时只认当前节点;这是角色树“半选/单节点授权”的落库语义。
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
				// include_child=true 时用物化路径前缀判断子树覆盖,新增子节点天然继承权限。
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

// CheckResource 判断用户是否能对某个业务资源执行某个操作。
// 它先看资源所在区域是否在 RES_AREA 范围内,再应用资源级精细授权覆盖规则。
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

// checkResourceWithSkip 是不读缓存的资源操作判定,用于重建权限快照和应用创建人动态收窄。
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
		// 第一层:资源所在区域必须落在角色的 RES_AREA 范围内。
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
		// 第二层:资源级精细配置。只要进入 override 模式,就不再继承区域全部操作。
		// ResourceOverrides 可以表达“精细模式 + 零操作”,这会让应用端列表隐藏该资源。
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
		// 没有资源级覆盖时,只要区域范围覆盖,默认继承全部操作。
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
	for _, menu := range s.menus {
		if menu.Code == code {
			item := *menu
			return &item
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
