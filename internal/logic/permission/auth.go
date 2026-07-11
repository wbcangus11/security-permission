package permission

import (
	"strings"

	"security-permission/internal/model"
)

func isSuper(u *model.User) bool { return u != nil && u.IsSuperuser }

func superDecision(what string) *model.Decision {
	r := "超级管理员拥有全部" + what
	return &model.Decision{Allow: true, Reason: r, Trace: []string{r}}
}

func (s *PermissionService) effectiveRoles(u *model.User) []*model.Role {
	if u == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles := make([]*model.Role, 0, len(u.RoleIds))
	for _, rid := range u.RoleIds {
		roles = append(roles, s.roles[rid])
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

func (s *PermissionService) creatorByRole(r *model.Role) *model.User {
	if r == nil || r.CreatedBy == "" || r.CreatedBy == "0" {
		return nil
	}
	return s.User(r.CreatedBy)
}

// 系统内置角色和超级管理员创建的角色不受创建人当前权限收窄。
func (s *PermissionService) delegatedRoleUncapped(r *model.Role) bool {
	if r == nil || r.CreatedBy == "" || r.CreatedBy == "0" {
		return true
	}
	creator := s.User(r.CreatedBy)
	return creator != nil && creator.IsSuperuser
}

func (s *PermissionService) creatorAllowsMenu(r *model.Role, menuId int, skip map[int]bool) bool {
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

func (s *PermissionService) creatorAllowsTree(r *model.Role, kind string, nodeId int, skip map[int]bool) bool {
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

func (s *PermissionService) creatorAllowsResArea(r *model.Role, areaId int, skip map[int]bool) bool {
	if s.delegatedRoleUncapped(r) {
		return true
	}
	creator := s.creatorByRole(r)
	if creator == nil {
		return false
	}
	return s.userResAreaCoversUncachedWithSkip(creator, areaId, withSkippedRole(skip, r.Id))
}

// CheckMenu 判断用户是否拥有某个菜单/功能权限。
// 这是“功能关”:只看角色里有没有该菜单 code;超级管理员直接通过。
func (s *PermissionService) CheckMenu(u *model.User, menuCode string) *model.Decision {
	if isSuper(u) {
		return superDecision("功能权限")
	}
	d := &model.Decision{}
	// 接口只接受稳定 menu code；先转成数据库菜单记录，避免调用方依赖自增 id。
	menu := s.menuByCode(menuCode)
	if menu == nil {
		d.Reason = "菜单不存在: " + menuCode
		return d
	}
	// userPermissions 已经合并多角色、created_by 动态收窄和缓存版本，读这里就是最终生效结果。
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
func (s *PermissionService) CheckArea(u *model.User, areaId int) *model.Decision {
	return s.checkCachedTree(u, areaId, treeKindArea)
}

// CheckOrg 判断用户是否覆盖某个组织节点。
// 这是后台人员/组织管理的数据关。
func (s *PermissionService) CheckOrg(u *model.User, orgId int) *model.Decision {
	return s.checkCachedTree(u, orgId, treeKindOrg)
}

func (s *PermissionService) checkCachedTree(u *model.User, nodeId int, kind string) *model.Decision {
	if isSuper(u) {
		return superDecision("数据权限")
	}
	if kind == treeKindArea {
		return s.checkTreeScopeWithSkip(u, nodeId, kind, func(r *model.Role) []model.DataScope { return r.AreaScopes }, nil)
	}
	return s.checkTreeScopeWithSkip(u, nodeId, kind, func(r *model.Role) []model.DataScope { return r.OrgScopes }, nil)
}

// checkTreeScopeWithSkip 是不读缓存的树范围判定,用于重建用户权限快照和应用创建人动态收窄。
func (s *PermissionService) checkTreeScopeWithSkip(u *model.User, nodeId int, kind string, pick func(*model.Role) []model.DataScope, skip map[int]bool) *model.Decision {
	if isSuper(u) {
		return superDecision("数据权限")
	}
	d := &model.Decision{}
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
// 资源所在区域落在 RES_AREA 范围内时,该资源的所有操作都可用。
func (s *PermissionService) CheckResource(u *model.User, resourceId int, actionCode string) *model.Decision {
	if isSuper(u) {
		return superDecision("业务资源操作权限")
	}
	d := &model.Decision{}
	menuCode, ok := resourceActionMenus[actionCode]
	if !ok {
		d.Reason = "未知资源操作:" + actionCode
		return d
	}
	if menuDecision := s.CheckMenu(u, menuCode); !menuDecision.Allow {
		d.Reason = "功能权限不足:" + menuDecision.Reason
		d.Trace = append(d.Trace, menuDecision.Trace...)
		return d
	}
	// 资源先从内存快照读取；鉴权路径不查库，保证高频访问稳定。
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
	if s.userResAreaCoversUncachedWithSkip(u, res.AreaId, nil) {
		d.Allow = true
		d.Reason = "用户有效业务资源范围覆盖资源「" + res.Name + "」,允许「" + actionName + "」"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	d.Reason = "资源不在任何有效业务范围内"
	return d
}

// checkResourceWithSkip 是不读缓存的资源操作判定,用于重建权限快照和应用创建人动态收窄。
// 这里的 actionCode 只用于输出可读 trace;实际授权只看资源所在区域是否在 RES_AREA 范围内。
func (s *PermissionService) checkResourceWithSkip(u *model.User, resourceId int, actionCode string, skip map[int]bool) *model.Decision {
	if isSuper(u) {
		return superDecision("业务资源操作权限")
	}
	d := &model.Decision{}
	menuCode, ok := resourceActionMenus[actionCode]
	if !ok {
		d.Reason = "未知资源操作:" + actionCode
		return d
	}
	menu := s.menuByCode(menuCode)
	if menu == nil || !s.userHasMenuIdWithSkip(u, menu.Id, skip) {
		d.Reason = "没有资源操作对应的功能权限"
		return d
	}
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
		// 资源权限只认 RES_AREA 区域范围;资源落在范围内时默认拥有全部操作。
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

		d.Allow = true
		d.Reason = "角色「" + r.Name + "」业务范围覆盖资源所在区域,默认允许「" + s.actionName(actionCode) + "」"
		d.Trace = append(d.Trace, d.Reason)
		return d
	}
	if d.Reason == "" {
		d.Reason = "资源不在任何角色的业务范围内"
	}
	return d
}

func (s *PermissionService) menuByCode(code string) *model.Menu {
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

func (s *PermissionService) nodePath(kind string, id int) string {
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

func (s *PermissionService) nodeName(kind string, id int) string {
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

func (s *PermissionService) actionName(code string) string {
	for _, a := range s.Actions() {
		if a.Code == code {
			return a.Name
		}
	}
	return code
}
