package service

import "security-permission/internal/model"

// effectivePermission 是某个用户“最终生效权限”的快照。
// 它已经把多角色叠加、created_by 动态收窄、资源精细覆盖都算完了,鉴权时只需查 map。
type effectivePermission struct {
	Version uint64

	MenuIds   map[int]bool
	MenuCodes map[string]bool

	AreaIds    map[int]bool
	OrgIds     map[int]bool
	ResAreaIds map[int]bool

	ResourceActions   map[int]map[string]bool
	HiddenResourceIds map[int]bool
}

// userPermissions 返回用户有效权限快照。
// 缓存版本号来自 Store.permVersion;只要角色/用户/树/资源被重载,旧快照就会自动失效。
func (s *Store) userPermissions(u *model.User) *effectivePermission {
	if u == nil {
		return nil
	}
	for {
		s.mu.RLock()
		version := s.permVersion
		if p := s.permCache[u.Id]; p != nil && p.Version == version {
			s.mu.RUnlock()
			return p
		}
		s.mu.RUnlock()

		p := s.buildUserPermissions(u, version)

		s.mu.Lock()
		if s.permVersion == version {
			if s.permCache == nil {
				s.permCache = map[string]*effectivePermission{}
			}
			s.permCache[u.Id] = p
			s.mu.Unlock()
			return p
		}
		s.mu.Unlock()
	}
}

// buildUserPermissions 重新计算用户最终权限。
// 这是相对重的操作,所以只在缓存失效时执行;日常鉴权走 userPermissions 的快照。
func (s *Store) buildUserPermissions(u *model.User, version uint64) *effectivePermission {
	p := &effectivePermission{
		Version:           version,
		MenuIds:           map[int]bool{},
		MenuCodes:         map[string]bool{},
		AreaIds:           map[int]bool{},
		OrgIds:            map[int]bool{},
		ResAreaIds:        map[int]bool{},
		ResourceActions:   map[int]map[string]bool{},
		HiddenResourceIds: map[int]bool{},
	}
	if u.IsSuperuser {
		return p
	}

	for _, m := range s.Menus() {
		if s.userHasMenuIdUncachedWithSkip(u, m.Id, nil) {
			p.MenuIds[m.Id] = true
			p.MenuCodes[m.Code] = true
		}
	}
	for _, a := range s.Areas() {
		if s.checkTreeScopeWithSkip(u, a.Id, treeKindArea, func(r *model.Role) []model.DataScope { return r.AreaScopes }, nil).Allow {
			p.AreaIds[a.Id] = true
		}
		if s.userResAreaCoversUncachedWithSkip(u, a.Id, nil) {
			p.ResAreaIds[a.Id] = true
		}
	}
	for _, o := range s.Orgs() {
		if s.checkTreeScopeWithSkip(u, o.Id, treeKindOrg, func(r *model.Role) []model.DataScope { return r.OrgScopes }, nil).Allow {
			p.OrgIds[o.Id] = true
		}
	}
	for _, res := range s.Resources() {
		for _, act := range s.Actions() {
			if s.checkResourceWithSkip(u, res.Id, act.Code, nil).Allow {
				if p.ResourceActions[res.Id] == nil {
					p.ResourceActions[res.Id] = map[string]bool{}
				}
				p.ResourceActions[res.Id][act.Code] = true
			}
		}
	}

	candidates := map[int]bool{}
	// 只有进入过精细模式的资源才可能被“零操作隐藏”;继承模式默认拥有全部资源操作,不需要检查。
	for _, r := range s.effectiveRoles(u) {
		for _, id := range r.ResourceOverrides {
			candidates[id] = true
		}
		for _, ra := range r.ResourceActions {
			candidates[ra.ResourceId] = true
		}
	}
	for id := range candidates {
		if len(p.ResourceActions[id]) == 0 {
			p.HiddenResourceIds[id] = true
		}
	}
	return p
}
