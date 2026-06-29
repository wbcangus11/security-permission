package service

import "security-permission/internal/model"

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
				s.permCache = map[int]*effectivePermission{}
			}
			s.permCache[u.Id] = p
			s.mu.Unlock()
			return p
		}
		s.mu.Unlock()
	}
}

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
