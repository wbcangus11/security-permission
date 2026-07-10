package permission

import "security-permission/internal/model"

// effectivePermission caches the compact menu permission set. Tree permissions
// remain as path scopes and are evaluated on demand to avoid expanding every
// area and organization for every active user.
type effectivePermission struct {
	Version uint64

	MenuIds   map[int]bool
	MenuCodes map[string]bool
}

// userPermissions 返回用户有效权限快照。
// 缓存版本号来自 Store.permVersion;角色或用户变化后旧快照会自动失效。
func (s *PermissionService) userPermissions(u *model.User) *effectivePermission {
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

// buildUserPermissions rebuilds the compact, final menu permission set.
func (s *PermissionService) buildUserPermissions(u *model.User, version uint64) *effectivePermission {
	p := &effectivePermission{
		Version:   version,
		MenuIds:   map[int]bool{},
		MenuCodes: map[string]bool{},
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
	return p
}
