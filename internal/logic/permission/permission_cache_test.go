package permission

import (
	"testing"
)

func TestUserPermissionCacheInvalidatesByVersion(t *testing.T) {
	s := newRuntimeCapPermission()
	li := s.User("2")

	if d := s.CheckMenu(li, "app.video.live"); !d.Allow {
		t.Fatalf("expected initial cached menu allow, got deny: %s", d.Reason)
	}

	s.roles[10].MenuIds = nil
	if d := s.CheckMenu(li, "app.video.live"); !d.Allow {
		t.Fatalf("expected stale cache to keep menu before invalidation, got deny: %s", d.Reason)
	}

	s.mu.Lock()
	s.invalidatePermissionsLocked()
	s.mu.Unlock()

	if d := s.CheckMenu(li, "app.video.live"); d.Allow {
		t.Fatalf("expected menu denied after cache invalidation, got allow: %s", d.Reason)
	}
}
