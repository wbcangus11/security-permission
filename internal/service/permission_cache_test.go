package service

import (
	"testing"

	"security-permission/internal/model"
)

func TestUserPermissionCacheInvalidatesByVersion(t *testing.T) {
	s := newRuntimeCapStore()
	li := s.User("2")

	if d := s.CheckArea(li, 2); !d.Allow {
		t.Fatalf("expected initial cached area 2 allow, got deny: %s", d.Reason)
	}

	s.roles[10].AreaScopes = []model.DataScope{{NodeId: 3, IncludeChild: true}}
	if d := s.CheckArea(li, 2); !d.Allow {
		t.Fatalf("expected stale cache to keep area 2 before invalidation, got deny: %s", d.Reason)
	}

	s.mu.Lock()
	s.invalidatePermissionsLocked()
	s.mu.Unlock()

	if d := s.CheckArea(li, 2); d.Allow {
		t.Fatalf("expected area 2 denied after cache invalidation, got allow: %s", d.Reason)
	}
	if d := s.CheckArea(li, 3); !d.Allow {
		t.Fatalf("expected area 3 allowed after cache invalidation, got deny: %s", d.Reason)
	}
}
