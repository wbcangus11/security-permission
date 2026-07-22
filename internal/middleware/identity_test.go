package middleware

import (
	"net/http"
	"strings"
	"testing"
)

func TestIdentityHeaderRequiresOneCleanValue(t *testing.T) {
	header := http.Header{userHeader: []string{"user-123"}}
	if got := identityHeaderValue(header, userHeader); got != "user-123" {
		t.Fatalf("unexpected identity %q", got)
	}
	header[userHeader] = []string{"user-123", "other"}
	if got := identityHeaderValue(header, userHeader); got != "" {
		t.Fatalf("duplicate identity headers must be rejected, got %q", got)
	}
	for _, value := range []string{"user 123", "user,other", "user\nother", strings.Repeat("a", 65)} {
		header[userHeader] = []string{value}
		if got := identityHeaderValue(header, userHeader); got != "" {
			t.Fatalf("unsafe identity %q must be rejected", value)
		}
	}
}

func TestPermissionResponsesCannotBeCachedAcrossUsers(t *testing.T) {
	header := http.Header{}
	setPermissionResponseHeaders(header)
	if got := header.Get("Cache-Control"); got != "no-store, private" {
		t.Fatalf("unexpected Cache-Control %q", got)
	}
	if got := header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("unexpected Pragma %q", got)
	}
	if got := header.Get("Vary"); got != userHeader {
		t.Fatalf("permission response must vary by identity, got %q", got)
	}
}
