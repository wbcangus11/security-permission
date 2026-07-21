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
