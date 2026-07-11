package permission

import (
	"context"
	"testing"
)

func TestReloadFromDatabaseSmoke(t *testing.T) {
	if err := S.Runtime.Reload(context.Background()); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if menu := S.Permission.menuByCode("app.video.live"); menu == nil {
		t.Fatal("expected menu app.video.live loaded from database")
	}
}
