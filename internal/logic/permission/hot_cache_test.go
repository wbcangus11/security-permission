package permission

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"security-permission/internal/model"
)

func TestBoundedTTLCacheExpiresAndStaysBounded(t *testing.T) {
	cache := newBoundedTTLCache[int, string](2, 10*time.Nanosecond)
	now := int64(100)
	cache.nowNano = func() int64 { return now }
	cache.set(1, "one")
	cache.set(2, "two")
	cache.set(3, "three")
	if size := cache.size(); size != 2 {
		t.Fatalf("cache must stay bounded, got size %d", size)
	}
	if value, ok := cache.get(3); !ok || value != "three" {
		t.Fatalf("new value missing: value=%q hit=%v", value, ok)
	}
	now = 111
	if _, ok := cache.get(3); ok {
		t.Fatal("expired value must not be returned")
	}
}

func TestHotCacheCollapsesConcurrentColdLoads(t *testing.T) {
	cache := newHotPermissionCache()
	var loads atomic.Int32
	loader := func() (*model.User, error) {
		loads.Add(1)
		time.Sleep(10 * time.Millisecond)
		return &model.User{Id: "u1", RoleIds: []int{1}}, nil
	}
	const callers = 20
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			user, err := loadCached(cache, cache.users, &cache.userFlights, "u1", loader)
			if err != nil || user == nil || user.Id != "u1" {
				t.Errorf("unexpected cached load: user=%+v err=%v", user, err)
			}
		}()
	}
	wait.Wait()
	if count := loads.Load(); count != 1 {
		t.Fatalf("concurrent misses must collapse to one load, got %d", count)
	}
	if _, err := loadCached(cache, cache.users, &cache.userFlights, "u1", loader); err != nil {
		t.Fatal(err)
	}
	if count := loads.Load(); count != 1 {
		t.Fatalf("warm hit unexpectedly called loader, got %d loads", count)
	}
	cache.invalidateAll()
	if _, err := loadCached(cache, cache.users, &cache.userFlights, "u1", loader); err != nil {
		t.Fatal(err)
	}
	if count := loads.Load(); count != 2 {
		t.Fatalf("load after invalidation expected, got %d loads", count)
	}
}

func TestInvalidationPreventsOldInflightLoadFromRepopulatingCache(t *testing.T) {
	cache := newHotPermissionCache()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = loadCached(cache, cache.users, &cache.userFlights, "u1", func() (*model.User, error) {
			close(started)
			<-release
			return &model.User{Id: "u1"}, nil
		})
	}()
	<-started
	cache.invalidateAll()
	close(release)
	<-done
	if _, ok := cache.users.get("u1"); ok {
		t.Fatal("a load started before invalidation repopulated the current cache generation")
	}
}

func TestCachedModelsAreReturnedAsCopies(t *testing.T) {
	original := &model.Role{
		Id: 1, MenuIds: []int{10},
		AreaScopes: []model.DataScope{{NodeId: 2, IncludeChild: true}},
	}
	copy := cloneRole(original)
	copy.MenuIds[0] = 99
	copy.AreaScopes[0].NodeId = 88
	if original.MenuIds[0] != 10 || original.AreaScopes[0].NodeId != 2 {
		t.Fatal("mutating a returned model changed the cached model")
	}
}
