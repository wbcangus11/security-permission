package permission

import (
	"context"
	"sync"
	"testing"
	"time"

	"security-permission/internal/consts"
	"security-permission/internal/model"
)

func TestLoadPermissionSnapshotRequiresContextUser(t *testing.T) {
	if _, err := loadPermissionSnapshot(context.Background()); err == nil {
		t.Fatal("ctx 中没有当前用户时必须拒绝请求")
	}
	systemCtx := context.WithValue(context.Background(), consts.ContextKeyUserId, "0")
	if _, err := loadPermissionSnapshot(systemCtx); err == nil {
		t.Fatal("系统内置身份不能作为当前登录用户")
	}
}

func TestFindUserSkipsDatabaseWhenIDIsEmpty(t *testing.T) {
	user, err := findUser(context.Background(), "")
	if err != nil || user != nil {
		t.Fatalf("空 ID 不应该查询数据库，user=%v err=%v", user, err)
	}
}

func TestSnapshotCacheHitAndTargetedInvalidation(t *testing.T) {
	cache := newSnapshotCache(time.Hour)
	first := newTestSnapshot(&model.User{Id: "u1"})

	_, token, hit := cache.get("u1")
	if hit {
		t.Fatal("空缓存不应该命中")
	}
	cache.put("u1", token, first)

	cached, _, hit := cache.get("u1")
	if !hit || cached != first {
		t.Fatal("写入以后应该直接命中同一份只读快照")
	}

	cache.invalidateUsers("u2")
	if cached, _, hit = cache.get("u1"); !hit || cached != first {
		t.Fatal("失效别的用户不能影响 u1")
	}

	cache.invalidateUsers("u1")
	if _, _, hit = cache.get("u1"); hit {
		t.Fatal("精准失效以后 u1 不应该继续命中")
	}
}

func TestSnapshotCacheDoesNotPutBackStaleLoad(t *testing.T) {
	cache := newSnapshotCache(time.Hour)
	stale := newTestSnapshot(&model.User{Id: "u1"})

	_, oldToken, _ := cache.get("u1")
	cache.invalidateUsers("u1")
	if cache.put("u1", oldToken, stale) {
		t.Fatal("版本已经变化时不应该接受旧快照")
	}

	if _, _, hit := cache.get("u1"); hit {
		t.Fatal("失效之前开始的旧查询不能把旧权限重新放回缓存")
	}

	fresh := newTestSnapshot(&model.User{Id: "u1"})
	_, newToken, _ := cache.get("u1")
	if !cache.put("u1", newToken, fresh) {
		t.Fatal("使用最新版本重新加载后应该可以写入缓存")
	}
	if cached, _, hit := cache.get("u1"); !hit || cached != fresh {
		t.Fatal("重新加载后的请求应该拿到最新快照")
	}
}

func TestSnapshotCacheExpires(t *testing.T) {
	cache := newSnapshotCache(time.Hour)
	snapshot := newTestSnapshot(&model.User{Id: "u1"})
	_, token, _ := cache.get("u1")
	cache.put("u1", token, snapshot)

	cache.mu.Lock()
	entry := cache.entries["u1"]
	entry.expiresAt = time.Now().Add(-time.Second)
	cache.entries["u1"] = entry
	cache.mu.Unlock()

	if _, _, hit := cache.get("u1"); hit {
		t.Fatal("超过 TTL 的快照应该重新回源")
	}
}

func TestSnapshotCacheConcurrentAccess(t *testing.T) {
	cache := newSnapshotCache(time.Hour)
	snapshot := newTestSnapshot(&model.User{Id: "u1"})
	var workers sync.WaitGroup

	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for round := 0; round < 500; round++ {
				_, token, hit := cache.get("u1")
				if !hit {
					cache.put("u1", token, snapshot)
				}
				if (worker+round)%17 == 0 {
					cache.invalidateUsers("u1")
				}
				if (worker+round)%101 == 0 {
					cache.invalidateAll()
				}
			}
		}(i)
	}

	workers.Wait()
}

func TestAccessExposesReadOnlyPermissionMethods(t *testing.T) {
	snapshot := newTestSnapshot(
		&model.User{Id: "u1", RoleIds: []int{1}},
		&model.Role{
			MenuConfigCodes: []string{menuRoleManage},
			AreaScopes:      []model.DataScope{{NodeId: 1, IncludeChild: true}},
		},
	)
	access := &Access{snapshot: snapshot}

	if !access.HasMenu(menuRoleManage) {
		t.Fatal("Access 应该暴露菜单判断")
	}
	if !access.Covers(ScopeArea, "/1/3/", 3) {
		t.Fatal("Access 应该暴露树范围判断")
	}
	user := access.User()
	user.RoleIds[0] = 999
	if snapshot.user.RoleIds[0] != 1 {
		t.Fatal("Access.User 返回值不能改坏缓存里的用户")
	}
}
