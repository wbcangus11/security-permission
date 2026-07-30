package permission

import (
	"sync"
	"time"
)

const defaultPermissionSnapshotTTL = 5 * time.Minute

type snapshotCacheEntry struct {
	snapshot  *permissionSnapshot
	expiresAt time.Time
}

// snapshotLoadToken 记住本次回源开始时的版本。
// 如果查库期间刚好有人改了权限，旧结果就不会再被塞回缓存。
type snapshotLoadToken struct {
	userVersion uint64
	allVersion  uint64
}

type snapshotCache struct {
	mu           sync.RWMutex
	ttl          time.Duration
	entries      map[string]snapshotCacheEntry
	userVersions map[string]uint64
	allVersion   uint64
}

func newSnapshotCache(ttl time.Duration) *snapshotCache {
	return &snapshotCache{
		ttl:          ttl,
		entries:      map[string]snapshotCacheEntry{},
		userVersions: map[string]uint64{},
	}
}

func (c *snapshotCache) get(userID string) (*permissionSnapshot, snapshotLoadToken, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	token := snapshotLoadToken{
		userVersion: c.userVersions[userID],
		allVersion:  c.allVersion,
	}
	entry, ok := c.entries[userID]
	if !ok || entry.snapshot == nil || time.Now().After(entry.expiresAt) {
		return nil, token, false
	}
	return entry.snapshot, token, true
}

func (c *snapshotCache) put(userID string, token snapshotLoadToken, snapshot *permissionSnapshot) bool {
	if userID == "" || snapshot == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.allVersion != token.allVersion || c.userVersions[userID] != token.userVersion {
		return false
	}
	c.entries[userID] = snapshotCacheEntry{
		snapshot:  snapshot,
		expiresAt: time.Now().Add(c.ttl),
	}
	return true
}

func (c *snapshotCache) invalidateUsers(userIDs ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, userID := range userIDs {
		if userID == "" {
			continue
		}
		delete(c.entries, userID)
		c.userVersions[userID]++
	}
}

func (c *snapshotCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = map[string]snapshotCacheEntry{}
	c.allVersion++
}

var permissionSnapshots = newSnapshotCache(defaultPermissionSnapshotTTL)

// InvalidateUser 用在用户自身或角色绑定发生变化之后。
// 这里只删一个用户，不会影响其他人的缓存。
func InvalidateUser(userID string) {
	permissionSnapshots.invalidateUsers(userID)
}

// InvalidateUsers 用在角色权限变化之后，一次清掉绑定该角色的用户。
func InvalidateUsers(userIDs ...string) {
	permissionSnapshots.invalidateUsers(userIDs...)
}

// InvalidateAll 用在区域、组织路径发生变化之后。
// 树结构写入很少见，基础版本先统一清快照，规则简单也不容易漏权限。
func InvalidateAll() {
	permissionSnapshots.invalidateAll()
}
