package permission

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"security-permission/internal/model"
)

// 热缓存只保存实际访问过的数据，并同时受 TTL 和条目上限约束。
// 它不是表快照：不会启动全量加载，也不会遍历数据库来填充缓存。
const (
	hotCacheTTL      = 5 * time.Minute
	hotUserLimit     = 4096
	hotRoleLimit     = 1024
	hotAreaLimit     = 16384
	hotOrgLimit      = 8192
	hotResourceLimit = 32768
	hotMenuLimit     = 1024
)

type ttlValue[V any] struct {
	value     V
	expiresAt int64
}

// boundedTTLCache 的命中只持有读锁，适合鉴权高频读。达到上限时优先清理
// 过期项，仍超限则逐出任意项；权限正确性不依赖具体逐出顺序。
type boundedTTLCache[K comparable, V any] struct {
	mu      sync.RWMutex
	items   map[K]ttlValue[V]
	limit   int
	ttl     time.Duration
	nowNano func() int64
}

func newBoundedTTLCache[K comparable, V any](limit int, ttl time.Duration) *boundedTTLCache[K, V] {
	return &boundedTTLCache[K, V]{
		items:   make(map[K]ttlValue[V]),
		limit:   limit,
		ttl:     ttl,
		nowNano: func() int64 { return time.Now().UnixNano() },
	}
}

func (c *boundedTTLCache[K, V]) get(key K) (V, bool) {
	var zero V
	now := c.nowNano()
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return zero, false
	}
	if entry.expiresAt > now {
		return entry.value, true
	}
	c.mu.Lock()
	if current, exists := c.items[key]; exists && current.expiresAt <= now {
		delete(c.items, key)
	}
	c.mu.Unlock()
	return zero, false
}

func (c *boundedTTLCache[K, V]) set(key K, value V) {
	now := c.nowNano()
	c.mu.Lock()
	_, replacing := c.items[key]
	if c.limit > 0 && !replacing && len(c.items) >= c.limit {
		for existingKey, entry := range c.items {
			if entry.expiresAt <= now {
				delete(c.items, existingKey)
			}
		}
		if len(c.items) >= c.limit {
			for existingKey := range c.items {
				delete(c.items, existingKey)
				break
			}
		}
	}
	c.items[key] = ttlValue[V]{value: value, expiresAt: now + c.ttl.Nanoseconds()}
	c.mu.Unlock()
}

func (c *boundedTTLCache[K, V]) clear() {
	c.mu.Lock()
	c.items = make(map[K]ttlValue[V])
	c.mu.Unlock()
}

func (c *boundedTTLCache[K, V]) size() int {
	c.mu.RLock()
	size := len(c.items)
	c.mu.RUnlock()
	return size
}

type flightCall[V any] struct {
	done       chan struct{}
	value      V
	err        error
	panicValue any
}

// flightGroup 合并同一版本、同一 key 的并发冷加载，避免缓存失效后大量
// 请求同时打到数据库。
type flightGroup[K comparable, V any] struct {
	mu    sync.Mutex
	calls map[K]*flightCall[V]
}

func (g *flightGroup[K, V]) do(key K, load func() (V, error)) (V, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[K]*flightCall[V])
	}
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		<-call.done
		if call.panicValue != nil {
			panic(call.panicValue)
		}
		return call.value, call.err
	}
	call := &flightCall[V]{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	func() {
		defer func() { call.panicValue = recover() }()
		call.value, call.err = load()
	}()
	g.mu.Lock()
	delete(g.calls, key)
	close(call.done)
	g.mu.Unlock()
	if call.panicValue != nil {
		panic(call.panicValue)
	}
	return call.value, call.err
}

type versionedKey[K comparable] struct {
	key     K
	version uint64
}

type hotPermissionCache struct {
	version atomic.Uint64

	users       *boundedTTLCache[string, *model.User]
	roles       *boundedTTLCache[int, *model.Role]
	areas       *boundedTTLCache[int, *model.Area]
	orgs        *boundedTTLCache[int, *model.Org]
	resources   *boundedTTLCache[int, *model.Resource]
	menusByCode *boundedTTLCache[string, *model.Menu]
	menuLists   *boundedTTLCache[string, []*model.Menu]

	userFlights     flightGroup[versionedKey[string], *model.User]
	roleFlights     flightGroup[versionedKey[int], *model.Role]
	areaFlights     flightGroup[versionedKey[int], *model.Area]
	orgFlights      flightGroup[versionedKey[int], *model.Org]
	resourceFlights flightGroup[versionedKey[int], *model.Resource]
	menuCodeFlights flightGroup[versionedKey[string], *model.Menu]
	menuListFlights flightGroup[versionedKey[string], []*model.Menu]
}

func newHotPermissionCache() *hotPermissionCache {
	cache := &hotPermissionCache{
		users:       newBoundedTTLCache[string, *model.User](hotUserLimit, hotCacheTTL),
		roles:       newBoundedTTLCache[int, *model.Role](hotRoleLimit, hotCacheTTL),
		areas:       newBoundedTTLCache[int, *model.Area](hotAreaLimit, hotCacheTTL),
		orgs:        newBoundedTTLCache[int, *model.Org](hotOrgLimit, hotCacheTTL),
		resources:   newBoundedTTLCache[int, *model.Resource](hotResourceLimit, hotCacheTTL),
		menusByCode: newBoundedTTLCache[string, *model.Menu](hotMenuLimit, hotCacheTTL),
		menuLists:   newBoundedTTLCache[string, []*model.Menu](1, hotCacheTTL),
	}
	cache.version.Store(1)
	return cache
}

var permissionHotCache = newHotPermissionCache()

func loadCached[K comparable, V any](
	owner *hotPermissionCache,
	cache *boundedTTLCache[K, V],
	flights *flightGroup[versionedKey[K], V],
	key K,
	load func() (V, error),
) (V, error) {
	version := owner.version.Load()
	if value, ok := cache.get(key); ok {
		return value, nil
	}
	return flights.do(versionedKey[K]{key: key, version: version}, func() (V, error) {
		if value, ok := cache.get(key); ok {
			return value, nil
		}
		value, err := load()
		if err == nil && owner.version.Load() == version {
			cache.set(key, value)
		}
		return value, err
	})
}

// invalidateAll 在事务提交成功后调用。递增版本可阻止失效前已经开始的冷加载
// 把旧数据重新写回缓存；清空 map 则立即释放旧对象。
func (c *hotPermissionCache) invalidateAll() {
	c.version.Add(1)
	c.users.clear()
	c.roles.clear()
	c.areas.clear()
	c.orgs.clear()
	c.resources.clear()
	c.menusByCode.clear()
	c.menuLists.clear()
}

func cloneUser(user *model.User) *model.User {
	if user == nil {
		return nil
	}
	clone := *user
	clone.RoleIds = append([]int(nil), user.RoleIds...)
	return &clone
}

func cloneRole(role *model.Role) *model.Role {
	if role == nil {
		return nil
	}
	clone := *role
	clone.MenuIds = append([]int(nil), role.MenuIds...)
	clone.MenuCodes = append([]string(nil), role.MenuCodes...)
	clone.AreaScopes = append([]model.DataScope(nil), role.AreaScopes...)
	clone.OrgScopes = append([]model.DataScope(nil), role.OrgScopes...)
	clone.ResourceAreaScopes = append([]model.DataScope(nil), role.ResourceAreaScopes...)
	return &clone
}

func cloneArea(area *model.Area) *model.Area {
	if area == nil {
		return nil
	}
	clone := *area
	return &clone
}

func cloneOrg(org *model.Org) *model.Org {
	if org == nil {
		return nil
	}
	clone := *org
	return &clone
}

func cloneResource(resource *model.Resource) *model.Resource {
	if resource == nil {
		return nil
	}
	clone := *resource
	return &clone
}

func cloneMenu(menu *model.Menu) *model.Menu {
	if menu == nil {
		return nil
	}
	clone := *menu
	return &clone
}

func cloneMenus(menus []*model.Menu) []*model.Menu {
	out := make([]*model.Menu, 0, len(menus))
	for _, menu := range menus {
		out = append(out, cloneMenu(menu))
	}
	return out
}

func cachedUser(ctx context.Context, id string) (*model.User, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.users, &permissionHotCache.userFlights, id,
		func() (*model.User, error) { return findUser(ctx, id) })
	return cloneUser(value), err
}

func cachedRole(ctx context.Context, id int) (*model.Role, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.roles, &permissionHotCache.roleFlights, id,
		func() (*model.Role, error) { return findRole(ctx, id) })
	return cloneRole(value), err
}

func cachedArea(ctx context.Context, id int) (*model.Area, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.areas, &permissionHotCache.areaFlights, id,
		func() (*model.Area, error) { return findArea(ctx, id) })
	return cloneArea(value), err
}

func cachedOrg(ctx context.Context, id int) (*model.Org, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.orgs, &permissionHotCache.orgFlights, id,
		func() (*model.Org, error) { return findOrg(ctx, id) })
	return cloneOrg(value), err
}

func cachedResource(ctx context.Context, id int) (*model.Resource, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.resources, &permissionHotCache.resourceFlights, id,
		func() (*model.Resource, error) { return findResource(ctx, id) })
	return cloneResource(value), err
}

func cachedMenuByCode(ctx context.Context, code string) (*model.Menu, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.menusByCode, &permissionHotCache.menuCodeFlights, code,
		func() (*model.Menu, error) { return findMenuByCode(ctx, code) })
	return cloneMenu(value), err
}

func cachedMenus(ctx context.Context) ([]*model.Menu, error) {
	value, err := loadCached(permissionHotCache, permissionHotCache.menuLists, &permissionHotCache.menuListFlights, "all",
		func() ([]*model.Menu, error) { return listMenus(ctx) })
	return cloneMenus(value), err
}
