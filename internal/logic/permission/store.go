// Package service 提供权限系统的应用服务、鉴权引擎和运行时缓存。
//
// Application 是对外服务入口;Store 只保存从 MySQL 加载出来的运行时快照,
// 供鉴权、委派、视图查询和写业务服务共同读取。
package permission

import (
	"sort"
	"strconv"
	"sync"

	"security-permission/internal/model"
)

// Store 是运行时读模型,只负责保存 MySQL 快照和用户有效权限缓存。
//
// 业务入口不要直接依赖 Store;应从 RoleService、UserService、PermissionService、ViewService 等服务进入。
type Store struct {
	mu sync.RWMutex

	// 从 MySQL 加载的领域数据,供鉴权和界面服务读取。
	areas     map[int]*model.Area
	orgs      map[int]*model.Org
	menus     map[int]*model.Menu
	resources map[int]*model.Resource
	actions   []model.Action
	roles     map[int]*model.Role
	users     map[string]*model.User

	// 按用户缓存的有效权限快照。版本号防止并发重载前构建的旧快照在权限变化后写回缓存。
	permVersion uint64
	permCache   map[string]*effectivePermission
}

func newStore() *Store {
	return &Store{
		areas:     map[int]*model.Area{},
		orgs:      map[int]*model.Org{},
		menus:     map[int]*model.Menu{},
		resources: map[int]*model.Resource{},
		roles:     map[int]*model.Role{},
		users:     map[string]*model.User{},
		permCache: map[string]*effectivePermission{},
	}
}

func (s *Store) invalidatePermissionsLocked() {
	s.permVersion++
	s.permCache = map[string]*effectivePermission{}
}

// ---------- 读取(返回有序切片,便于前端展示) ----------

// Areas 返回全部区域,按 ID 排序,主要给元数据接口和前端字典使用。
func (s *Store) Areas() []*model.Area {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Area, 0, len(s.areas))
	for _, a := range s.areas {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

func userIDLess(a, b string) bool {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		return ai < bi
	}
	return a < b
}

// Orgs 返回全部组织,按 ID 排序。
func (s *Store) Orgs() []*model.Org {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Org, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

// Menus 返回数据库菜单副本。
// 前后端用 code 交互;role_menu 内部仍保存 menu_id,便于数据库关联。
func (s *Store) Menus() []*model.Menu {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Menu, 0, len(s.menus))
	for _, m := range s.menus {
		item := *m
		out = append(out, &item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sort != out[j].Sort {
			return out[i].Sort < out[j].Sort
		}
		return out[i].Id < out[j].Id
	})
	return out
}

// MenuIdsByCodes 把接口传入的菜单 code 转成数据库内部 menu_id。
// 返回 missing 便于接口给出清晰错误,避免静默丢权限。
func (s *Store) MenuIdsByCodes(codes []string) (ids []int, missing []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byCode := make(map[string]int, len(s.menus))
	for _, menu := range s.menus {
		byCode[menu.Code] = menu.Id
	}
	seen := map[int]bool{}
	for _, code := range codes {
		id := byCode[code]
		if id == 0 {
			missing = append(missing, code)
			continue
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids, missing
}

// Resources 返回全部业务资源,按 ID 排序。
func (s *Store) Resources() []*model.Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Resource, 0, len(s.resources))
	for _, r := range s.resources {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

// Actions 返回资源操作字典,例如实时预览、远程回放、图片查询。
func (s *Store) Actions() []model.Action {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Action(nil), s.actions...)
}

// Roles 返回全部角色,按 ID 排序。
// 普通用户能不能看到某个角色,由 RoleService.List 统一过滤。
func (s *Store) Roles() []*model.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

// Users 返回全部用户,按 ID 排序。
func (s *Store) Users() []*model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return userIDLess(out[i].Id, out[j].Id) })
	return out
}

// Role 按 ID 读取单个角色;不存在时返回 nil。
func (s *Store) Role(id int) *model.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roles[id]
}

// User 按 ID 读取单个用户;不存在时返回 nil。
func (s *Store) User(id string) *model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

// AreaById 按 ID 读取区域;写操作做数据权限校验时会用到。
func (s *Store) AreaById(id int) *model.Area {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.areas[id]
}

// OrgById 按 ID 读取组织。
func (s *Store) OrgById(id int) *model.Org {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.orgs[id]
}

// ResourceById 按 ID 读取业务资源。
func (s *Store) ResourceById(id int) *model.Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resources[id]
}

func (s *Store) area(id int) *model.Area         { return s.areas[id] }
func (s *Store) org(id int) *model.Org           { return s.orgs[id] }
func (s *Store) resource(id int) *model.Resource { return s.resources[id] }
