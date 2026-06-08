// Package service 提供权限数据的内存存储与鉴权引擎。
//
// 这里用内存 map 模拟持久层,便于零依赖运行与前端联调;
// 后续接数据库时,只需把 Store 的读写换成 GoFrame 的 dao/gdb 实现即可,
// 鉴权引擎(auth.go)无需改动。
package service

import (
	"sort"
	"sync"

	"security-permission/internal/model"
)

// Store 内存数据仓库,读写加锁保证并发安全。
type Store struct {
	mu sync.RWMutex

	areas     map[int]*model.Area
	orgs      map[int]*model.Org
	menus     map[int]*model.Menu
	resources map[int]*model.Resource
	actions   []model.Action
	roles     map[int]*model.Role
	users     map[int]*model.User
}

// S 全局单例。数据从 MySQL 加载到内存缓存(读多写少),
// 写操作落库后调用 Reload 刷新缓存;鉴权逻辑(auth.go)始终读缓存,保持高性能。
// 启动时需调用 service.S.Reload(ctx) 初始化(见 internal/cmd/cmd.go)。
var S = &Store{
	areas:     map[int]*model.Area{},
	orgs:      map[int]*model.Org{},
	menus:     map[int]*model.Menu{},
	resources: map[int]*model.Resource{},
	roles:     map[int]*model.Role{},
	users:     map[int]*model.User{},
}

// ---------- 读取(返回有序切片,便于前端展示) ----------

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

func (s *Store) Menus() []*model.Menu {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Menu, 0, len(s.menus))
	for _, m := range s.menus {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

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

func (s *Store) Actions() []model.Action { return s.actions }

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

func (s *Store) Users() []*model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

func (s *Store) Role(id int) *model.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roles[id]
}

func (s *Store) User(id int) *model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

func (s *Store) AreaById(id int) *model.Area {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.areas[id]
}

func (s *Store) OrgById(id int) *model.Org {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.orgs[id]
}

func (s *Store) ResourceById(id int) *model.Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resources[id]
}

func (s *Store) area(id int) *model.Area     { return s.areas[id] }
func (s *Store) org(id int) *model.Org       { return s.orgs[id] }
func (s *Store) resource(id int) *model.Resource { return s.resources[id] }

