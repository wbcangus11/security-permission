package permission

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/middleware"
	"security-permission/internal/model"
)

// permissionFacts 是 Repository 一次批量查回来的权限事实。
// 它只负责装数据，不在这里做任何放行或拒绝判断。
type permissionFacts struct {
	user       *model.User
	roles      []*model.Role
	scopePaths map[string]map[int]string
}

// permissionSnapshot 是按用户缓存的只读权限结果。
// 命中缓存后，菜单和树范围判断都只看内存，不会判断到一半又偷偷查库。
type permissionSnapshot struct {
	user       *model.User
	roles      []*model.Role
	menuCodes  map[string]bool
	filters    map[string]treeFilter
	scopePaths map[string]map[int]string
}

func loadPermissionSnapshot(ctx context.Context) (*permissionSnapshot, error) {
	userID := middleware.GetUserId(ctx)
	if userID == "" {
		return nil, gerror.NewCode(gcode.CodeNotAuthorized, "未获取到当前用户")
	}
	if userID == "0" {
		return nil, gerror.NewCode(gcode.CodeNotAuthorized, "系统内置身份不能登录")
	}

	for {
		snapshot, token, ok := permissionSnapshots.get(userID)
		if ok {
			return snapshot, nil
		}

		facts, err := loadPermissionFacts(ctx, userID)
		if err != nil {
			return nil, err
		}
		if facts == nil || facts.user == nil {
			return nil, gerror.NewCode(gcode.CodeNotAuthorized, "当前用户不存在或已失效")
		}
		snapshot = newPermissionSnapshot(facts)
		if permissionSnapshots.put(userID, token, snapshot) {
			return snapshot, nil
		}

		// 查库期间权限刚好被改了，这份结果不能继续用，重新加载最新权限。
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func newPermissionSnapshot(facts *permissionFacts) *permissionSnapshot {
	snapshot := &permissionSnapshot{
		user:      facts.user,
		roles:     facts.roles,
		menuCodes: map[string]bool{},
		filters: map[string]treeFilter{
			treeKindArea:    {None: true},
			treeKindOrg:     {None: true},
			treeKindResArea: {None: true},
		},
		scopePaths: map[string]map[int]string{
			treeKindArea:    {},
			treeKindOrg:     {},
			treeKindResArea: {},
		},
	}
	if facts.user.IsSuperuser {
		snapshot.filters[treeKindArea] = treeFilter{All: true}
		snapshot.filters[treeKindOrg] = treeFilter{All: true}
		snapshot.filters[treeKindResArea] = treeFilter{All: true}
		return snapshot
	}

	for _, role := range facts.roles {
		for _, code := range role.MenuConfigCodes {
			snapshot.menuCodes[code] = true
		}
		for _, code := range role.MenuAppCodes {
			snapshot.menuCodes[code] = true
		}
	}

	for _, kind := range []string{treeKindArea, treeKindOrg, treeKindResArea} {
		filter := treeFilter{}
		for _, role := range snapshot.roles {
			for _, scope := range roleScopes(role, kind) {
				path := facts.scopePaths[kind][scope.NodeId]
				if path == "" {
					continue
				}
				snapshot.scopePaths[kind][scope.NodeId] = path
				addScopeToFilter(&filter, scope, path)
			}
		}
		filter.None = len(filter.Prefixes) == 0 && len(filter.ExactIds) == 0
		snapshot.filters[kind] = filter
	}
	return snapshot
}

func loadAuthorizedSnapshot(
	ctx context.Context,
	menuCodes ...string,
) (*permissionSnapshot, error) {
	snapshot, err := loadPermissionSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err := snapshot.requireAnyMenu(menuCodes...); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (s *permissionSnapshot) isSuper() bool {
	return s != nil && s.user != nil && s.user.IsSuperuser
}

func (s *permissionSnapshot) hasMenu(code string) bool {
	return s != nil && (s.isSuper() || s.menuCodes[code])
}

func (s *permissionSnapshot) hasAnyMenu(codes ...string) bool {
	for _, code := range codes {
		if s.hasMenu(code) {
			return true
		}
	}
	return false
}

// requireAnyMenu 是 service 入口的功能权限门。
// 数据范围管“能看哪些数据”，菜单权限管“能不能用这个接口”，两件事分开判断更直白。
func (s *permissionSnapshot) requireAnyMenu(codes ...string) error {
	if s == nil || s.user == nil {
		return gerror.NewCode(gcode.CodeNotAuthorized, "当前用户不存在或已失效")
	}
	if s.hasAnyMenu(codes...) {
		return nil
	}
	return gerror.NewCode(gcode.CodeNotAuthorized, "功能权限不足")
}

func (s *permissionSnapshot) treeFilter(kind string) treeFilter {
	if s == nil {
		return treeFilter{None: true}
	}
	filter, ok := s.filters[kind]
	if !ok {
		return treeFilter{None: true}
	}
	return filter
}

func (s *permissionSnapshot) covers(kind, path string, id int) bool {
	return s.treeFilter(kind).covers(path, id)
}

// canGrantScope 会把“能看这个点”和“能把整棵子树授出去”区分开。
// 自己只有单点权限时，只能继续授单点，不能把权限偷偷放大成整棵子树。
func (s *permissionSnapshot) canGrantScope(kind, path string, scope model.DataScope) bool {
	if s.isSuper() {
		return true
	}
	filter := s.treeFilter(kind)
	if scope.IncludeChild {
		return filter.underPrefix(path)
	}
	return filter.covers(path, scope.NodeId)
}

func (s *permissionSnapshot) roleScopePath(kind string, nodeID int) string {
	if s == nil {
		return ""
	}
	return s.scopePaths[kind][nodeID]
}

// areaAutoGrantRole 只处理一个特殊情况：管理员只有父节点单点权限时，
// 新建子节点要顺手把这个子节点补到同一个角色里，不然刚创建完自己反而看不见。
func (s *permissionSnapshot) areaAutoGrantRole(parent *model.Area) int {
	if s == nil || parent == nil || s.isSuper() {
		return 0
	}
	candidate := 0
	for _, role := range s.roles {
		for _, scope := range role.AreaScopes {
			scopePath := s.roleScopePath(treeKindArea, scope.NodeId)
			if scopePath == "" {
				continue
			}
			covered := scope.NodeId == parent.Id ||
				(scope.IncludeChild && strings.HasPrefix(parent.Path, scopePath))
			if !covered {
				continue
			}
			if scope.IncludeChild {
				return 0
			}
			if candidate == 0 {
				candidate = role.Id
			}
		}
	}
	return candidate
}
