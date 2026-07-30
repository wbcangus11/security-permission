package permission

import (
	"context"

	"security-permission/internal/model"
)

// ScopeKind 说明要检查哪一棵权限树。
type ScopeKind string

const (
	ScopeArea         ScopeKind = treeKindArea
	ScopeOrg          ScopeKind = treeKindOrg
	ScopeResourceArea ScopeKind = treeKindResArea
)

// Access 是 permission 包给其他业务使用的只读鉴权对象。
// 调用方只看这些方法，不需要知道缓存和快照里面怎么存。
type Access struct {
	snapshot *permissionSnapshot
}

// ForUser 返回 ctx 中当前用户可用的鉴权对象。
// 有缓存就直接复用，没缓存才回源数据库。
func ForUser(ctx context.Context) (*Access, error) {
	snapshot, err := loadPermissionSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return &Access{snapshot: snapshot}, nil
}

func (a *Access) User() *model.User {
	if a == nil || a.snapshot == nil || a.snapshot.user == nil {
		return nil
	}
	user := *a.snapshot.user
	user.RoleIds = append([]int{}, a.snapshot.user.RoleIds...)
	return &user
}

func (a *Access) IsSuperuser() bool {
	return a != nil && a.snapshot != nil && a.snapshot.isSuper()
}

func (a *Access) HasMenu(code string) bool {
	return a != nil && a.snapshot != nil && a.snapshot.hasMenu(code)
}

func (a *Access) HasAnyMenu(codes ...string) bool {
	return a != nil && a.snapshot != nil && a.snapshot.hasAnyMenu(codes...)
}

func (a *Access) RequireAnyMenu(codes ...string) error {
	var snapshot *permissionSnapshot
	if a != nil {
		snapshot = a.snapshot
	}
	return snapshot.requireAnyMenu(codes...)
}

func (a *Access) Covers(kind ScopeKind, path string, nodeID int) bool {
	return a != nil && a.snapshot != nil && a.snapshot.covers(string(kind), path, nodeID)
}
