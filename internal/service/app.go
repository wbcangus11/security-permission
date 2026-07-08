package service

import (
	"context"
	"fmt"
	"strings"

	"security-permission/internal/model"
)

// Application 是服务层的统一入口。
//
// Store 只保存运行时数据快照;业务代码从这里按职责进入对应服务,
// 避免 HTTP 层继续把所有操作都当成 Store 方法调用。
type Application struct {
	Runtime   *RuntimeService
	Auth      *AuthService
	Delegate  *DelegationService
	Roles     *RoleService
	Users     *UserService
	Areas     *AreaService
	Orgs      *OrgService
	Resources *ResourceService
	Views     *ViewService
}

// S 是当前进程的服务层单例。启动时先调用 S.Runtime.Reload(ctx)。
var S = NewApplication()

func NewApplication() *Application {
	store := newStore()
	return &Application{
		Runtime:   &RuntimeService{store: store},
		Auth:      &AuthService{store: store},
		Delegate:  &DelegationService{store: store},
		Roles:     &RoleService{store: store},
		Users:     &UserService{store: store},
		Areas:     &AreaService{store: store},
		Orgs:      &OrgService{store: store},
		Resources: &ResourceService{store: store},
		Views:     &ViewService{store: store},
	}
}

// Reload 保留给包内旧测试和临时脚本使用;业务入口应优先调用 S.Runtime.Reload。
func (a *Application) Reload(ctx context.Context) error {
	return a.Runtime.Reload(ctx)
}

func (a *Application) menuByCode(code string) *model.Menu {
	return a.Runtime.store.menuByCode(code)
}

type RuntimeService struct {
	store *Store
}

func (r *RuntimeService) Reload(ctx context.Context) error { return r.store.Reload(ctx) }
func (r *RuntimeService) Areas() []*model.Area             { return r.store.Areas() }
func (r *RuntimeService) Orgs() []*model.Org               { return r.store.Orgs() }
func (r *RuntimeService) Menus() []*model.Menu             { return r.store.Menus() }
func (r *RuntimeService) Resources() []*model.Resource     { return r.store.Resources() }
func (r *RuntimeService) Actions() []model.Action          { return r.store.Actions() }
func (r *RuntimeService) Roles() []*model.Role             { return r.store.Roles() }
func (r *RuntimeService) Users() []*model.User             { return r.store.Users() }
func (r *RuntimeService) Role(id int) *model.Role          { return r.store.Role(id) }
func (r *RuntimeService) User(id string) *model.User       { return r.store.User(id) }

type AuthService struct {
	store *Store
}

func (a *AuthService) CheckMenu(u *model.User, menuCode string) *Decision {
	return a.store.CheckMenu(u, menuCode)
}

func (a *AuthService) CheckArea(u *model.User, areaId int) *Decision {
	return a.store.CheckArea(u, areaId)
}

func (a *AuthService) CheckOrg(u *model.User, orgId int) *Decision {
	return a.store.CheckOrg(u, orgId)
}

func (a *AuthService) CheckResource(u *model.User, resourceId int, actionCode string) *Decision {
	return a.store.CheckResource(u, resourceId, actionCode)
}

type DelegationService struct {
	store *Store
}

func (d *DelegationService) GrantableSet(actorId string) *Grantable {
	return d.store.GrantableSet(actorId)
}

func (d *DelegationService) RoleAreaChildren(ctx context.Context, actorId string, parentId int, kind string) []RoleTreeNode {
	return d.store.RoleAreaChildren(ctx, actorId, parentId, kind)
}

type RoleService struct {
	store *Store
}

type RoleSaveResult struct {
	Role      *model.Role
	Preserved int
}

type RoleResourcePermission struct {
	RoleId            int                    `json:"roleId"`
	ResourceActions   []model.ResourceAction `json:"resourceActions"`
	ResourceOverrides []int                  `json:"resourceOverrides"`
}

func (r *RoleService) List() []*model.Role {
	return r.store.Roles()
}

func (r *RoleService) Get(id int) *model.Role {
	return r.store.Role(id)
}

// SaveBasic 保存角色基础权限。
//
// 这个入口对应 /api/role/save:先把菜单 code 转为 menu_id,再区分新建/编辑;
// 编辑时保持 created_by 和资源精细授权不变,最后走受控委派合并并落库。
func (r *RoleService) SaveBasic(ctx context.Context, actorId string, role *model.Role) (*RoleSaveResult, error) {
	ids, missing := r.store.MenuIdsByCodes(role.MenuCodes)
	if len(missing) > 0 {
		return nil, fmt.Errorf("菜单权限码不存在:%s", strings.Join(missing, ","))
	}
	role.MenuIds = ids

	old := r.store.Role(role.Id)
	if old != nil {
		if err := r.store.GuardManageRole(actorId, role.Id); err != nil {
			return nil, err
		}
		role.CreatedBy = old.CreatedBy
		role.ResourceActions = old.ResourceActions
		role.ResourceOverrides = old.ResourceOverrides
	} else {
		role.CreatedBy = actorId
	}

	merged, preserved := r.store.MergeDelegated(actorId, old, role)
	saved, err := r.store.SaveRole(ctx, merged)
	if err != nil {
		return nil, err
	}
	return &RoleSaveResult{Role: saved, Preserved: preserved}, nil
}

func (r *RoleService) Delete(ctx context.Context, actorId string, roleId int) error {
	return r.store.DeleteRole(ctx, actorId, roleId)
}

func (r *RoleService) ResourcePermission(actorId string, roleId int) (*RoleResourcePermission, error) {
	role := r.store.Role(roleId)
	if role == nil {
		return nil, fmt.Errorf("角色不存在")
	}
	if err := r.store.GuardManageRole(actorId, roleId); err != nil {
		return nil, err
	}
	return &RoleResourcePermission{
		RoleId:            role.Id,
		ResourceActions:   role.ResourceActions,
		ResourceOverrides: role.ResourceOverrides,
	}, nil
}

// SaveResourcePermission 只保存角色的资源级精细操作授权。
//
// 菜单和三类树范围沿用旧值,避免“单独配置资源权限”时误改角色基础权限。
func (r *RoleService) SaveResourcePermission(ctx context.Context, actorId string, roleId int, actions []model.ResourceAction, overrides []int) (*RoleSaveResult, error) {
	old := r.store.Role(roleId)
	if old == nil {
		return nil, fmt.Errorf("角色不存在")
	}
	if err := r.store.GuardManageRole(actorId, roleId); err != nil {
		return nil, err
	}
	merged, preserved := r.store.MergeResourcePermissionDelegated(actorId, old, actions, overrides)
	saved, err := r.store.SaveRole(ctx, merged)
	if err != nil {
		return nil, err
	}
	return &RoleSaveResult{Role: saved, Preserved: preserved}, nil
}

type UserService struct {
	store *Store
}

func (u *UserService) List() []*model.User       { return u.store.Users() }
func (u *UserService) Get(id string) *model.User { return u.store.User(id) }
func (u *UserService) SaveManaged(ctx context.Context, actorId string, user *model.User) (*model.User, error) {
	return u.store.SaveUserManaged(ctx, actorId, user)
}
func (u *UserService) Delete(ctx context.Context, actorId, userId string) error {
	return u.store.DeleteUser(ctx, actorId, userId)
}

type AreaService struct {
	store *Store
}

func (a *AreaService) Save(ctx context.Context, actorId string, in *AreaSaveInput) (*model.Area, error) {
	return a.store.SaveArea(ctx, actorId, in)
}

func (a *AreaService) Reorder(ctx context.Context, actorId string, in *AreaReorderInput) error {
	return a.store.ReorderArea(ctx, actorId, in)
}

func (a *AreaService) Delete(ctx context.Context, actorId string, areaId int) error {
	return a.store.DeleteArea(ctx, actorId, areaId)
}

type OrgService struct {
	store *Store
}

func (o *OrgService) Save(ctx context.Context, actorId string, in *OrgSaveInput) (*model.Org, error) {
	return o.store.SaveOrg(ctx, actorId, in)
}

func (o *OrgService) Delete(ctx context.Context, actorId string, orgId int) error {
	return o.store.DeleteOrg(ctx, actorId, orgId)
}

type ResourceService struct {
	store *Store
}

func (r *ResourceService) Save(ctx context.Context, actorId string, in *ResourceSaveInput) (*model.Resource, error) {
	return r.store.SaveResource(ctx, actorId, in)
}

func (r *ResourceService) Delete(ctx context.Context, actorId string, resourceId int) error {
	return r.store.DeleteResource(ctx, actorId, resourceId)
}

type ViewService struct {
	store *Store
}

func (v *ViewService) AppMenus(userId string) []*model.Menu {
	return v.store.AppMenus(userId)
}

func (v *ViewService) VisibleAreas(userId string) []VisibleArea {
	return v.store.VisibleAreas(userId)
}

func (v *ViewService) AreaChildren(ctx context.Context, userId string, parentId, page, size int) *PagedAreas {
	return v.store.AreaChildren(ctx, userId, parentId, page, size)
}

func (v *ViewService) SearchAreas(ctx context.Context, userId string, q, scope string, page, size int) *PagedAreas {
	return v.store.SearchAreas(ctx, userId, q, scope, page, size)
}

func (v *ViewService) AreaResourcesPaged(ctx context.Context, userId string, areaId, page, size int) *AreaResourcesPage {
	return v.store.AreaResourcesPaged(ctx, userId, areaId, page, size)
}

func (v *ViewService) SysMenus(userId string) []*model.Menu {
	return v.store.SysMenus(userId)
}

func (v *ViewService) ManageAreas(userId string) []VisibleArea {
	return v.store.ManageAreas(userId)
}

func (v *ViewService) ManageAreaChildren(ctx context.Context, userId string, parentId, page, size int) *PagedAreas {
	return v.store.ManageAreaChildren(ctx, userId, parentId, page, size)
}

func (v *ViewService) ManageAreaDetail(ctx context.Context, userId string, areaId int) *ManageDetail {
	return v.store.ManageAreaDetail(ctx, userId, areaId)
}

func (v *ViewService) ManageOrgs(userId string) []VisibleArea {
	return v.store.ManageOrgs(userId)
}

func (v *ViewService) ManageOrgDetail(userId string, orgId int) *ManageDetail {
	return v.store.ManageOrgDetail(userId, orgId)
}
