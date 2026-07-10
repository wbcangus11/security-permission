package permission

import (
	"context"
	"fmt"
	"strings"

	"security-permission/internal/model"
)

// Application 是服务层的统一入口。
//
// Store 只保存运行时数据快照;业务方法挂到下面这些服务类型上,
// 避免 Store 继续变成分散在各文件里的万能对象。
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

// NewApplication 组装当前进程内的服务层对象图。
//
// 所有服务共享同一个 Store 快照;PermissionService 单独复用,因为鉴权、委派、
// 写业务校验和视图查询都要使用同一套“当前用户有效权限”计算。
func NewApplication() *Application {
	store := newStore()
	permission := &PermissionService{Store: store}
	return &Application{
		Runtime:   &RuntimeService{PermissionService: permission},
		Auth:      permission,
		Delegate:  permission,
		Roles:     &RoleService{Store: store, PermissionService: permission},
		Users:     &UserService{Store: store, PermissionService: permission},
		Areas:     &AreaService{Store: store, PermissionService: permission},
		Orgs:      &OrgService{Store: store, PermissionService: permission},
		Resources: &ResourceService{Store: store, PermissionService: permission},
		Views:     &ViewService{Store: store, PermissionService: permission},
	}
}

// Reload 保留给包内旧测试和临时脚本使用;业务入口应优先调用 S.Runtime.Reload。
func (a *Application) Reload(ctx context.Context) error {
	return a.Runtime.Reload(ctx)
}

func (a *Application) menuByCode(code string) *model.Menu {
	return a.Auth.menuByCode(code)
}

// RuntimeService 提供元数据读取和缓存重载入口。
// 它直接嵌入 Store,但只用于运行时快照读写,不承载业务规则。
type RuntimeService struct {
	*PermissionService
}

// PermissionService 承载只读权限计算和受控委派计算。
//
// AuthService 与 DelegationService 是同一个实现类型的两个入口名:
// HTTP 层按语义读起来分别是“鉴权”和“委派”,内部共享同一套权限计算辅助方法。
type PermissionService struct {
	*Store
}

type AuthService = PermissionService
type DelegationService = PermissionService

// RoleService 承载角色管理写业务。
//
// 它负责把接口提交的菜单 code 转为 menu_id、保持 created_by 语义、
// 调用 PermissionService 做受控委派合并,最后才调用 Store.SaveRole 落库。
type RoleService struct {
	*Store
	*PermissionService
}

// RoleSaveResult 是角色保存类接口的统一返回。
// Preserved 表示本次保存中因操作者当前无权修改而保留的旧权限数量。
type RoleSaveResult struct {
	Role      *model.Role
	Preserved int
}

// List 返回全部角色;角色对当前用户是否可见由前端和委派接口再过滤。
func (r *RoleService) List() []*model.Role {
	return r.Roles()
}

// Get 读取单个角色详情;不存在返回 nil。
func (r *RoleService) Get(id int) *model.Role {
	return r.Role(id)
}

// SaveBasic 保存角色基础权限。
//
// 这个入口对应 /api/role/save:先把菜单 code 转为 menu_id,再区分新建/编辑;
// 编辑时保持 created_by 不变,最后走受控委派合并并落库。
func (r *RoleService) SaveBasic(ctx context.Context, actorId string, role *model.Role) (*RoleSaveResult, error) {
	role.Name = strings.TrimSpace(role.Name)
	if role.Name == "" {
		return nil, fmt.Errorf("角色名称不能为空")
	}
	for _, existing := range r.Roles() {
		if existing.Name == role.Name && existing.Id != role.Id {
			return nil, fmt.Errorf("角色名称已存在:%s", role.Name)
		}
	}
	ids, missing := r.MenuIdsByCodes(role.MenuCodes)
	if len(missing) > 0 {
		return nil, fmt.Errorf("菜单权限码不存在:%s", strings.Join(missing, ","))
	}
	role.MenuIds = ids

	old := r.Role(role.Id)
	if role.Id > 0 && old == nil {
		return nil, fmt.Errorf("角色不存在")
	}
	if old != nil {
		if err := r.GuardManageRole(actorId, role.Id); err != nil {
			return nil, err
		}
		role.CreatedBy = old.CreatedBy
	} else {
		// Creating a delegated role is itself a role-management operation. The
		// submitted permission set is still narrowed by MergeDelegated below.
		if err := r.guardRoleWriter(actorId); err != nil {
			return nil, err
		}
		role.CreatedBy = actorId
	}

	merged, preserved := r.MergeDelegated(actorId, old, role)
	saved, err := r.SaveRole(ctx, merged)
	if err != nil {
		return nil, err
	}
	return &RoleSaveResult{Role: saved, Preserved: preserved}, nil
}

// UserService 承载账号管理写业务。
// 保存账号时会同时校验账号管理菜单、组织数据范围和可分配角色集合。
type UserService struct {
	*Store
	*PermissionService
}

// List 返回全部用户;前端按当前管理界面需要展示。
func (u *UserService) List() []*model.User { return u.Users() }

// Get 读取单个用户详情;不存在返回 nil。
func (u *UserService) Get(id string) *model.User { return u.User(id) }

// AreaService 承载安保区域树写业务。
// 新增、移动、删除都要维护物化路径 path,并在删除时清理授权引用。
type AreaService struct {
	*Store
	*PermissionService
}

// OrgService 承载组织树写业务。
// 它与 AreaService 共用同一套 path 维护思路,但删除前置检查的是子组织和下属用户。
type OrgService struct {
	*Store
	*PermissionService
}

// ResourceService 承载摄像头等业务资源写业务。
// 资源挂在区域下,写操作同时校验资源管理菜单和所在区域管理权限。
type ResourceService struct {
	*Store
	*PermissionService
}

// ViewService 承载前端视图查询。
// 它把鉴权结果包装成树、详情、分页列表等 UI 需要的数据形状。
type ViewService struct {
	*Store
	*PermissionService
}
