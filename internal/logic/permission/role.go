package permission

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

func normalizeRoleInfo(name, description string) (string, string, error) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" {
		return "", "", fmt.Errorf("角色名称不能为空")
	}
	return name, description, nil
}

func guardRoleWriter(snapshot *permissionSnapshot) error {
	return snapshot.requireAnyMenu(menuRoleManage)
}

// guardManageRole 把“能进角色管理”和“这个角色归不归你管”放在一个地方判断。
// 普通管理员只能管理自己创建的角色，超级管理员不受这个限制。
func guardManageRole(ctx context.Context, snapshot *permissionSnapshot, roleID int) (*model.Role, error) {
	if err := guardRoleWriter(snapshot); err != nil {
		return nil, err
	}
	role, err := findRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, gerror.New("角色不存在")
	}
	if snapshot.isSuper() || role.CreatedBy == snapshot.user.Id {
		return role, nil
	}
	return nil, gerror.New("无权管理角色“" + role.Name + "”：普通管理员只能管理自己创建的角色")
}

// SaveRole 只保存请求里明确带来的改动。
// 没传 permissions 就只改名称和说明，没提交的权限域也原样保留。
func SaveRole(ctx context.Context, userID string, input *model.RoleSaveInput) (*model.Role, error) {
	if input == nil || input.RoleId < 0 {
		return nil, fmt.Errorf("角色保存参数无效")
	}
	name, description, err := normalizeRoleInfo(input.Name, input.Description)
	if err != nil {
		return nil, err
	}

	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return nil, err
	}

	old := &model.Role{}
	createdBy := snapshot.user.Id
	if input.RoleId > 0 {
		old, err = guardManageRole(ctx, snapshot, input.RoleId)
		if err != nil {
			return nil, err
		}
		createdBy = old.CreatedBy
	} else if err = guardRoleWriter(snapshot); err != nil {
		return nil, err
	}

	if exists, err := roleNameExists(ctx, name, input.RoleId); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("角色名称已存在：%s", name)
	}

	permissions, err := prepareRolePermissions(ctx, snapshot, old, input.Permissions)
	if err != nil {
		return nil, err
	}
	affectedUserIDs := []string{}
	if input.RoleId > 0 {
		affectedUserIDs, err = userIDsByRole(ctx, input.RoleId)
		if err != nil {
			return nil, err
		}
	}
	saved, err := saveRole(ctx, &model.Role{
		Id: input.RoleId, Name: name, Description: description, CreatedBy: createdBy,
	}, permissions)
	if err != nil {
		return nil, err
	}
	InvalidateUsers(affectedUserIDs...)

	// 如果改的是自己正在使用的角色，保存后权限可能已经变了，所以响应按新快照过滤。
	resultSnapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return nil, err
	}
	return roleDetailForEditor(ctx, resultSnapshot, saved)
}

// ListRoles 只返回列表真正要展示的字段，不在这里加载菜单和数据范围。
func ListRoles(ctx context.Context, userID string) ([]*model.RoleSummary, error) {
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := guardRoleWriter(snapshot); err != nil {
		return nil, err
	}

	out := []*model.RoleSummary{}
	query := dao.Role.Ctx(ctx).Fields(
		dao.Role.Columns().Id,
		dao.Role.Columns().Name,
		dao.Role.Columns().Description,
		dao.Role.Columns().CreatedBy,
	).Order(dao.Role.Columns().Id)
	if !snapshot.isSuper() {
		query = query.Where(dao.Role.Columns().CreatedBy, userID)
	}
	if err := query.Scan(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// roleDetailForEditor 只返回当前编辑人还能继续授出去的权限。
// 看不到的历史权限仍留在数据库里，保存时也不会被顺手删掉。
func roleDetailForEditor(
	ctx context.Context,
	snapshot *permissionSnapshot,
	role *model.Role,
) (*model.Role, error) {
	if snapshot == nil || role == nil {
		return nil, nil
	}
	out := &model.Role{
		Id: role.Id, Name: role.Name, Description: role.Description, CreatedBy: role.CreatedBy,
		MenuConfigCodes: []string{}, MenuAppCodes: []string{},
		AreaScopes: []model.DataScope{}, OrgScopes: []model.DataScope{}, ResourceAreaScopes: []model.DataScope{},
	}
	for _, code := range role.MenuConfigCodes {
		if snapshot.hasMenu(code) {
			out.MenuConfigCodes = append(out.MenuConfigCodes, code)
		}
	}
	for _, code := range role.MenuAppCodes {
		if snapshot.hasMenu(code) {
			out.MenuAppCodes = append(out.MenuAppCodes, code)
		}
	}

	appendGrantable := func(target *[]model.DataScope, kind string, scopes []model.DataScope) error {
		for _, scope := range scopes {
			path, _, err := findTreeNode(ctx, kind, scope.NodeId)
			if err != nil {
				return err
			}
			if path != "" && snapshot.canGrantScope(kind, path, scope) {
				*target = append(*target, scope)
			}
		}
		return nil
	}
	if err := appendGrantable(&out.AreaScopes, treeKindArea, role.AreaScopes); err != nil {
		return nil, err
	}
	if err := appendGrantable(&out.OrgScopes, treeKindOrg, role.OrgScopes); err != nil {
		return nil, err
	}
	if err := appendGrantable(&out.ResourceAreaScopes, treeKindResArea, role.ResourceAreaScopes); err != nil {
		return nil, err
	}
	return out, nil
}

func GetRole(ctx context.Context, userID string, roleID int) (*model.Role, error) {
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return nil, err
	}
	role, err := guardManageRole(ctx, snapshot, roleID)
	if err != nil {
		return nil, err
	}
	return roleDetailForEditor(ctx, snapshot, role)
}

func DeleteRole(ctx context.Context, userID string, roleID int) error {
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return err
	}
	if _, err := guardManageRole(ctx, snapshot, roleID); err != nil {
		return err
	}
	affectedUserIDs, err := userIDsByRole(ctx, roleID)
	if err != nil {
		return err
	}
	// 先记住受影响用户，再删角色；级联删除之后 user_role 已经查不到这些人了。
	if _, err = dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, roleID).Delete(); err != nil {
		return err
	}
	InvalidateUsers(affectedUserIDs...)
	return nil
}
