package service

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
)

// DeleteRole 删除角色并清理所有引用。
// 角色即使已经绑定用户也允许删除;删除后 user_role 会被清掉,用户自然失去该角色带来的权限。
// actorId 是当前用户 ID 的历史命名,实际项目应从 token/context 取得。
func (s *Store) DeleteRole(ctx context.Context, actorId string, roleId int) error {
	if s.Role(roleId) == nil {
		return gerror.New("角色不存在")
	}
	if err := s.GuardManageRole(actorId, roleId); err != nil {
		return err
	}

	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 没启用数据库外键级联,所以服务层显式清理所有以 role_id 指向该角色的关联表。
		// 角色删除后绑定用户会自然失去该角色权限,不做“仍绑定就禁止删除”的拦截。
		for _, item := range []struct {
			table  string
			column string
		}{
			{dao.RoleMenu.Table(), dao.RoleMenu.Columns().RoleId},
			{dao.RoleDataScope.Table(), dao.RoleDataScope.Columns().RoleId},
			{dao.RoleResourceAction.Table(), dao.RoleResourceAction.Columns().RoleId},
			{dao.UserRole.Table(), dao.UserRole.Columns().RoleId},
		} {
			if _, err := tx.Model(item.table).Ctx(ctx).Where(item.column, roleId).Delete(); err != nil {
				return err
			}
		}
		// 兼容历史版本的显式角色范围(scope_type=ROLE):删除被引用角色时同步清掉悬挂引用。
		if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
			Where(dao.RoleDataScope.Columns().ScopeType, "ROLE").
			Where(dao.RoleDataScope.Columns().NodeId, roleId).
			Delete(); err != nil {
			return err
		}
		_, err := tx.Model(dao.Role.Table()).Ctx(ctx).Where(dao.Role.Columns().Id, roleId).Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.reloadRolesAndUsers(ctx)
}

// GuardManageRole 是编辑/删除角色的统一门禁。
// 普通用户必须有“角色管理”菜单,且目标角色必须是自己创建的;超级管理员不受限制。
func (s *Store) GuardManageRole(actorId string, roleId int) error {
	if isUnrestrictedActor(actorId) {
		return nil
	}
	actor := s.User(actorId)
	if actor == nil {
		return gerror.New("操作人不存在")
	}
	if actor.IsSuperuser {
		return nil
	}
	if d := s.CheckMenu(actor, menuRoleManage); !d.Allow {
		return gerror.New("功能权限不足:" + d.Reason)
	}
	if set, unlimited := s.OwnedRoles(actorId); !unlimited && !set[roleId] {
		name := ""
		if target := s.Role(roleId); target != nil {
			name = target.Name
		}
		return gerror.New("无权管理角色「" + name + "」:仅可编辑/删除自己创建的角色")
	}
	return nil
}
