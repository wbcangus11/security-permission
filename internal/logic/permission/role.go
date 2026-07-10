package permission

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
)

// Delete 删除角色并清理所有引用。
// 角色即使已经绑定用户也允许删除;删除后 user_role 会被清掉,用户自然失去该角色带来的权限。
// actorId 是当前用户 ID 的历史命名,实际项目应从 token/context 取得。
func (s *RoleService) Delete(ctx context.Context, actorId string, roleId int) error {
	// 第一步先确认目标存在，避免后面的权限判断和事务删除对空角色产生误导性结果。
	if s.Role(roleId) == nil {
		return gerror.New("角色不存在")
	}
	// 删除角色走和编辑角色相同的门禁：有角色管理菜单，并且普通用户只能操作自己创建的角色。
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
		// 最后删主表。前面的关联清理全部成功后才真正移除角色，保证失败时事务整体回滚。
		_, err := tx.Model(dao.Role.Table()).Ctx(ctx).Where(dao.Role.Columns().Id, roleId).Delete()
		return err
	})
	if err != nil {
		return err
	}
	// 角色删除会影响角色列表、用户绑定和权限快照，所以必须同时刷新角色与用户缓存。
	return s.reloadRolesAndUsers(ctx)
}

// GuardManageRole 是编辑/删除角色的统一门禁。
// 普通用户必须有“角色管理”菜单,且目标角色必须是自己创建的;超级管理员不受限制。
func (s *RoleService) GuardManageRole(actorId string, roleId int) error {
	if err := s.guardRoleWriter(actorId); err != nil {
		return err
	}
	if isUnrestrictedActor(actorId) || s.User(actorId).IsSuperuser {
		return nil
	}
	// 委派边界：普通用户只能编辑/删除自己创建的角色，避免通过角色列表接触到别人创建的高权限角色。
	if set, unlimited := s.OwnedRoles(actorId); !unlimited && !set[roleId] {
		name := ""
		if target := s.Role(roleId); target != nil {
			name = target.Name
		}
		return gerror.New("无权管理角色「" + name + "」:仅可编辑/删除自己创建的角色")
	}
	return nil
}

// guardRoleWriter is the common function-permission gate for role creation,
// editing and deletion. Ownership checks are applied separately for existing roles.
func (s *RoleService) guardRoleWriter(actorId string) error {
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
	return nil
}
