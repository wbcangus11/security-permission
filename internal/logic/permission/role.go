package permission

import (
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// List 返回当前用户可见的角色。普通用户需要角色管理功能且只能看自建角色,超级管理员可看全部。
func (s *RoleService) List(actorID string) []*model.Role {
	actor := s.User(actorID)
	if actor == nil {
		return []*model.Role{}
	}
	if !actor.IsSuperuser && !s.CheckMenu(actor, menuRoleManage).Allow {
		return []*model.Role{}
	}
	visible, unlimited := s.ManageableRoles(actorID)
	roles := s.Roles()
	if unlimited {
		return roles
	}
	out := make([]*model.Role, 0, len(visible))
	for _, role := range roles {
		if visible[role.Id] {
			out = append(out, role)
		}
	}
	return out
}

// Get 返回当前用户可见的角色详情。
func (s *RoleService) Get(actorID string, roleID int) (*model.Role, error) {
	for _, role := range s.List(actorID) {
		if role.Id == roleID {
			return role, nil
		}
	}
	if s.Role(roleID) == nil {
		return nil, gerror.New("角色不存在")
	}
	return nil, gerror.New("无权查看该角色")
}

// Delete 删除角色并清理所有引用。
// 角色即使已经绑定用户也允许删除;删除后 user_role 会被清掉,用户自然失去该角色带来的权限。
func (s *RoleService) Delete(ctx context.Context, actorId string, roleId int) error {
	// 第一步先确认目标存在，避免后面的权限判断和事务删除对空角色产生误导性结果。
	if s.Role(roleId) == nil {
		return gerror.New("角色不存在")
	}
	// 删除角色走和编辑角色相同的门禁：有角色管理菜单，并且普通用户只能操作自己创建的角色。
	if err := s.GuardManageRole(actorId, roleId); err != nil {
		return err
	}

	// 当前 schema 通过外键级联清理 role_menu、role_data_scope 和 user_role。
	_, err := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, roleId).Delete()
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
	if s.User(actorId).IsSuperuser {
		return nil
	}
	// 委派边界：普通用户只能编辑/删除自己创建的角色，避免通过角色列表接触到别人创建的高权限角色。
	if set, unlimited := s.ManageableRoles(actorId); !unlimited && !set[roleId] {
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
