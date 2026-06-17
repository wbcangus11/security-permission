package service

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
)

const menuRoleManage = "sys.person.role"

func (s *Store) DeleteRole(ctx context.Context, actorId, roleId int) error {
	if s.Role(roleId) == nil {
		return gerror.New("角色不存在")
	}
	if err := s.GuardManageRole(actorId, roleId); err != nil {
		return err
	}

	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
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
	return s.Reload(ctx)
}

func (s *Store) GuardManageRole(actorId, roleId int) error {
	if actorId <= 0 {
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
