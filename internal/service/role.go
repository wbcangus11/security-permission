package service

// 角色删除:写时鉴权 + 级联清理引用。
//
// 鉴权规则(委派语义,与已实测的模型 A 自洽):
//   不受限(actorId<=0,即"系统管理员")或超级管理员:可删任意角色;
//   普通操作人(委派者):
//     功能关——须有「角色管理」菜单(sys.person.role);
//     委派关——只能删除自己创建的角色(role.created_by == actorId)。
//   说明:种子/系统创建的角色 created_by=0,普通操作人删不了,只有不受限/超管能删。
//
// 删除策略(对齐用户约定):角色即便仍绑着用户也直接删,不拦。
//   级联清理:role 主表 + role_menu + role_data_scope + role_resource_action + user_role。
//   绑定被清后,丢了该角色的用户即失去这部分权限;若不再有其他角色,登录后即无任何权限。

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

// menuRoleManage 角色管理菜单 code(角色写操作的功能关)。
const menuRoleManage = "sys.person.role"

// DeleteRole 删除角色(委派校验 + 级联清理引用),成功后刷新缓存。
// actorId=操作人,<=0 表示不受限(系统管理员)。
func (s *Store) DeleteRole(ctx context.Context, actorId, roleId int) error {
	target := s.Role(roleId)
	if target == nil {
		return gerror.New("角色不存在")
	}
	// 委派校验:不受限/超管放行;否则功能关 + 仅能删自己创建的
	if actorId > 0 {
		actor := s.User(actorId)
		if actor == nil {
			return gerror.New("操作人不存在")
		}
		if !actor.IsSuperuser {
			if d := s.CheckMenu(actor, menuRoleManage); !d.Allow {
				return gerror.New("功能权限不足:" + d.Reason)
			}
			if target.CreatedBy != actorId {
				return gerror.New("只能删除自己创建的角色「" + target.Name + "」")
			}
		}
	}
	err := g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 先清关联(含 user_role 绑定),再删主表
		for _, t := range []string{"role_menu", "role_data_scope", "role_resource_action", "user_role"} {
			if _, err := tx.Model(t).Ctx(ctx).Where("role_id", roleId).Delete(); err != nil {
				return err
			}
		}
		_, err := tx.Model("role").Ctx(ctx).Where("id", roleId).Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.Reload(ctx)
}
