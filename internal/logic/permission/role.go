package permission

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

func SaveRole(ctx context.Context, userID string, role *model.Role) (*model.Role, int, error) {
	role.Name = strings.TrimSpace(role.Name)
	if role.Name == "" {
		return nil, 0, fmt.Errorf("角色名称不能为空")
	}
	if exists, err := roleNameExists(ctx, role.Name, role.Id); err != nil {
		return nil, 0, err
	} else if exists {
		return nil, 0, fmt.Errorf("角色名称已存在：%s", role.Name)
	}

	ids, missing, err := menuIDsByCodes(ctx, role.MenuCodes)
	if err != nil {
		return nil, 0, err
	}
	if len(missing) > 0 {
		return nil, 0, fmt.Errorf("菜单权限码不存在：%s", strings.Join(missing, ","))
	}
	role.MenuIds = ids

	ev := newEvaluator(ctx)
	old := ev.role(role.Id)
	if err := ev.err; err != nil {
		return nil, 0, err
	}
	if role.Id > 0 && old == nil {
		return nil, 0, fmt.Errorf("角色不存在")
	}
	if old != nil {
		if err := ev.guardManageRole(userID, role.Id); err != nil {
			return nil, 0, err
		}
		role.CreatedBy = old.CreatedBy
	} else {
		if err := ev.guardRoleWriter(userID); err != nil {
			return nil, 0, err
		}
		role.CreatedBy = userID
	}

	merged, preserved := ev.mergeDelegated(userID, old, role)
	if err := ev.err; err != nil {
		return nil, 0, err
	}
	saved, err := saveRole(ctx, merged)
	if err != nil {
		return nil, 0, err
	}
	return saved, preserved, nil
}

func (e *evaluator) guardRoleWriter(userID string) error {
	user := e.user(userID)
	if e.err != nil {
		return e.err
	}
	if user == nil {
		return gerror.New("操作人不存在")
	}
	if user.IsSuperuser {
		return nil
	}
	decision := e.checkMenu(user, menuRoleManage)
	if e.err != nil {
		return e.err
	}
	if !decision.Allow {
		return gerror.New("功能权限不足：" + decision.Reason)
	}
	return nil
}

func (e *evaluator) guardManageRole(userID string, roleID int) error {
	if err := e.guardRoleWriter(userID); err != nil {
		return err
	}
	user := e.user(userID)
	target := e.role(roleID)
	if e.err != nil {
		return e.err
	}
	if target == nil {
		return gerror.New("角色不存在")
	}
	if user.IsSuperuser || target.CreatedBy == userID {
		return nil
	}
	return gerror.New("无权管理角色“" + target.Name + "”：普通管理员只能管理自己创建的角色")
}

// List 返回当前用户可管理的角色。超级管理员查看全部，普通管理员只查看自己创建的角色。
func ListRoles(ctx context.Context, userID string) ([]*model.Role, error) {
	out := []*model.Role{}
	ev := newEvaluator(ctx)
	if err := ev.guardRoleWriter(userID); err != nil {
		// 列表接口保持“无权限即空列表”的既有行为；数据库错误仍向上传递。
		if ev.err != nil {
			return nil, ev.err
		}
		return out, nil
	}
	user := ev.user(userID)
	query := dao.Role.Ctx(ctx).Fields(dao.Role.Columns().Id).Order(dao.Role.Columns().Id)
	if !user.IsSuperuser {
		query = query.Where(dao.Role.Columns().CreatedBy, userID)
	}
	var rows []struct{ Id int }
	if err := query.Scan(&rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if role := ev.role(row.Id); role != nil {
			out = append(out, role)
		}
	}
	return out, ev.err
}

func GetRole(ctx context.Context, userID string, roleID int) (*model.Role, error) {
	ev := newEvaluator(ctx)
	if err := ev.guardManageRole(userID, roleID); err != nil {
		return nil, err
	}
	return ev.role(roleID), ev.err
}

func DeleteRole(ctx context.Context, userID string, roleID int) error {
	ev := newEvaluator(ctx)
	if err := ev.guardManageRole(userID, roleID); err != nil {
		return err
	}
	if _, err := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, roleID).Delete(); err != nil {
		return err
	}
	permissionHotCache.invalidateAll()
	return nil
}
