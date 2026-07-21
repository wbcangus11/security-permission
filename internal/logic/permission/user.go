package permission

import (
	"context"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

func (e *evaluator) checkUserWriter(userID string) (*model.User, bool, error) {
	user := e.user(userID)
	if e.err != nil {
		return nil, false, e.err
	}
	if user == nil {
		return nil, false, gerror.New("操作人不存在")
	}
	if user.IsSuperuser {
		return user, true, nil
	}
	decision := e.checkMenu(user, menuAccountManage)
	if e.err != nil {
		return nil, false, e.err
	}
	if !decision.Allow {
		return nil, false, gerror.New("功能权限不足：" + decision.Reason)
	}
	return user, false, nil
}

// List 用 ORG 物化路径把数据权限下推到 SQL，再批量装配角色绑定。
func ListUsers(ctx context.Context, userID string) ([]*model.User, error) {
	out := []*model.User{}
	ev := newEvaluator(ctx)
	current, unlimited, err := ev.checkUserWriter(userID)
	if err != nil {
		if ev.err != nil {
			return nil, ev.err
		}
		return out, nil
	}
	query := g.DB().Model(dao.User.Table()+" u").Ctx(ctx).
		LeftJoin(dao.Org.Table()+" o", "o.id=u.org_id").Fields("u.id")
	if !unlimited {
		filter := ev.treeScopeFilter(current, treeKindOrg)
		if filter.None {
			return out, ev.err
		}
		query = query.Where("u.is_superuser", 0)
		if where, args := treeScopeWhere("o", filter); where != "" {
			query = query.Where(where, args...)
		}
	}
	var rows []struct{ Id string }
	if err = query.Order("u.id").Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.Id)
	}
	return listUsersByIDs(ctx, ids)
}

func GetUser(ctx context.Context, userID, targetUserID string) (*model.User, error) {
	ev := newEvaluator(ctx)
	current, unlimited, err := ev.checkUserWriter(userID)
	if err != nil {
		return nil, err
	}
	target := ev.user(targetUserID)
	if ev.err != nil {
		return nil, ev.err
	}
	if target == nil {
		return nil, gerror.New("用户不存在")
	}
	if unlimited {
		return target, nil
	}
	if target.IsSuperuser || !ev.checkTree(current, target.OrgId, treeKindOrg).Allow {
		return nil, gerror.New("无权查看该用户")
	}
	return target, ev.err
}

func (e *evaluator) mergeAssignableUserRoles(userID string, unlimited bool, old *model.User, submitted []int) ([]int, error) {
	seen := map[int]bool{}
	clean := []int{}
	for _, roleID := range submitted {
		if roleID <= 0 || seen[roleID] {
			continue
		}
		if e.role(roleID) == nil {
			if e.err != nil {
				return nil, e.err
			}
			return nil, gerror.New("角色不存在 #" + strconv.Itoa(roleID))
		}
		seen[roleID] = true
		clean = append(clean, roleID)
	}
	if unlimited {
		return clean, nil
	}
	grantable, _ := e.manageableRoles(userID)
	if e.err != nil {
		return nil, e.err
	}
	out := []int{}
	outSeen := map[int]bool{}
	for _, roleID := range clean {
		if grantable[roleID] {
			out = append(out, roleID)
			outSeen[roleID] = true
		}
	}
	if old != nil {
		for _, roleID := range old.RoleIds {
			if !grantable[roleID] && !outSeen[roleID] {
				out = append(out, roleID)
				outSeen[roleID] = true
			}
		}
	}
	return out, nil
}

func SaveUser(ctx context.Context, userID string, input *model.User) (*model.User, error) {
	ev := newEvaluator(ctx)
	current, unlimited, err := ev.checkUserWriter(userID)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("用户名不能为空")
	}
	if ev.org(input.OrgId) == nil {
		if ev.err != nil {
			return nil, ev.err
		}
		return nil, gerror.New("所属组织不存在")
	}
	old := ev.user(input.Id)
	if ev.err != nil {
		return nil, ev.err
	}
	if input.Id != "" && old == nil {
		return nil, gerror.New("用户不存在")
	}
	if old != nil && !unlimited {
		if old.IsSuperuser {
			return nil, gerror.New("无权编辑超级管理员")
		}
		decision := ev.checkTree(current, old.OrgId, treeKindOrg)
		if !decision.Allow {
			return nil, gerror.New("无权编辑“" + old.Name + "”：" + decision.Reason)
		}
	}
	if !unlimited {
		decision := ev.checkTree(current, input.OrgId, treeKindOrg)
		if !decision.Allow {
			return nil, gerror.New("无权把用户归属到该组织：" + decision.Reason)
		}
	}
	if ev.err != nil {
		return nil, ev.err
	}
	if exists, err := userNameExists(ctx, input.Name, input.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("用户名已存在：" + input.Name)
	}
	if !unlimited {
		if old != nil {
			input.IsSuperuser = old.IsSuperuser
		} else {
			input.IsSuperuser = false
		}
	}
	input.RoleIds, err = ev.mergeAssignableUserRoles(userID, unlimited, old, input.RoleIds)
	if err != nil {
		return nil, err
	}
	saved, err := saveUser(ctx, input, old != nil)
	if err != nil {
		return nil, err
	}
	return saved, nil
}

func DeleteUser(ctx context.Context, userID, targetUserID string) error {
	ev := newEvaluator(ctx)
	current, unlimited, err := ev.checkUserWriter(userID)
	if err != nil {
		return err
	}
	target := ev.user(targetUserID)
	if ev.err != nil {
		return ev.err
	}
	if target == nil {
		return gerror.New("用户不存在")
	}
	if userID == targetUserID {
		return gerror.New("不能删除当前登录用户")
	}
	if !unlimited {
		if target.IsSuperuser {
			return gerror.New("无权删除超级管理员")
		}
		decision := ev.checkTree(current, target.OrgId, treeKindOrg)
		if !decision.Allow {
			return gerror.New("无权删除“" + target.Name + "”：" + decision.Reason)
		}
	}
	if ev.err != nil {
		return ev.err
	}
	err = dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if target.IsSuperuser {
			var superusers []struct{ Id string }
			if err := tx.Model(dao.User.Table()).Ctx(ctx).Fields(dao.User.Columns().Id).
				Where(dao.User.Columns().IsSuperuser, 1).LockUpdate().Scan(&superusers); err != nil {
				return err
			}
			if len(superusers) <= 1 {
				return gerror.New("至少保留一个超级管理员")
			}
		}
		_, err := tx.Model(dao.User.Table()).Ctx(ctx).
			Where(dao.User.Columns().Id, targetUserID).Delete()
		return err
	})
	if err != nil {
		return err
	}
	permissionHotCache.invalidateAll()
	return nil
}
