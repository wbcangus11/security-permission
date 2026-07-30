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

// ListUsers 先把组织范围下推到 SQL，再批量装配角色绑定。
// 权限范围有多大就查多大，不会先把用户全表搬进内存再过滤。
func ListUsers(ctx context.Context, userID string) ([]*model.User, error) {
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAccountManage)
	if err != nil {
		return nil, err
	}

	out := []*model.User{}
	query := g.DB().Model(dao.User.Table()+" u").Ctx(ctx).
		LeftJoin(dao.Org.Table()+" o", "o.id=u.org_id").Fields("u.id")
	if !snapshot.isSuper() {
		filter := snapshot.treeFilter(treeKindOrg)
		if filter.None {
			return out, nil
		}
		query = query.Where("u.is_superuser", 0)
		if where, args := treeScopeWhere("o", filter); where != "" {
			query = query.Where(where, args...)
		}
	}

	var rows []struct{ Id string }
	if err := query.Order("u.id").Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.Id)
	}
	return listUsersByIDs(ctx, ids)
}

func GetUser(ctx context.Context, userID, targetUserID string) (*model.User, error) {
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAccountManage)
	if err != nil {
		return nil, err
	}
	target, err := findUser(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, gerror.New("用户不存在")
	}
	if snapshot.isSuper() {
		return target, nil
	}
	if target.IsSuperuser {
		return nil, gerror.New("无权查看该用户")
	}
	org, err := findOrg(ctx, target.OrgId)
	if err != nil {
		return nil, err
	}
	if org == nil || !snapshot.covers(treeKindOrg, org.Path, org.Id) {
		return nil, gerror.New("无权查看该用户")
	}
	return target, nil
}

// mergeAssignableUserRoles 只替换当前管理员能分配的角色。
// 用户身上那些管理员看不到的历史角色会原样保留，避免编辑基本信息时误删权限。
func mergeAssignableUserRoles(
	ctx context.Context,
	snapshot *permissionSnapshot,
	old *model.User,
	submitted []int,
) ([]int, error) {
	seen := map[int]bool{}
	clean := []int{}
	for _, roleID := range submitted {
		if roleID <= 0 || seen[roleID] {
			continue
		}
		role, err := findRole(ctx, roleID)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, gerror.New("角色不存在 #" + strconv.Itoa(roleID))
		}
		seen[roleID] = true
		clean = append(clean, roleID)
	}
	if snapshot.isSuper() {
		return clean, nil
	}

	grantable, _, err := manageableRoles(ctx, snapshot)
	if err != nil {
		return nil, err
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
	if input == nil {
		return nil, gerror.New("用户保存参数不能为空")
	}
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAccountManage)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("用户名不能为空")
	}

	targetOrg, err := findOrg(ctx, input.OrgId)
	if err != nil {
		return nil, err
	}
	if targetOrg == nil {
		return nil, gerror.New("所属组织不存在")
	}
	old, err := findUser(ctx, input.Id)
	if err != nil {
		return nil, err
	}
	if input.Id != "" && old == nil {
		return nil, gerror.New("用户不存在")
	}

	if !snapshot.isSuper() {
		if old != nil {
			if old.IsSuperuser {
				return nil, gerror.New("无权编辑超级管理员")
			}
			oldOrg, err := findOrg(ctx, old.OrgId)
			if err != nil {
				return nil, err
			}
			if oldOrg == nil || !snapshot.covers(treeKindOrg, oldOrg.Path, oldOrg.Id) {
				return nil, gerror.New("无权编辑“" + old.Name + "”")
			}
		}
		if !snapshot.covers(treeKindOrg, targetOrg.Path, targetOrg.Id) {
			return nil, gerror.New("无权把用户归属到该组织")
		}
	}

	if exists, err := userNameExists(ctx, input.Name, input.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("用户名已存在：" + input.Name)
	}
	if !snapshot.isSuper() {
		if old != nil {
			input.IsSuperuser = old.IsSuperuser
		} else {
			input.IsSuperuser = false
		}
	}
	input.RoleIds, err = mergeAssignableUserRoles(ctx, snapshot, old, input.RoleIds)
	if err != nil {
		return nil, err
	}
	saved, err := saveUser(ctx, input, old != nil)
	if err != nil {
		return nil, err
	}
	InvalidateUser(saved.Id)
	return saved, nil
}

func DeleteUser(ctx context.Context, userID, targetUserID string) error {
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAccountManage)
	if err != nil {
		return err
	}
	target, err := findUser(ctx, targetUserID)
	if err != nil {
		return err
	}
	if target == nil {
		return gerror.New("用户不存在")
	}
	if userID == targetUserID {
		return gerror.New("不能删除当前登录用户")
	}
	if !snapshot.isSuper() {
		if target.IsSuperuser {
			return gerror.New("无权删除超级管理员")
		}
		org, err := findOrg(ctx, target.OrgId)
		if err != nil {
			return err
		}
		if org == nil || !snapshot.covers(treeKindOrg, org.Path, org.Id) {
			return gerror.New("无权删除“" + target.Name + "”")
		}
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
	InvalidateUser(targetUserID)
	return nil
}
