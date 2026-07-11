package permission

// 用户(账号)管理:基础增删改查的写时鉴权。
//
// 鉴权规则:
//   - 功能关:当前用户须有「账号管理」菜单(sys.person.account)。
//   - 数据关:普通当前用户只能管理自己 ORG 范围覆盖的用户/目标组织。
//   - 角色绑定:普通当前用户只能授予自己可见/可再委派的角色;范围外旧绑定保存时保留,避免误删。
//   - 超级管理员不受限制。

import (
	"context"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// List 返回当前用户可管理的账号。普通用户按组织范围过滤,超级管理员可看全部。
func (s *UserService) List(actorID string) []*model.User {
	actor, unlimited, err := s.checkUserWriter(actorID)
	if err != nil {
		return []*model.User{}
	}
	users := s.Users()
	if unlimited {
		return users
	}
	out := make([]*model.User, 0, len(users))
	for _, user := range users {
		if !user.IsSuperuser && s.CheckOrg(actor, user.OrgId).Allow {
			out = append(out, user)
		}
	}
	return out
}

// Get 返回当前用户可管理的账号详情。
func (s *UserService) Get(actorID, userID string) (*model.User, error) {
	for _, user := range s.List(actorID) {
		if user.Id == userID {
			return user, nil
		}
	}
	if s.User(userID) == nil {
		return nil, gerror.New("用户不存在")
	}
	return nil, gerror.New("无权查看该用户")
}

// SaveManaged 新增或更新用户,带账号管理写时鉴权。
func (s *UserService) SaveManaged(ctx context.Context, actorId string, in *model.User) (*model.User, error) {
	// 账号写操作先统一过功能关;超级管理员可跳过后续数据关和角色范围限制。
	actor, unlimited, err := s.checkUserWriter(actorId)
	if err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, gerror.New("用户名不能为空")
	}
	if s.OrgById(in.OrgId) == nil {
		return nil, gerror.New("所属组织不存在")
	}
	old := s.User(in.Id)
	if in.Id != "" && old == nil {
		return nil, gerror.New("用户不存在")
	}
	if old != nil && !unlimited {
		// 普通账号管理员不能改超级管理员,也不能改自己组织权限范围外的账号。
		if old.IsSuperuser {
			return nil, gerror.New("无权编辑超级管理员")
		}
		if d := s.CheckOrg(actor, old.OrgId); !d.Allow {
			return nil, gerror.New("无权编辑「" + old.Name + "」:" + d.Reason)
		}
	}
	if !unlimited {
		// 新归属组织也必须在操作者的 ORG 数据范围内,否则可以通过“移动用户”越权管理组织外账号。
		if d := s.CheckOrg(actor, in.OrgId); !d.Allow {
			return nil, gerror.New("无权把用户归属到该组织:" + d.Reason)
		}
	}
	if s.userNameTaken(in.Name, in.Id) {
		return nil, gerror.New("用户名已存在:" + in.Name)
	}
	if !unlimited {
		// 普通账号管理员不能创建/提升超级管理员。
		if old != nil {
			in.IsSuperuser = old.IsSuperuser
		} else {
			in.IsSuperuser = false
		}
	}
	// 角色绑定同样走委派模型:可分配范围内以提交为准,范围外旧绑定保留。
	in.RoleIds, err = s.mergeAssignableUserRoles(actorId, unlimited, old, in.RoleIds)
	if err != nil {
		return nil, err
	}
	return s.SaveUser(ctx, in)
}

// Delete 删除用户并清理 user_role 绑定。
// actorId 是当前用户 ID;禁止删除自己,并且至少保留一个超级管理员。
func (s *UserService) Delete(ctx context.Context, actorId, userId string) error {
	// 删除账号也先过账号管理功能关;超级管理员可跳过后续组织数据关。
	actor, unlimited, err := s.checkUserWriter(actorId)
	if err != nil {
		return err
	}
	target := s.User(userId)
	if target == nil {
		return gerror.New("用户不存在")
	}
	if actorId == userId {
		return gerror.New("不能删除当前登录用户")
	}
	if !unlimited {
		// 普通账号管理员只能删自己 ORG 范围内的普通账号。
		if target.IsSuperuser {
			return gerror.New("无权删除超级管理员")
		}
		if d := s.CheckOrg(actor, target.OrgId); !d.Allow {
			return gerror.New("无权删除「" + target.Name + "」:" + d.Reason)
		}
	}
	err = dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if target.IsSuperuser {
			// Lock all current superuser rows so concurrent deletes cannot both
			// observe a safe count and remove the final administrators.
			var superusers []struct{ Id string }
			if err := tx.Model(dao.User.Table()).Ctx(ctx).
				Fields(dao.User.Columns().Id).
				Where(dao.User.Columns().IsSuperuser, true).
				LockUpdate().
				Scan(&superusers); err != nil {
				return err
			}
			if len(superusers) <= 1 {
				return gerror.New("至少保留一个超级管理员")
			}
		}
		// user_role 由当前 schema 的外键级联清理。
		_, err := tx.Model(dao.User.Table()).Ctx(ctx).Where(dao.User.Columns().Id, userId).Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.reloadUsers(ctx)
}

func (s *UserService) checkUserWriter(actorId string) (*model.User, bool, error) {
	actor := s.User(actorId)
	if actor == nil {
		return nil, false, gerror.New("操作人不存在")
	}
	if actor.IsSuperuser {
		return actor, true, nil
	}
	if d := s.CheckMenu(actor, menuAccountManage); !d.Allow {
		return nil, false, gerror.New("功能权限不足:" + d.Reason)
	}
	return actor, false, nil
}

// mergeAssignableUserRoles 合并用户角色绑定。
// 当前用户能分配的角色以提交为准;当前用户无权看到的旧绑定保留,避免编辑用户时误删。
func (s *UserService) mergeAssignableUserRoles(actorId string, unlimited bool, old *model.User, submitted []int) ([]int, error) {
	// 先清洗提交值:去重、忽略无效 ID、拒绝不存在的角色。
	seen := map[int]bool{}
	clean := []int{}
	for _, rid := range submitted {
		if rid <= 0 || seen[rid] {
			continue
		}
		if s.Role(rid) == nil {
			return nil, gerror.New("角色不存在:#" + strconv.Itoa(rid))
		}
		seen[rid] = true
		clean = append(clean, rid)
	}
	if unlimited {
		return clean, nil
	}
	grant, _ := s.ManageableRoles(actorId)
	out, outSeen := []int{}, map[int]bool{}
	// 操作者有权分配的角色,完全以本次提交为准。
	for _, rid := range clean {
		if grant[rid] {
			out = append(out, rid)
			outSeen[rid] = true
		}
	}
	if old != nil {
		// 操作者看不到/无权分配的旧角色绑定保留,防止编辑账号时误删高权限绑定。
		for _, rid := range old.RoleIds {
			if !grant[rid] && !outSeen[rid] {
				out = append(out, rid)
				outSeen[rid] = true
			}
		}
	}
	return out, nil
}

// userNameTaken 判断用户名是否已被其他用户占用。
func (s *UserService) userNameTaken(name string, excludeId string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Name == name && u.Id != excludeId {
			return true
		}
	}
	return false
}
