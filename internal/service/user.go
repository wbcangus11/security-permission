package service

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

// SaveUserManaged 新增或更新用户,带账号管理写时鉴权。
// actorId 是历史命名,语义上就是“当前用户 ID”;真实项目应来自 token/context。
func (s *Store) SaveUserManaged(ctx context.Context, actorId string, in *model.User) (*model.User, error) {
	// 账号写操作先统一过功能关;返回 unrestricted 表示后续数据关/角色范围限制都可跳过。
	actor, unrestricted, err := s.checkUserWriter(actorId)
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
	if old != nil && !unrestricted {
		// 普通账号管理员不能改超级管理员,也不能改自己组织权限范围外的账号。
		if old.IsSuperuser {
			return nil, gerror.New("无权编辑超级管理员")
		}
		if d := s.CheckOrg(actor, old.OrgId); !d.Allow {
			return nil, gerror.New("无权编辑「" + old.Name + "」:" + d.Reason)
		}
	}
	if !unrestricted {
		// 新归属组织也必须在操作者的 ORG 数据范围内,否则可以通过“移动用户”越权管理组织外账号。
		if d := s.CheckOrg(actor, in.OrgId); !d.Allow {
			return nil, gerror.New("无权把用户归属到该组织:" + d.Reason)
		}
	}
	if s.userNameTaken(in.Name, in.Id) {
		return nil, gerror.New("用户名已存在:" + in.Name)
	}
	if !unrestricted {
		// 普通账号管理员不能创建/提升超级管理员。
		if old != nil {
			in.IsSuperuser = old.IsSuperuser
		} else {
			in.IsSuperuser = false
		}
	}
	// 角色绑定同样走委派模型:可分配范围内以提交为准,范围外旧绑定保留。
	in.RoleIds, err = s.mergeAssignableUserRoles(actorId, unrestricted, old, in.RoleIds)
	if err != nil {
		return nil, err
	}
	return s.SaveUser(ctx, in)
}

// DeleteUser 删除用户并清理 user_role 绑定。
// actorId 是当前用户 ID;禁止删除自己,并且至少保留一个超级管理员。
func (s *Store) DeleteUser(ctx context.Context, actorId, userId string) error {
	// 删除账号也先过账号管理功能关;超管/不受限可跳过后续组织数据关。
	actor, unrestricted, err := s.checkUserWriter(actorId)
	if err != nil {
		return err
	}
	target := s.User(userId)
	if target == nil {
		return gerror.New("用户不存在")
	}
	if actorId == userId && !isUnrestrictedActor(actorId) {
		return gerror.New("不能删除当前登录用户")
	}
	if !unrestricted {
		// 普通账号管理员只能删自己 ORG 范围内的普通账号。
		if target.IsSuperuser {
			return gerror.New("无权删除超级管理员")
		}
		if d := s.CheckOrg(actor, target.OrgId); !d.Allow {
			return gerror.New("无权删除「" + target.Name + "」:" + d.Reason)
		}
	}
	if target.IsSuperuser && s.superuserCount() <= 1 {
		return gerror.New("至少保留一个超级管理员")
	}
	err = dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 先清 user_role 再删 user,避免留下悬挂绑定;真实外键未启用,所以服务层显式清理。
		if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Where(dao.UserRole.Columns().UserId, userId).Delete(); err != nil {
			return err
		}
		_, err := tx.Model(dao.User.Table()).Ctx(ctx).Where(dao.User.Columns().Id, userId).Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.reloadUsers(ctx)
}

func (s *Store) checkUserWriter(actorId string) (*model.User, bool, error) {
	if isUnrestrictedActor(actorId) {
		return nil, true, nil
	}
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
func (s *Store) mergeAssignableUserRoles(actorId string, unrestricted bool, old *model.User, submitted []int) ([]int, error) {
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
	if unrestricted {
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
func (s *Store) userNameTaken(name string, excludeId string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Name == name && u.Id != excludeId {
			return true
		}
	}
	return false
}

func (s *Store) nextUserId() string {
	maxId := 0
	for _, u := range s.Users() {
		if n, err := strconv.Atoi(u.Id); err == nil && n > maxId {
			maxId = n
		}
	}
	return strconv.Itoa(maxId + 1)
}

func (s *Store) superuserCount() int {
	n := 0
	for _, u := range s.Users() {
		if u.IsSuperuser {
			n++
		}
	}
	return n
}
