package service

// 用户(账号)管理:基础增删改查的写时鉴权。
//
// 鉴权规则:
//   - 功能关:操作人须有「账号管理」菜单(sys.person.account)。
//   - 数据关:普通操作人只能管理自己 ORG 范围覆盖的用户/目标组织。
//   - 角色绑定:普通操作人只能授予自己可见/可再委派的角色;范围外旧绑定保存时保留,避免误删。
//   - 超级管理员/actor<=0 不受限制。

import (
	"context"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// menuAccountManage 账号管理菜单 code(用户写操作的功能关)。
const menuAccountManage = "sys.person.account"

// SaveUserManaged 新增或更新用户,带账号管理写时鉴权。
func (s *Store) SaveUserManaged(ctx context.Context, actorId int, in *model.User) (*model.User, error) {
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
	if in.Id > 0 && old == nil {
		return nil, gerror.New("用户不存在")
	}
	if old != nil && !unrestricted {
		if old.IsSuperuser {
			return nil, gerror.New("无权编辑超级管理员")
		}
		if d := s.CheckOrg(actor, old.OrgId); !d.Allow {
			return nil, gerror.New("无权编辑「" + old.Name + "」:" + d.Reason)
		}
	}
	if !unrestricted {
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
	in.RoleIds, err = s.mergeAssignableUserRoles(actorId, unrestricted, old, in.RoleIds)
	if err != nil {
		return nil, err
	}
	return s.SaveUser(ctx, in)
}

// DeleteUser 删除用户并清理 user_role 绑定。
func (s *Store) DeleteUser(ctx context.Context, actorId, userId int) error {
	actor, unrestricted, err := s.checkUserWriter(actorId)
	if err != nil {
		return err
	}
	target := s.User(userId)
	if target == nil {
		return gerror.New("用户不存在")
	}
	if actorId == userId && actorId > 0 {
		return gerror.New("不能删除当前登录用户")
	}
	if !unrestricted {
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

func (s *Store) checkUserWriter(actorId int) (*model.User, bool, error) {
	if actorId <= 0 {
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

func (s *Store) mergeAssignableUserRoles(actorId int, unrestricted bool, old *model.User, submitted []int) ([]int, error) {
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
	for _, rid := range clean {
		if grant[rid] {
			out = append(out, rid)
			outSeen[rid] = true
		}
	}
	if old != nil {
		for _, rid := range old.RoleIds {
			if !grant[rid] && !outSeen[rid] {
				out = append(out, rid)
				outSeen[rid] = true
			}
		}
	}
	return out, nil
}

func (s *Store) userNameTaken(name string, excludeId int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Name == name && u.Id != excludeId {
			return true
		}
	}
	return false
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
