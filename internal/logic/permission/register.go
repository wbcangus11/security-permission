package permission

import (
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/model"
	services "security-permission/internal/service"
)

type roleProvider struct {
	service *RoleService
}

func (p *roleProvider) List(actorID string) []*model.Role {
	actor := p.service.User(actorID)
	if actor == nil {
		return []*model.Role{}
	}
	if !actor.IsSuperuser && !p.service.CheckMenu(actor, menuRoleManage).Allow {
		return []*model.Role{}
	}
	visible, unlimited := p.service.ManageableRoles(actorID)
	roles := p.service.Roles()
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

func (p *roleProvider) Get(actorID string, roleID int) (*model.Role, error) {
	for _, role := range p.List(actorID) {
		if role.Id == roleID {
			return role, nil
		}
	}
	if p.service.Role(roleID) == nil {
		return nil, gerror.New("角色不存在")
	}
	return nil, gerror.New("无权查看该角色")
}

func (p *roleProvider) SaveBasic(ctx context.Context, actorID string, role *model.Role) (*model.Role, int, error) {
	result, err := p.service.SaveBasic(ctx, actorID, role)
	if err != nil {
		return nil, 0, err
	}
	return result.Role, result.Preserved, nil
}

func (p *roleProvider) Delete(ctx context.Context, actorID string, roleID int) error {
	return p.service.Delete(ctx, actorID, roleID)
}

type userProvider struct {
	service *UserService
}

func (p *userProvider) List(actorID string) []*model.User {
	actor, unrestricted, err := p.service.checkUserWriter(actorID)
	if err != nil {
		return []*model.User{}
	}
	users := p.service.Users()
	if unrestricted {
		return users
	}
	out := make([]*model.User, 0, len(users))
	for _, user := range users {
		if !user.IsSuperuser && p.service.CheckOrg(actor, user.OrgId).Allow {
			out = append(out, user)
		}
	}
	return out
}

func (p *userProvider) Get(actorID, userID string) (*model.User, error) {
	for _, user := range p.List(actorID) {
		if user.Id == userID {
			return user, nil
		}
	}
	if p.service.User(userID) == nil {
		return nil, gerror.New("用户不存在")
	}
	return nil, gerror.New("无权查看该用户")
}

func (p *userProvider) SaveManaged(ctx context.Context, actorID string, user *model.User) (*model.User, error) {
	return p.service.SaveManaged(ctx, actorID, user)
}

func (p *userProvider) Delete(ctx context.Context, actorID, userID string) error {
	return p.service.Delete(ctx, actorID, userID)
}

func init() {
	services.Register(services.Provider{
		Runtime:    S.Runtime,
		Auth:       S.Auth,
		Role:       &roleProvider{service: S.Roles},
		Delegation: S.Delegate,
		User:       &userProvider{service: S.Users},
		Area:       S.Areas,
		Org:        S.Orgs,
		Resource:   S.Resources,
		View:       S.Views,
	})
}
