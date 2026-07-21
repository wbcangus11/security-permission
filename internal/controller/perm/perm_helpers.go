package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/middleware"
	"security-permission/internal/model"
)

func requestUser(ctx context.Context) (string, error) {
	return middleware.UserId(ctx)
}

func roleFromReq(req *v1.RoleSaveReq) *model.Role {
	return &model.Role{
		Id:                 req.Id,
		Name:               req.Name,
		Description:        req.Description,
		MenuCodes:          req.MenuCodes,
		AreaScopes:         req.AreaScopes,
		OrgScopes:          req.OrgScopes,
		ResourceAreaScopes: req.ResourceAreaScopes,
	}
}

func userFromReq(req *v1.UserSaveReq) *model.User {
	return &model.User{
		Id: req.Id, Name: req.Name, OrgId: req.OrgId,
		IsSuperuser: req.IsSuperuser, RoleIds: req.RoleIds,
	}
}
