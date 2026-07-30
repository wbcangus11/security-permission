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

func userFromReq(req *v1.UserSaveReq) *model.User {
	return &model.User{
		Id: req.Id, Name: req.Name, OrgId: req.OrgId,
		IsSuperuser: req.IsSuperuser, RoleIds: append([]int{}, req.RoleIds...),
	}
}
