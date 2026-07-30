package perm

import (
	"security-permission/api/perm/v1"
	"security-permission/internal/model"
)

func userFromReq(req *v1.UserSaveReq) *model.User {
	return &model.User{
		Id: req.Id, Name: req.Name, OrgId: req.OrgId,
		IsSuperuser: req.IsSuperuser, RoleIds: append([]int{}, req.RoleIds...),
	}
}
