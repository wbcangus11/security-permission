package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) UserList(ctx context.Context, req *v1.UserListReq) (*v1.UserListRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	users, err := permission.ListUsers(ctx, userID)
	if err != nil {
		return nil, err
	}
	res := &v1.UserListRes{Items: make([]v1.UserItem, 0, len(users))}
	for _, user := range users {
		if user != nil {
			res.Items = append(res.Items, userItemRes(user))
		}
	}
	return res, nil
}

func (c *ControllerV1) UserDetail(ctx context.Context, req *v1.UserDetailReq) (*v1.UserDetailRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	user, err := permission.GetUser(ctx, userID, req.Id)
	if err != nil {
		return nil, err
	}
	item := userItemRes(user)
	res := v1.UserDetailRes(item)
	return &res, nil
}

func (c *ControllerV1) UserSave(ctx context.Context, req *v1.UserSaveReq) (*v1.UserSaveRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	user, err := permission.SaveUser(ctx, userID, userFromReq(req))
	if err != nil {
		return nil, err
	}
	item := userItemRes(user)
	res := v1.UserSaveRes(item)
	return &res, nil
}

func (c *ControllerV1) UserDelete(ctx context.Context, req *v1.UserDeleteReq) (*v1.UserDeleteRes, error) {
	userID, err := requestUser(ctx)
	if err != nil {
		return nil, err
	}
	if err = permission.DeleteUser(ctx, userID, req.Id); err != nil {
		return nil, err
	}
	return &v1.UserDeleteRes{Success: true}, nil
}

func userItemRes(user *model.User) v1.UserItem {
	if user == nil {
		return v1.UserItem{RoleIds: []int{}}
	}
	return v1.UserItem{
		Id: user.Id, Name: user.Name, OrgId: user.OrgId,
		RoleIds: append([]int{}, user.RoleIds...), IsSuperuser: user.IsSuperuser,
	}
}
