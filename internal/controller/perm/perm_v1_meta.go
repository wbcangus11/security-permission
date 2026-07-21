package perm

import (
	"context"

	"security-permission/api/perm/v1"
	"security-permission/internal/logic/permission"
	"security-permission/internal/model"
)

func (c *ControllerV1) Meta(ctx context.Context, req *v1.MetaReq) (*model.MetaData, error) {
	return permission.Meta(ctx)
}
