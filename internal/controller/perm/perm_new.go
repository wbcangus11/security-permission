package perm

import permapi "security-permission/api/perm"

type ControllerV1 struct{}

func NewV1() permapi.IPermV1 {
	return &ControllerV1{}
}
