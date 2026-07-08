package perm

import permapi "security-permission/api/perm"

// ControllerV1 实现权限模块 v1 版本接口。
// 业务逻辑不直接写在这里,控制器只负责收参、调用 service、统一返回 CommonRes。
type ControllerV1 struct{}

// NewV1 返回 v1 控制器实例,供路由注册时绑定。
func NewV1() permapi.IPermV1 {
	return &ControllerV1{}
}
