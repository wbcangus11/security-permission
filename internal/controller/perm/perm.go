package perm

import "github.com/gogf/gf/v2/net/ghttp"

type ControllerV1 struct{}

// Register 注册权限模块路由。
// 具体路径、方法和接口说明都写在 api/perm/v1 的 g.Meta 标签里。
func Register(group *ghttp.RouterGroup) {
	group.Bind(&ControllerV1{})
}
