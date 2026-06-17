package perm

import "github.com/gogf/gf/v2/net/ghttp"

func Register(group *ghttp.RouterGroup) {
	group.Bind(NewV1())
}
