package cmd

import (
	"context"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcmd"

	"security-permission/internal/controller/hello"
	"security-permission/internal/controller/perm"
	"security-permission/internal/service"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			// 从 MySQL 加载权限数据到内存缓存
			if err = service.S.Reload(ctx); err != nil {
				return err
			}

			s := g.Server()

			// 静态资源:把前端测试页放在 resource/public 下,根路径访问。
			s.SetServerRoot("resource/public")
			s.SetIndexFiles([]string{"index.html"})

			s.Group("/", func(group *ghttp.RouterGroup) {
				group.Middleware(ghttp.MiddlewareHandlerResponse)
				group.Bind(
					hello.NewV1(),
				)
			})

			// 权限演示接口,统一前缀 /api。
			s.Group("/api", func(group *ghttp.RouterGroup) {
				perm.Register(group)
			})

			s.Run()
			return nil
		},
	}
)
