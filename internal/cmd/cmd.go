package cmd

import (
	"context"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/gogf/gf/v2/os/genv"

	"security-permission/internal/controller/perm"
	_ "security-permission/internal/logic/permission"
	"security-permission/internal/middleware"
	"security-permission/internal/service"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			// 从 MySQL 加载权限数据到运行时缓存。
			if err = service.RuntimeService().Reload(ctx); err != nil {
				return err
			}

			s := g.Server()
			if address := genv.Get("APP_SERVER_ADDRESS").String(); address != "" {
				s.SetAddr(address)
			}

			// 静态资源:前端单页放在 resource/public 下,根路径访问。
			s.SetServerRoot("resource/public")
			s.SetIndexFiles([]string{"index.html"})

			// 权限接口,统一前缀 /api。
			s.Group("/api", func(group *ghttp.RouterGroup) {
				group.Middleware(middleware.Identity, ghttp.MiddlewareHandlerResponse)
				perm.Register(group)
			})

			s.Run()
			return nil
		},
	}
)
