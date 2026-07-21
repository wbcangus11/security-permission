package cmd

import (
	"context"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/gogf/gf/v2/os/genv"
	"github.com/gogf/gf/v2/os/gfile"

	"security-permission/internal/controller/perm"
	"security-permission/internal/middleware"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			if err = g.DB().PingMaster(); err != nil {
				return gerror.Wrap(err, "数据库启动检查失败")
			}
			s := g.Server()
			if address := genv.Get("APP_SERVER_ADDRESS").String(); address != "" {
				s.SetAddr(address)
			}

			// 发布包把 resource/public 放在可执行文件旁边；go run 时回退到当前工作目录。
			serverRoot := "resource/public"
			if packagedRoot := gfile.Join(gfile.SelfDir(), "resource", "public"); gfile.Exists(packagedRoot) {
				serverRoot = packagedRoot
			}
			s.SetServerRoot(serverRoot)
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
