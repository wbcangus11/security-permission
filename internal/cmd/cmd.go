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
	permissionlogic "security-permission/internal/logic/permission"
	"security-permission/internal/middleware"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			// 第 1 步：先确认主库可用。数据库不可用时直接终止启动，避免提供不完整服务。
			if err = g.DB().PingMaster(); err != nil {
				return gerror.Wrap(err, "数据库启动检查失败")
			}
			// 第 2 步：在注册 HTTP 路由前完整加载菜单权限字典，之后鉴权不再查询菜单表。
			if err = permissionlogic.InitializeMenuCatalog(ctx); err != nil {
				return gerror.Wrap(err, "菜单目录启动加载失败")
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
