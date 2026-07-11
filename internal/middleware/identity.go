package middleware

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	"security-permission/internal/consts"
	"security-permission/internal/service"
)

const demoUserHeader = "X-Demo-User-Id"

// Identity resolves the request actor once and stores it in the GoFrame request
// context. Demo impersonation is isolated behind security.demoMode; production
// deployments must let a trusted gateway populate security.trustedUserHeader.
func Identity(r *ghttp.Request) {
	actorID := ""
	if DemoMode(r.Context()) {
		actorID = strings.TrimSpace(r.Header.Get(demoUserHeader))
	} else if header := trustedUserHeader(r.Context()); header != "" {
		actorID = strings.TrimSpace(r.Header.Get(header))
	}
	if actorID != "" {
		r.SetCtxVar(consts.ContextKeyActorID, actorID)
	}
	r.Middleware.Next()
}

// ActorID returns the authenticated actor. "0" is reserved for system-owned
// seed data and is never a valid login identity.
func ActorID(ctx context.Context) (string, error) {
	r := g.RequestFromCtx(ctx)
	if r == nil {
		return "", gerror.New("请求上下文不存在")
	}
	actorID := strings.TrimSpace(r.GetCtxVar(consts.ContextKeyActorID).String())
	if actorID == "" {
		return "", gerror.New("未登录或身份凭证缺失")
	}
	if actorID == "0" {
		return "", gerror.New("系统内置身份不能登录")
	}
	if service.RuntimeService().User(actorID) == nil {
		return "", gerror.New("当前登录用户不存在")
	}
	return actorID, nil
}

func DemoMode(ctx context.Context) bool {
	return g.Cfg().MustGetWithEnv(ctx, "security.demoMode", true).Bool()
}

func trustedUserHeader(ctx context.Context) string {
	return strings.TrimSpace(g.Cfg().MustGetWithEnv(ctx, "security.trustedUserHeader", "").String())
}
