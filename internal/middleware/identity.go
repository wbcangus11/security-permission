package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	"security-permission/internal/consts"
	"security-permission/internal/logic/permission"
)

const userHeader = "X-User-Id"
const maxIdentityLength = 64

// Identity 读取当前用户请求头并写入请求上下文。
func Identity(r *ghttp.Request) {
	setPermissionResponseHeaders(r.Response.Header())
	if userID := identityHeaderValue(r.Header, userHeader); userID != "" {
		r.SetCtxVar(consts.ContextKeyUserId, userID)
	}
	r.Middleware.Next()
}

// 权限结果随当前用户和角色配置变化，禁止浏览器或代理复用旧用户的 GET 响应。
func setPermissionResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store, private")
	header.Set("Pragma", "no-cache")
	header.Set("Vary", userHeader)
}

// UserId 返回当前用户并验证账号仍然存在。
// "0" is reserved for system-owned roles and cannot be used as an identity.
func UserId(ctx context.Context) (string, error) {
	r := g.RequestFromCtx(ctx)
	if r == nil {
		return "", gerror.New("请求上下文不存在")
	}
	userID := strings.TrimSpace(r.GetCtxVar(consts.ContextKeyUserId).String())
	if userID == "" {
		return "", gerror.New("未选择当前用户")
	}
	if userID == "0" {
		return "", gerror.New("系统内置身份不能登录")
	}
	if !r.GetCtxVar(consts.ContextKeyUser).IsNil() {
		return userID, nil
	}
	user, err := permission.UserByID(ctx, userID)
	if err != nil {
		return "", gerror.Wrap(err, "读取当前用户失败")
	}
	if user == nil {
		return "", gerror.New("当前用户不存在")
	}
	r.SetCtxVar(consts.ContextKeyUser, user)
	return userID, nil
}

func identityHeaderValue(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	value := strings.TrimSpace(values[0])
	if value == "" || len(value) > maxIdentityLength {
		return ""
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f || r == ',' {
			return ""
		}
	}
	return value
}
