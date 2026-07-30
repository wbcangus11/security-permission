package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/net/ghttp"

	"security-permission/internal/consts"
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

// GetUserId 只从 ctx 里读取中间件已经放好的用户 ID。
// 实际项目替换这里的 context key 就行，Controller 和 Service 都不用再改。
func GetUserId(ctx context.Context) (userId string) {
	if ctx == nil {
		return ""
	}
	userId, _ = ctx.Value(consts.ContextKeyUserId).(string)
	return strings.TrimSpace(userId)
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
