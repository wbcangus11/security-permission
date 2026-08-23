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

// Identity 是当前独立演示页面使用的身份适配器：读取请求头并写入请求上下文。
// 实际项目应由统一认证中间件在完成身份校验后写入同一个 ctx 身份位置；权限和
// 业务代码只依赖 GetUserId，不需要知道身份来自 Token、Session 还是网关。
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

// GetUserId 是权限和业务代码读取当前用户 ID 的稳定边界，只读取认证中间件已经
// 放入 ctx 的身份。实际项目调整认证方式、context key 或用户信息结构时，只需在
// 中间件包内部完成适配，Controller、Service 和权限逻辑都不用修改。
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
