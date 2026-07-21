package v1

import "github.com/gogf/gf/v2/frame/g"

// AppMenuReq 查询应用端可见菜单。
// 对应前台应用页顶部的功能入口。
type AppMenuReq struct {
	g.Meta `path:"/app/menu" method:"get" tags:"权限/应用端" summary:"查询应用端可见菜单"`
}

// ManageMenuReq 查询后台系统管理可见菜单。
type ManageMenuReq struct {
	g.Meta `path:"/manage/menu" method:"get" tags:"权限/后台管理" summary:"查询后台可见菜单"`
}
