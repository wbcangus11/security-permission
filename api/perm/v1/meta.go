package v1

import "github.com/gogf/gf/v2/frame/g"

// MetaReq 查询前端初始化角色和用户管理所需的区域、组织、菜单和用户字典。
type MetaReq struct {
	g.Meta `path:"/meta" method:"get" tags:"权限/元数据" summary:"获取权限配置元数据"`
}
