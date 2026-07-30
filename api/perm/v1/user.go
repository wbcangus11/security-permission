package v1

import "github.com/gogf/gf/v2/frame/g"

// UserListReq 查询当前用户有权管理的用户列表。
type UserListReq struct {
	g.Meta `path:"/user/list" method:"get" tags:"权限/用户" summary:"查询用户列表"`
}

type UserItem struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	OrgId       int    `json:"orgId"`
	RoleIds     []int  `json:"roleIds"`
	IsSuperuser bool   `json:"isSuperuser"`
}

type UserListRes struct {
	Items []UserItem `json:"items"`
}

// UserDetailReq 查询单个用户详情。
type UserDetailReq struct {
	g.Meta `path:"/user/detail" method:"get" tags:"权限/用户" summary:"查询用户详情"`
	Id     string `json:"id" dc:"用户 ID"`
}

type UserDetailRes UserItem

// UserSaveReq 保存用户和角色绑定。
// 角色绑定会按当前用户可分配角色范围做合并,防止越权分配或误删不可见绑定。
type UserSaveReq struct {
	g.Meta      `path:"/user/save" method:"post" tags:"权限/用户" summary:"保存用户"`
	Id          string `json:"id" dc:"用户 ID,空表示新建用户"`
	Name        string `json:"name" dc:"用户名称"`
	OrgId       int    `json:"orgId" dc:"用户所属组织 ID"`
	IsSuperuser bool   `json:"isSuperuser" dc:"是否超级管理员;超级管理员绕过全部鉴权"`
	RoleIds     []int  `json:"roleIds" dc:"绑定的角色 ID 列表"`
}

type UserSaveRes UserItem

// UserDeleteReq 删除用户并清理用户-角色绑定。
type UserDeleteReq struct {
	g.Meta `path:"/user/delete" method:"post" tags:"权限/用户" summary:"删除用户"`
	Id     string `json:"id" dc:"要删除的用户 ID"`
}

type UserDeleteRes struct {
	Success bool `json:"success"`
}
