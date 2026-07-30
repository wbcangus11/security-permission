package v1

import "github.com/gogf/gf/v2/frame/g"

type OrgItem struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// ManageOrgTreeReq 查询后台可见组织树。
type ManageOrgTreeReq struct {
	g.Meta `path:"/manage/org-tree" method:"get" tags:"权限/后台管理" summary:"查询后台可见组织树"`
}

type VisibleOrgItem struct {
	Id         int    `json:"id"`
	ParentId   int    `json:"parentId"`
	Name       string `json:"name"`
	Accessible bool   `json:"accessible"`
}

type ManageOrgTreeRes struct {
	Items []VisibleOrgItem `json:"items"`
}

// ManageOrgDetailReq 查询组织详情。
type ManageOrgDetailReq struct {
	g.Meta `path:"/manage/org-detail" method:"get" tags:"权限/后台管理" summary:"查询组织详情"`
	OrgId  int `json:"orgId" dc:"组织 ID"`
}

type ManageOrgDetailRes struct {
	Accessible    bool            `json:"accessible"`
	Name          string          `json:"name"`
	ParentId      int             `json:"parentId"`
	ChildCount    int             `json:"childCount"`
	Children      []string        `json:"children"`
	ResourceItems []ResourceBrief `json:"resourceItems"`
}

// ManageOrgSaveReq 新增、重命名或移动组织。
// 写操作同时检查“人员信息”菜单权限和组织数据权限。
type ManageOrgSaveReq struct {
	g.Meta   `path:"/manage/org-save" method:"post" tags:"权限/后台管理" summary:"新增或修改组织"`
	Id       int    `json:"id" dc:"组织 ID,0 或空表示新增组织"`
	ParentId int    `json:"parentId" dc:"父组织 ID;新增时必填,更新时非 0 且变化表示移动组织"`
	Name     string `json:"name" dc:"组织名称"`
}

type ManageOrgSaveRes OrgItem

// ManageOrgDeleteReq 删除组织。
// 只能删除无子组织且无下属用户的叶子组织。
type ManageOrgDeleteReq struct {
	g.Meta `path:"/manage/org-delete" method:"post" tags:"权限/后台管理" summary:"删除组织"`
	Id     int `json:"id" dc:"要删除的组织 ID"`
}

type ManageOrgDeleteRes struct {
	Success bool `json:"success"`
}
