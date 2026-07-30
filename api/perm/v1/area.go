package v1

import "github.com/gogf/gf/v2/frame/g"

type AreaItem struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Sort     int    `json:"sort"`
}

type AncestorRef struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type AreaNode struct {
	Id          int           `json:"id"`
	ParentId    int           `json:"parentId"`
	Name        string        `json:"name"`
	Accessible  bool          `json:"accessible"`
	HasChildren bool          `json:"hasChildren"`
	Ancestors   []AncestorRef `json:"ancestors,omitempty"`
}

// AppAreaChildrenReq 分页查询应用端区域树某一层。
// 它使用 RES_AREA 资源范围过滤,返回“可访问节点 + 导航祖先”。
type AppAreaChildrenReq struct {
	g.Meta   `path:"/app/area-children" method:"get" tags:"权限/应用端" summary:"分页查询应用端区域树子节点"`
	ParentId int `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Page     int `json:"page" dc:"页码,从 1 开始"`
	Size     int `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

type AppAreaChildrenRes struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

// AppAreaSearchReq 搜索应用端区域树。
// 搜索结果会带祖先链,前端按局部树展示并高亮命中节点。
type AppAreaSearchReq struct {
	g.Meta `path:"/app/area-search" method:"get" tags:"权限/应用端" summary:"搜索应用端区域树"`
	Q      string `json:"q" v:"length:0,64" dc:"搜索关键字,最多返回前 500 条匹配"`
}

type AppAreaSearchRes struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

// ManageAreaChildrenReq 分页查询后台区域树某一层。
// 它使用 AREA 管理范围过滤,返回可管理节点和必要的导航祖先。
type ManageAreaChildrenReq struct {
	g.Meta   `path:"/manage/area-children" method:"get" tags:"权限/后台管理" summary:"分页查询后台区域树子节点"`
	ParentId int `json:"parentId" dc:"父区域 ID,0 表示查询根层"`
	Page     int `json:"page" dc:"页码,从 1 开始"`
	Size     int `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

type ManageAreaChildrenRes struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

// ManageAreaSearchReq 搜索后台管理区域树。权限域固定为 AREA，调用方不能切换。
type ManageAreaSearchReq struct {
	g.Meta `path:"/manage/area-search" method:"get" tags:"权限/后台管理" summary:"搜索后台管理区域树"`
	Q      string `json:"q" v:"length:0,64" dc:"搜索关键字,最多返回前 500 条匹配"`
}

type ManageAreaSearchRes struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

// ManageAreaDetailReq 查询后台区域详情。
// 可管理时返回子区域数量和本区域直接资源;不可管理时返回空详情。
type ManageAreaDetailReq struct {
	g.Meta `path:"/manage/area-detail" method:"get" tags:"权限/后台管理" summary:"查询后台区域详情"`
	AreaId int `json:"areaId" dc:"区域 ID"`
}

type ResourceBrief struct {
	Id     int    `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	AreaId int    `json:"areaId"`
}

type ManageAreaDetailRes struct {
	Accessible    bool            `json:"accessible"`
	Name          string          `json:"name"`
	ParentId      int             `json:"parentId"`
	ChildCount    int             `json:"childCount"`
	Children      []string        `json:"children"`
	ResourceItems []ResourceBrief `json:"resourceItems"`
}

// ManageAreaSaveReq 新增、重命名或移动区域。
// 写操作同时检查功能菜单权限和区域数据权限。
type ManageAreaSaveReq struct {
	g.Meta   `path:"/manage/area-save" method:"post" tags:"权限/后台管理" summary:"新增或修改区域"`
	Id       int    `json:"id" dc:"区域 ID,0 或空表示新增区域"`
	ParentId int    `json:"parentId" dc:"父区域 ID;新增时必填,更新时非 0 且变化表示移动区域"`
	Name     string `json:"name" dc:"区域名称"`
}

type ManageAreaSaveRes AreaItem

// ManageAreaReorderReq 调整同父区域的排序。
type ManageAreaReorderReq struct {
	g.Meta   `path:"/manage/area-reorder" method:"post" tags:"权限/后台管理" summary:"交换同级区域排序"`
	AreaId   int `json:"areaId" dc:"当前区域 ID"`
	ToAreaId int `json:"toAreaId" dc:"目标同级区域 ID,后端会和当前区域交换排序"`
}

type ManageAreaReorderRes struct {
	Success bool `json:"success"`
}

// ManageAreaDeleteReq 删除区域。
// 只能删除无子区域且无资源的叶子区域。
type ManageAreaDeleteReq struct {
	g.Meta `path:"/manage/area-delete" method:"post" tags:"权限/后台管理" summary:"删除区域"`
	Id     int `json:"id" dc:"要删除的区域 ID"`
}

type ManageAreaDeleteRes struct {
	Success bool `json:"success"`
}
