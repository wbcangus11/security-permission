package v1

import "github.com/gogf/gf/v2/frame/g"

// AppResourceListReq 查询某区域子树下应用端可见资源。
// 返回每个资源对实时预览、远程回放、图片查询等操作是否可用。
type AppResourceListReq struct {
	g.Meta `path:"/app/resource-list" method:"get" tags:"权限/应用端" summary:"分页查询应用端资源列表"`
	AreaId int `json:"areaId" dc:"区域 ID,返回该区域子树下用户可见资源"`
	Page   int `json:"page" dc:"页码,从 1 开始"`
	Size   int `json:"size" dc:"每页数量,为空或超限时使用默认值"`
}

// ManageResourceSaveReq 新增、重命名、改类型或移动业务资源。
// 资源管理写操作检查“资源管理”菜单权限和资源所在区域管理权限。
type ManageResourceSaveReq struct {
	g.Meta `path:"/manage/resource-save" method:"post" tags:"权限/后台管理" summary:"新增或修改资源"`
	Id     int    `json:"id" dc:"资源 ID,0 或空表示新增资源"`
	AreaId int    `json:"areaId" dc:"资源所在区域 ID;更新时变化表示移动资源"`
	Name   string `json:"name" dc:"资源名称"`
	Type   string `json:"type" dc:"资源类型,如 gun=枪机,dome=球机"`
}

// ManageResourceDeleteReq 删除业务资源。
// 当前资源权限只来自资源区域范围,删除资源不需要清理额外授权表。
type ManageResourceDeleteReq struct {
	g.Meta `path:"/manage/resource-delete" method:"post" tags:"权限/后台管理" summary:"删除资源"`
	Id     int `json:"id" dc:"要删除的资源 ID"`
}
