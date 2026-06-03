// Package perm 提供权限演示的 HTTP 接口(元数据 / 角色 CRUD / 鉴权测试)。
package perm

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	"security-permission/internal/model"
	"security-permission/internal/service"
)

// Register 把所有接口注册到给定路由组。
func Register(group *ghttp.RouterGroup) {
	group.GET("/meta", meta)
	group.GET("/roles", listRoles)
	group.GET("/roles/{id}", getRole)
	group.POST("/roles", saveRole)
	group.GET("/grantable", grantable)
	group.POST("/check", check)
	// 用户管理 + 应用端体验
	group.POST("/users", saveUser)
	group.GET("/visible-areas", visibleAreas)
	group.GET("/area-resources", areaResources)
	group.GET("/app-menus", appMenus)
	// 后台管理域体验
	group.GET("/sys-menus", sysMenus)
	group.GET("/manage-areas", manageAreas)
	group.GET("/manage-orgs", manageOrgs)
	group.GET("/manage-area-detail", manageAreaDetail)
	group.GET("/manage-org-detail", manageOrgDetail)
}

func ok(r *ghttp.Request, data interface{}) {
	r.Response.WriteJson(g.Map{"code": 0, "message": "ok", "data": data})
}

func fail(r *ghttp.Request, msg string) {
	r.Response.WriteJson(g.Map{"code": 1, "message": msg})
}

// meta 返回前端渲染所需的全部元数据:区域树、组织树、菜单、资源、操作项、用户。
func meta(r *ghttp.Request) {
	s := service.S
	ok(r, g.Map{
		"areas":     s.Areas(),
		"orgs":      s.Orgs(),
		"menus":     s.Menus(),
		"resources": s.Resources(),
		"actions":   s.Actions(),
		"users":     s.Users(),
	})
}

func listRoles(r *ghttp.Request) {
	ok(r, service.S.Roles())
}

func getRole(r *ghttp.Request) {
	id := r.Get("id").Int()
	role := service.S.Role(id)
	if role == nil {
		fail(r, "角色不存在")
		return
	}
	ok(r, role)
}

// saveRole 新增或更新角色,请求体即 model.Role 的 JSON。
func saveRole(r *ghttp.Request) {
	var role model.Role
	if err := r.Parse(&role); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	if role.Name == "" {
		fail(r, "角色名称不能为空")
		return
	}
	// 受控委派(二次授权)·海康式合并(模型 A):
	//   范围内以提交为准,范围外保留角色原有权限(编辑者看不到也删不掉)。actor=0=不受限。
	actor := r.Get("actor").Int()
	role.CreatedBy = actor
	old := service.S.Role(role.Id) // 编辑时取原角色;新建为 nil
	merged, preserved := service.S.MergeDelegated(actor, old, &role)
	saved, err := service.S.SaveRole(r.Context(), merged)
	if err != nil {
		fail(r, "保存失败:"+err.Error())
		return
	}
	r.Response.WriteJson(g.Map{"code": 0, "message": "ok", "data": saved, "preserved": preserved})
}

// grantable 返回操作者可授出的范围上限(供前端置灰)。?actor=用户ID,0=不受限。
func grantable(r *ghttp.Request) {
	ok(r, service.S.GrantableSet(r.Get("actor").Int()))
}

// saveUser 新增或更新用户(含角色绑定)。请求体即 model.User 的 JSON。
func saveUser(r *ghttp.Request) {
	var u model.User
	if err := r.Parse(&u); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	if u.Name == "" {
		fail(r, "用户名不能为空")
		return
	}
	saved, err := service.S.SaveUser(r.Context(), &u)
	if err != nil {
		fail(r, "保存失败:"+err.Error())
		return
	}
	ok(r, saved)
}

// visibleAreas 应用端:某用户可见的区域树(带 accessible)。?userId=
func visibleAreas(r *ghttp.Request) {
	ok(r, service.S.VisibleAreas(r.Get("userId").Int()))
}

// areaResources 应用端:点击某区域时该用户能看到的资源 + 各操作是否有权。?userId=&areaId=
func areaResources(r *ghttp.Request) {
	ok(r, service.S.AreaResources(r.Get("userId").Int(), r.Get("areaId").Int()))
}

// appMenus 应用端:某用户可见的应用菜单(功能权限)。?userId=
func appMenus(r *ghttp.Request) {
	ok(r, service.S.AppMenus(r.Get("userId").Int()))
}

// sysMenus 后台:某用户可见的系统管理菜单。?userId=
func sysMenus(r *ghttp.Request) {
	ok(r, service.S.SysMenus(r.Get("userId").Int()))
}

// manageAreas 后台:某用户可管理的安保区域树(带 accessible)。?userId=
func manageAreas(r *ghttp.Request) {
	ok(r, service.S.ManageAreas(r.Get("userId").Int()))
}

// manageOrgs 后台:某用户可管理的组织树(带 accessible)。?userId=
func manageOrgs(r *ghttp.Request) {
	ok(r, service.S.ManageOrgs(r.Get("userId").Int()))
}

// manageAreaDetail 后台:点击某区域的管理详情。?userId=&areaId=
func manageAreaDetail(r *ghttp.Request) {
	ok(r, service.S.ManageAreaDetail(r.Get("userId").Int(), r.Get("areaId").Int()))
}

// manageOrgDetail 后台:点击某组织的管理详情。?userId=&orgId=
func manageOrgDetail(r *ghttp.Request) {
	ok(r, service.S.ManageOrgDetail(r.Get("userId").Int(), r.Get("orgId").Int()))
}

// checkReq 鉴权测试请求。
//
//	type=menu      -> 用 code(菜单 code)
//	type=area/org  -> 用 nodeId
//	type=resource  -> 用 resourceId + action
type checkReq struct {
	UserId     int    `json:"userId"`
	Type       string `json:"type"`
	Code       string `json:"code"`
	NodeId     int    `json:"nodeId"`
	ResourceId int    `json:"resourceId"`
	Action     string `json:"action"`
}

func check(r *ghttp.Request) {
	var req checkReq
	if err := r.Parse(&req); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	user := service.S.User(req.UserId)
	if user == nil {
		fail(r, "用户不存在")
		return
	}
	s := service.S
	var d *service.Decision
	switch req.Type {
	case "menu":
		d = s.CheckMenu(user, req.Code)
	case "area":
		d = s.CheckArea(user, req.NodeId)
	case "org":
		d = s.CheckOrg(user, req.NodeId)
	case "resource":
		d = s.CheckResource(user, req.ResourceId, req.Action)
	default:
		fail(r, "未知鉴权类型:"+req.Type)
		return
	}
	ok(r, d)
}
