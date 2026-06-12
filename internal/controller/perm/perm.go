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
	group.POST("/roles/delete", deleteRole)
	group.GET("/grantable", grantable)
	group.POST("/check", check)
	// 用户管理 + 应用端体验
	group.GET("/users", listUsers)
	group.GET("/users/{id}", getUser)
	group.POST("/users", saveUser)
	group.POST("/users/delete", deleteUser)
	group.GET("/visible-areas", visibleAreas)
	group.GET("/area-children", areaChildren)
	group.GET("/area-search", areaSearch)
	group.GET("/area-resources", areaResources)
	group.GET("/role-area-children", roleAreaChildren)
	group.GET("/app-menus", appMenus)
	// 区域管理(真实落库:写时鉴权 + path 自动维护)
	group.POST("/areas", saveArea)
	group.POST("/areas/reorder", reorderArea)
	group.POST("/areas/delete", deleteArea)
	// 组织管理(真实落库:写时鉴权 + path 自动维护)
	group.POST("/orgs", saveOrg)
	group.POST("/orgs/delete", deleteOrg)
	// 资源(摄像头)管理(真实落库:写时鉴权 sys.resource + 区域数据权限)
	group.POST("/resources", saveResource)
	group.POST("/resources/delete", deleteResource)
	// 后台管理域体验
	group.GET("/sys-menus", sysMenus)
	group.GET("/manage-areas", manageAreas)
	group.GET("/manage-area-children", manageAreaChildren)
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
	old := service.S.Role(role.Id) // 编辑时取原角色;新建为 nil
	// 编辑既有角色:委派关——操作者须「可管理」该角色(对齐海康 canEdit);新建无此限(创建人即拥有者)。
	if old != nil {
		if err := service.S.GuardManageRole(actor, role.Id); err != nil {
			fail(r, err.Error())
			return
		}
	}
	// created_by 只在新建时记为操作人;编辑时保持原值不变(委派"可管理角色集"含自建角色依赖它)。
	if old != nil {
		role.CreatedBy = old.CreatedBy
	} else {
		role.CreatedBy = actor
	}
	merged, preserved := service.S.MergeDelegated(actor, old, &role)
	saved, err := service.S.SaveRole(r.Context(), merged)
	if err != nil {
		fail(r, "保存失败:"+err.Error())
		return
	}
	r.Response.WriteJson(g.Map{"code": 0, "message": "ok", "data": saved, "preserved": preserved})
}

// deleteRole 删除角色(委派校验 + 级联清理引用,含 user_role 绑定)。?actor=操作人,body 含 id。
func deleteRole(r *ghttp.Request) {
	if err := service.S.DeleteRole(r.Context(), r.Get("actor").Int(), r.Get("id").Int()); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

// grantable 返回操作者可授出的范围上限(供前端置灰)。?actor=用户ID,0=不受限。
func grantable(r *ghttp.Request) {
	ok(r, service.S.GrantableSet(r.Get("actor").Int()))
}

func listUsers(r *ghttp.Request) {
	ok(r, service.S.Users())
}

func getUser(r *ghttp.Request) {
	id := r.Get("id").Int()
	user := service.S.User(id)
	if user == nil {
		fail(r, "用户不存在")
		return
	}
	ok(r, user)
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
	saved, err := service.S.SaveUserManaged(r.Context(), r.Get("userId").Int(), &u)
	if err != nil {
		fail(r, "保存失败:"+err.Error())
		return
	}
	ok(r, saved)
}

func deleteUser(r *ghttp.Request) {
	if err := service.S.DeleteUser(r.Context(), r.Get("userId").Int(), r.Get("id").Int()); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

// saveArea 新增/重命名/移动区域。?userId=操作人。
// 写时鉴权(sys.area 菜单 + 区域数据权限),自动维护物化路径(移动批量改子孙 path)。
func saveArea(r *ghttp.Request) {
	var in service.AreaSaveInput
	if err := r.Parse(&in); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	saved, err := service.S.SaveArea(r.Context(), r.Get("userId").Int(), &in)
	if err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, saved)
}

// deleteArea 删除区域(仅限无子区域、无资源),并清理对该节点的数据范围授权。?userId=操作人
func deleteArea(r *ghttp.Request) {
	if err := service.S.DeleteArea(r.Context(), r.Get("userId").Int(), r.Get("id").Int()); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

func reorderArea(r *ghttp.Request) {
	var in service.AreaReorderInput
	if err := r.Parse(&in); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	if err := service.S.ReorderArea(r.Context(), r.Get("userId").Int(), &in); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

// saveOrg 新增/重命名/移动组织。?userId=操作人。
// 写时鉴权(sys.person.info 菜单 + 组织数据权限),自动维护物化路径(移动批量改子孙 path)。
func saveOrg(r *ghttp.Request) {
	var in service.OrgSaveInput
	if err := r.Parse(&in); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	saved, err := service.S.SaveOrg(r.Context(), r.Get("userId").Int(), &in)
	if err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, saved)
}

// deleteOrg 删除组织(仅限无子组织、无下属用户),并清理对该节点的数据范围授权。?userId=操作人
func deleteOrg(r *ghttp.Request) {
	if err := service.S.DeleteOrg(r.Context(), r.Get("userId").Int(), r.Get("id").Int()); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

// saveResource 新增/重命名/改类型/移动资源(摄像头)。?userId=操作人。
// 写时鉴权(sys.resource 菜单 + 资源所在区域的安保区域管理权限)。
func saveResource(r *ghttp.Request) {
	var in service.ResourceSaveInput
	if err := r.Parse(&in); err != nil {
		fail(r, "参数错误:"+err.Error())
		return
	}
	saved, err := service.S.SaveResource(r.Context(), r.Get("userId").Int(), &in)
	if err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, saved)
}

// deleteResource 删除资源,并清理对该资源的精细授权(role_resource_action)。?userId=操作人
func deleteResource(r *ghttp.Request) {
	if err := service.S.DeleteResource(r.Context(), r.Get("userId").Int(), r.Get("id").Int()); err != nil {
		fail(r, err.Error())
		return
	}
	ok(r, true)
}

// visibleAreas 应用端:某用户可见的区域树(带 accessible)。?userId=
func visibleAreas(r *ghttp.Request) {
	ok(r, service.S.VisibleAreas(r.Get("userId").Int()))
}

// areaResources 应用端:点击某区域时该用户能看到的资源 + 各操作是否有权(分页,权限下推 SQL)。
// ?userId=&areaId=&page=&size=(page/size 缺省 1/100)
func areaResources(r *ghttp.Request) {
	ok(r, service.S.AreaResourcesPaged(r.Context(), r.Get("userId").Int(), r.Get("areaId").Int(), r.Get("page").Int(), r.Get("size").Int()))
}

// areaChildren 应用端:某节点下"可见的"直接子区域,按层懒加载 + 分页(过滤 + 分页下推 SQL)。
// ?userId=&parentId=&page=&size=(parentId 缺省 0=根层;page/size 缺省 1/100)
func areaChildren(r *ghttp.Request) {
	ok(r, service.S.AreaChildren(r.Context(), r.Get("userId").Int(), r.Get("parentId").Int(), r.Get("page").Int(), r.Get("size").Int()))
}

// areaSearch 区域树搜索框:按名称搜索可见区域(全树下推 SQL + 权限过滤,分页)。
// ?userId=&q=&scope=app|manage&page=&size=(scope 缺省 app=RES_AREA;manage=AREA)
func areaSearch(r *ghttp.Request) {
	ok(r, service.S.SearchAreas(r.Context(), r.Get("userId").Int(), r.Get("q").String(), r.Get("scope").String(), r.Get("page").Int(), r.Get("size").Int()))
}

// roleAreaChildren 角色配置树:操作者可授范围内、父节点下整一层子区域(惰性加载,不分页)。
// ?actor=操作者&parentId=父节点(0=根)&kind=area|resarea
func roleAreaChildren(r *ghttp.Request) {
	ok(r, service.S.RoleAreaChildren(r.Context(), r.Get("actor").Int(), r.Get("parentId").Int(), r.Get("kind").String()))
}

// appMenus 应用端:某用户可见的应用菜单(功能权限)。?userId=
func appMenus(r *ghttp.Request) {
	ok(r, service.S.AppMenus(r.Get("userId").Int()))
}

// sysMenus 后台:某用户可见的系统管理菜单。?userId=
func sysMenus(r *ghttp.Request) {
	ok(r, service.S.SysMenus(r.Get("userId").Int()))
}

// manageAreas 后台:某用户可管理的安保区域树(带 accessible)。?userId=(全量,旧接口,保留)
func manageAreas(r *ghttp.Request) {
	ok(r, service.S.ManageAreas(r.Get("userId").Int()))
}

// manageAreaChildren 后台:某节点下"可管理/可见的"直接子区域,按层懒加载 + 分页(AREA 数据权限,下推 SQL)。
// ?userId=&parentId=&page=&size=(parentId 缺省 0=根层;page/size 缺省 1/100)
func manageAreaChildren(r *ghttp.Request) {
	ok(r, service.S.ManageAreaChildren(r.Context(), r.Get("userId").Int(), r.Get("parentId").Int(), r.Get("page").Int(), r.Get("size").Int()))
}

// manageOrgs 后台:某用户可管理的组织树(带 accessible)。?userId=
func manageOrgs(r *ghttp.Request) {
	ok(r, service.S.ManageOrgs(r.Get("userId").Int()))
}

// manageAreaDetail 后台:点击某区域的管理详情。?userId=&areaId=
func manageAreaDetail(r *ghttp.Request) {
	ok(r, service.S.ManageAreaDetail(r.Context(), r.Get("userId").Int(), r.Get("areaId").Int()))
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
