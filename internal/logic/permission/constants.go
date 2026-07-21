package permission

const (
	// 树范围类型在运行时的内部标识。
	// area/org 分别用于后台管理域;resarea 用于应用端业务资源范围。
	treeKindArea    = "area"
	treeKindOrg     = "org"
	treeKindResArea = "resarea"
)

const (
	menuAreaManage     = "sys.area"
	menuResourceManage = "sys.resource"
	menuOrgManage      = "sys.person.info"
	menuRoleManage     = "sys.person.role"
	menuAccountManage  = "sys.person.account"
)

var (
	videoReadMenus = []string{
		"app.video.live",
		"app.video.playback",
		"app.video.picture",
	}
	manageAreaReadMenus = []string{menuAreaManage, menuResourceManage}
	manageOrgReadMenus  = []string{menuOrgManage, menuAccountManage, menuRoleManage}
)

const (
	// sqlAlwaysFalse 用于“无任何可见范围”时拼出永不命中的 WHERE,避免误查全表。
	sqlAlwaysFalse = "1=0"

	// 分页默认值和上限。上限用于防止前端一次请求过多数据。
	defaultPageSize           = 100
	maxPageSize               = 500
	searchLimit               = 500
	maxAreaSearchLength       = 64
	manageDetailResourceLimit = 500
)

type resourceActionDefinition struct {
	Code     string
	Name     string
	MenuCode string
}

var resourceActions = []resourceActionDefinition{
	{Code: "live", Name: "实时预览", MenuCode: "app.video.live"},
	{Code: "playback", Name: "远程回放", MenuCode: "app.video.playback"},
	{Code: "picture", Name: "图片查询", MenuCode: "app.video.picture"},
}

func resourceAction(code string) (resourceActionDefinition, bool) {
	for _, action := range resourceActions {
		if action.Code == code {
			return action, true
		}
	}
	return resourceActionDefinition{}, false
}
