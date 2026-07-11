package permission

const (
	// 树范围类型在运行时的内部标识。
	// area/org 分别用于后台管理域;resarea 用于应用端业务资源范围。
	treeKindArea    = "area"
	treeKindOrg     = "org"
	treeKindResArea = "resarea"
)

const (
	// sqlAlwaysFalse 用于“无任何可见范围”时拼出永不命中的 WHERE,避免误查全表。
	sqlAlwaysFalse = "1=0"

	// 分页默认值和上限。上限用于防止前端一次请求过多数据。
	defaultPageSize           = 100
	maxPageSize               = 500
	searchLimit               = 500
	manageDetailResourceLimit = 500
)

const (
	// areaSearchScopeManage 表示区域搜索使用后台管理 AREA 范围;其他值默认按应用端 RES_AREA 范围。
	areaSearchScopeManage = "manage"
)

var resourceActionMenus = map[string]string{
	"live":     "app.video.live",
	"playback": "app.video.playback",
	"picture":  "app.video.picture",
}
