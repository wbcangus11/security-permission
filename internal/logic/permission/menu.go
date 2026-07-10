package permission

const (
	// 系统管理域权限码。菜单记录在 menu 表中维护,代码里只保留鉴权会直接引用的稳定 code。
	menuAreaManage     = "sys.area"
	menuResourceManage = "sys.resource"
	menuOrgManage      = "sys.person.info"
	menuRoleManage     = "sys.person.role"
	menuAccountManage  = "sys.person.account"
)
