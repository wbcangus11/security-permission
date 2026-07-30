// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// RoleMenuDao 是 role_menu 表的数据访问对象。
type RoleMenuDao struct {
	table    string             // DAO 对应的底层表名。
	group    string             // 当前 DAO 使用的数据库配置分组名。
	columns  RoleMenuColumns    // 保存表的全部列名，便于统一引用。
	handlers []gdb.ModelHandler // 用于自定义模型处理的处理器。
}

// RoleMenuColumns 定义并保存 role_menu 表的列名。
type RoleMenuColumns struct {
	Id       string // 角色菜单关系ID
	RoleId   string // 角色ID
	MenuCode string // 菜单权限码
}

// roleMenuColumns 保存 role_menu 表的列名。
var roleMenuColumns = RoleMenuColumns{
	Id:       "id",
	RoleId:   "role_id",
	MenuCode: "menu_code",
}

// NewRoleMenuDao 创建并返回 role_menu 表的数据访问对象。
func NewRoleMenuDao(handlers ...gdb.ModelHandler) *RoleMenuDao {
	return &RoleMenuDao{
		group:    "default",
		table:    "role_menu",
		columns:  roleMenuColumns,
		handlers: handlers,
	}
}

// DB 返回当前 DAO 使用的底层数据库对象。
func (dao *RoleMenuDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table 返回当前 DAO 对应的表名。
func (dao *RoleMenuDao) Table() string {
	return dao.table
}

// Columns 返回当前 DAO 对应表的全部列名。
func (dao *RoleMenuDao) Columns() RoleMenuColumns {
	return dao.columns
}

// Group 返回当前 DAO 使用的数据库配置分组名。
func (dao *RoleMenuDao) Group() string {
	return dao.group
}

// Ctx 创建当前 DAO 的模型，并自动绑定本次操作的上下文。
func (dao *RoleMenuDao) Ctx(ctx context.Context) *gdb.Model {
	model := dao.DB().Model(dao.table)
	for _, handler := range dao.handlers {
		model = handler(model)
	}
	return model.Safe().Ctx(ctx)
}

// Transaction 使用函数 f 封装事务逻辑。
// 当函数 f 返回非空错误时回滚事务并返回该错误；返回 nil 时提交事务。
//
// 注意：不要在函数 f 内自行提交或回滚，事务结果由本方法统一处理。
func (dao *RoleMenuDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
