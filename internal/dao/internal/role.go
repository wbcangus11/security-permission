// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// RoleDao 是 role 表的数据访问对象。
type RoleDao struct {
	table    string             // DAO 对应的底层表名。
	group    string             // 当前 DAO 使用的数据库配置分组名。
	columns  RoleColumns        // 保存表的全部列名，便于统一引用。
	handlers []gdb.ModelHandler // 用于自定义模型处理的处理器。
}

// RoleColumns 定义并保存 role 表的列名。
type RoleColumns struct {
	Id          string // 角色ID
	Name        string // 角色名称
	Description string // 描述
	CreatedBy   string // 创建人用户ID,0表示系统内置角色
}

// roleColumns 保存 role 表的列名。
var roleColumns = RoleColumns{
	Id:          "id",
	Name:        "name",
	Description: "description",
	CreatedBy:   "created_by",
}

// NewRoleDao 创建并返回 role 表的数据访问对象。
func NewRoleDao(handlers ...gdb.ModelHandler) *RoleDao {
	return &RoleDao{
		group:    "default",
		table:    "role",
		columns:  roleColumns,
		handlers: handlers,
	}
}

// DB 返回当前 DAO 使用的底层数据库对象。
func (dao *RoleDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table 返回当前 DAO 对应的表名。
func (dao *RoleDao) Table() string {
	return dao.table
}

// Columns 返回当前 DAO 对应表的全部列名。
func (dao *RoleDao) Columns() RoleColumns {
	return dao.columns
}

// Group 返回当前 DAO 使用的数据库配置分组名。
func (dao *RoleDao) Group() string {
	return dao.group
}

// Ctx 创建当前 DAO 的模型，并自动绑定本次操作的上下文。
func (dao *RoleDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *RoleDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
