// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// ResourceDao 是 resource 表的数据访问对象。
type ResourceDao struct {
	table    string             // DAO 对应的底层表名。
	group    string             // 当前 DAO 使用的数据库配置分组名。
	columns  ResourceColumns    // 保存表的全部列名，便于统一引用。
	handlers []gdb.ModelHandler // 用于自定义模型处理的处理器。
}

// ResourceColumns 定义并保存 resource 表的列名。
type ResourceColumns struct {
	Id     string // 资源ID
	AreaId string // 所属区域ID
	Type   string // 资源类型,如 camera
	Name   string // 资源名称
}

// resourceColumns 保存 resource 表的列名。
var resourceColumns = ResourceColumns{
	Id:     "id",
	AreaId: "area_id",
	Type:   "type",
	Name:   "name",
}

// NewResourceDao 创建并返回 resource 表的数据访问对象。
func NewResourceDao(handlers ...gdb.ModelHandler) *ResourceDao {
	return &ResourceDao{
		group:    "default",
		table:    "resource",
		columns:  resourceColumns,
		handlers: handlers,
	}
}

// DB 返回当前 DAO 使用的底层数据库对象。
func (dao *ResourceDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table 返回当前 DAO 对应的表名。
func (dao *ResourceDao) Table() string {
	return dao.table
}

// Columns 返回当前 DAO 对应表的全部列名。
func (dao *ResourceDao) Columns() ResourceColumns {
	return dao.columns
}

// Group 返回当前 DAO 使用的数据库配置分组名。
func (dao *ResourceDao) Group() string {
	return dao.group
}

// Ctx 创建当前 DAO 的模型，并自动绑定本次操作的上下文。
func (dao *ResourceDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *ResourceDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
