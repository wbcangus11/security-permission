// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// AreaDao 是 area 表的数据访问对象。
type AreaDao struct {
	table    string             // DAO 对应的底层表名。
	group    string             // 当前 DAO 使用的数据库配置分组名。
	columns  AreaColumns        // 保存表的全部列名，便于统一引用。
	handlers []gdb.ModelHandler // 用于自定义模型处理的处理器。
}

// AreaColumns 定义并保存 area 表的列名。
type AreaColumns struct {
	Id       string // 区域ID
	ParentId string // 父区域ID,0为根
	Name     string // 区域名称
	Path     string // 物化路径,含自身,形如 /1/3/4/
	Sort     string // 同级排序
}

// areaColumns 保存 area 表的列名。
var areaColumns = AreaColumns{
	Id:       "id",
	ParentId: "parent_id",
	Name:     "name",
	Path:     "path",
	Sort:     "sort",
}

// NewAreaDao 创建并返回 area 表的数据访问对象。
func NewAreaDao(handlers ...gdb.ModelHandler) *AreaDao {
	return &AreaDao{
		group:    "default",
		table:    "area",
		columns:  areaColumns,
		handlers: handlers,
	}
}

// DB 返回当前 DAO 使用的底层数据库对象。
func (dao *AreaDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table 返回当前 DAO 对应的表名。
func (dao *AreaDao) Table() string {
	return dao.table
}

// Columns 返回当前 DAO 对应表的全部列名。
func (dao *AreaDao) Columns() AreaColumns {
	return dao.columns
}

// Group 返回当前 DAO 使用的数据库配置分组名。
func (dao *AreaDao) Group() string {
	return dao.group
}

// Ctx 创建当前 DAO 的模型，并自动绑定本次操作的上下文。
func (dao *AreaDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *AreaDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
