// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// AreaDao is the data access object for the table area.
type AreaDao struct {
	table    string             // table is the underlying table name of the DAO.
	group    string             // group is the database configuration group name of the current DAO.
	columns  AreaColumns        // columns contains all the column names of Table for convenient usage.
	handlers []gdb.ModelHandler // handlers for customized model modification.
}

// AreaColumns defines and stores column names for the table area.
type AreaColumns struct {
	Id       string // 区域ID
	ParentId string // 父区域ID,0为根
	Name     string // 区域名称
	Path     string // 物化路径,含自身,形如 /1/3/4/
	Sort     string // 同级排序
}

// areaColumns holds the columns for the table area.
var areaColumns = AreaColumns{
	Id:       "id",
	ParentId: "parent_id",
	Name:     "name",
	Path:     "path",
	Sort:     "sort",
}

// NewAreaDao creates and returns a new DAO object for table data access.
func NewAreaDao(handlers ...gdb.ModelHandler) *AreaDao {
	return &AreaDao{
		group:    "default",
		table:    "area",
		columns:  areaColumns,
		handlers: handlers,
	}
}

// DB retrieves and returns the underlying raw database management object of the current DAO.
func (dao *AreaDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of the current DAO.
func (dao *AreaDao) Table() string {
	return dao.table
}

// Columns returns all column names of the current DAO.
func (dao *AreaDao) Columns() AreaColumns {
	return dao.columns
}

// Group returns the database configuration group name of the current DAO.
func (dao *AreaDao) Group() string {
	return dao.group
}

// Ctx creates and returns a Model for the current DAO. It automatically sets the context for the current operation.
func (dao *AreaDao) Ctx(ctx context.Context) *gdb.Model {
	model := dao.DB().Model(dao.table)
	for _, handler := range dao.handlers {
		model = handler(model)
	}
	return model.Safe().Ctx(ctx)
}

// Transaction wraps the transaction logic using function f.
// It rolls back the transaction and returns the error if function f returns a non-nil error.
// It commits the transaction and returns nil if function f returns nil.
//
// Note: Do not commit or roll back the transaction in function f,
// as it is automatically handled by this function.
func (dao *AreaDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
