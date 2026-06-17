// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// OrgDao is the data access object for the table org.
type OrgDao struct {
	table    string             // table is the underlying table name of the DAO.
	group    string             // group is the database configuration group name of the current DAO.
	columns  OrgColumns         // columns contains all the column names of Table for convenient usage.
	handlers []gdb.ModelHandler // handlers for customized model modification.
}

// OrgColumns defines and stores column names for the table org.
type OrgColumns struct {
	Id       string // 组织ID
	ParentId string // 父组织ID,0为根
	Name     string // 组织名称
	Path     string // 物化路径,含自身
	Sort     string // 同级排序
}

// orgColumns holds the columns for the table org.
var orgColumns = OrgColumns{
	Id:       "id",
	ParentId: "parent_id",
	Name:     "name",
	Path:     "path",
	Sort:     "sort",
}

// NewOrgDao creates and returns a new DAO object for table data access.
func NewOrgDao(handlers ...gdb.ModelHandler) *OrgDao {
	return &OrgDao{
		group:    "default",
		table:    "org",
		columns:  orgColumns,
		handlers: handlers,
	}
}

// DB retrieves and returns the underlying raw database management object of the current DAO.
func (dao *OrgDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of the current DAO.
func (dao *OrgDao) Table() string {
	return dao.table
}

// Columns returns all column names of the current DAO.
func (dao *OrgDao) Columns() OrgColumns {
	return dao.columns
}

// Group returns the database configuration group name of the current DAO.
func (dao *OrgDao) Group() string {
	return dao.group
}

// Ctx creates and returns a Model for the current DAO. It automatically sets the context for the current operation.
func (dao *OrgDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *OrgDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
