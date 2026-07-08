// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// RoleDataScopeDao is the data access object for the table role_data_scope.
type RoleDataScopeDao struct {
	table    string               // table is the underlying table name of the DAO.
	group    string               // group is the database configuration group name of the current DAO.
	columns  RoleDataScopeColumns // columns contains all the column names of Table for convenient usage.
	handlers []gdb.ModelHandler   // handlers for customized model modification.
}

// RoleDataScopeColumns defines and stores column names for the table role_data_scope.
type RoleDataScopeColumns struct {
	Id           string // 角色数据范围ID
	RoleId       string // 角色ID
	ScopeType    string // AREA / ORG / RES_AREA
	NodeId       string // 授权的树节点ID(area.id 或 org.id)
	IncludeChild string // 是否含子树
}

// roleDataScopeColumns holds the columns for the table role_data_scope.
var roleDataScopeColumns = RoleDataScopeColumns{
	Id:           "id",
	RoleId:       "role_id",
	ScopeType:    "scope_type",
	NodeId:       "node_id",
	IncludeChild: "include_child",
}

// NewRoleDataScopeDao creates and returns a new DAO object for table data access.
func NewRoleDataScopeDao(handlers ...gdb.ModelHandler) *RoleDataScopeDao {
	return &RoleDataScopeDao{
		group:    "default",
		table:    "role_data_scope",
		columns:  roleDataScopeColumns,
		handlers: handlers,
	}
}

// DB retrieves and returns the underlying raw database management object of the current DAO.
func (dao *RoleDataScopeDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of the current DAO.
func (dao *RoleDataScopeDao) Table() string {
	return dao.table
}

// Columns returns all column names of the current DAO.
func (dao *RoleDataScopeDao) Columns() RoleDataScopeColumns {
	return dao.columns
}

// Group returns the database configuration group name of the current DAO.
func (dao *RoleDataScopeDao) Group() string {
	return dao.group
}

// Ctx creates and returns a Model for the current DAO. It automatically sets the context for the current operation.
func (dao *RoleDataScopeDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *RoleDataScopeDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
