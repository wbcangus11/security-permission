// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// RoleResourceActionDao is the data access object for the table role_resource_action.
type RoleResourceActionDao struct {
	table    string                    // table is the underlying table name of the DAO.
	group    string                    // group is the database configuration group name of the current DAO.
	columns  RoleResourceActionColumns // columns contains all the column names of Table for convenient usage.
	handlers []gdb.ModelHandler        // handlers for customized model modification.
}

// RoleResourceActionColumns defines and stores column names for the table role_resource_action.
type RoleResourceActionColumns struct {
	Id         string // 角色资源操作ID
	RoleId     string // 角色ID
	ResourceId string // 资源ID
	ActionCode string // 操作编码
}

// roleResourceActionColumns holds the columns for the table role_resource_action.
var roleResourceActionColumns = RoleResourceActionColumns{
	Id:         "id",
	RoleId:     "role_id",
	ResourceId: "resource_id",
	ActionCode: "action_code",
}

// NewRoleResourceActionDao creates and returns a new DAO object for table data access.
func NewRoleResourceActionDao(handlers ...gdb.ModelHandler) *RoleResourceActionDao {
	return &RoleResourceActionDao{
		group:    "default",
		table:    "role_resource_action",
		columns:  roleResourceActionColumns,
		handlers: handlers,
	}
}

// DB retrieves and returns the underlying raw database management object of the current DAO.
func (dao *RoleResourceActionDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of the current DAO.
func (dao *RoleResourceActionDao) Table() string {
	return dao.table
}

// Columns returns all column names of the current DAO.
func (dao *RoleResourceActionDao) Columns() RoleResourceActionColumns {
	return dao.columns
}

// Group returns the database configuration group name of the current DAO.
func (dao *RoleResourceActionDao) Group() string {
	return dao.group
}

// Ctx creates and returns a Model for the current DAO. It automatically sets the context for the current operation.
func (dao *RoleResourceActionDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *RoleResourceActionDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
