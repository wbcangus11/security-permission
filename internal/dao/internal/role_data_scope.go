// ==========================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// RoleDataScopeDao 是 role_data_scope 表的数据访问对象。
type RoleDataScopeDao struct {
	table    string               // DAO 对应的底层表名。
	group    string               // 当前 DAO 使用的数据库配置分组名。
	columns  RoleDataScopeColumns // 保存表的全部列名，便于统一引用。
	handlers []gdb.ModelHandler   // 用于自定义模型处理的处理器。
}

// RoleDataScopeColumns 定义并保存 role_data_scope 表的列名。
type RoleDataScopeColumns struct {
	Id           string // 角色数据范围ID
	RoleId       string // 角色ID
	ScopeType    string // AREA / ORG / RES_AREA
	NodeId       string // 授权的树节点ID(area.id 或 org.id)
	IncludeChild string // 是否含子树
}

// roleDataScopeColumns 保存 role_data_scope 表的列名。
var roleDataScopeColumns = RoleDataScopeColumns{
	Id:           "id",
	RoleId:       "role_id",
	ScopeType:    "scope_type",
	NodeId:       "node_id",
	IncludeChild: "include_child",
}

// NewRoleDataScopeDao 创建并返回 role_data_scope 表的数据访问对象。
func NewRoleDataScopeDao(handlers ...gdb.ModelHandler) *RoleDataScopeDao {
	return &RoleDataScopeDao{
		group:    "default",
		table:    "role_data_scope",
		columns:  roleDataScopeColumns,
		handlers: handlers,
	}
}

// DB 返回当前 DAO 使用的底层数据库对象。
func (dao *RoleDataScopeDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table 返回当前 DAO 对应的表名。
func (dao *RoleDataScopeDao) Table() string {
	return dao.table
}

// Columns 返回当前 DAO 对应表的全部列名。
func (dao *RoleDataScopeDao) Columns() RoleDataScopeColumns {
	return dao.columns
}

// Group 返回当前 DAO 使用的数据库配置分组名。
func (dao *RoleDataScopeDao) Group() string {
	return dao.group
}

// Ctx 创建当前 DAO 的模型，并自动绑定本次操作的上下文。
func (dao *RoleDataScopeDao) Ctx(ctx context.Context) *gdb.Model {
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
func (dao *RoleDataScopeDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
