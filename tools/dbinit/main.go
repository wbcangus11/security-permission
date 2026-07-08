// 数据库初始化工具(幂等):
//  1. 总是应用 schema.sql(CREATE ... IF NOT EXISTS),库/表已存在则不动;
//  2. 迁移:为已存在的旧表补加新列、调整列类型、统一单列 id 主键;
//  3. 总是应用 menu.sql,按 code 幂等同步内置菜单/权限点;
//  4. 仅当 role 表为空时,才导入 seed.sql 种子数据;
//  5. 确保存在一个超级管理员(is_superuser=1),新库旧库都补;
//  6. 已有数据一律保留,可反复安全执行。
//
// 用法(项目根目录):go run ./tools/dbinit
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

const dsn = "root:123456@tcp(127.0.0.1:3306)/?multiStatements=true&charset=utf8mb4&parseTime=true&loc=Local"

func main() {
	recreate := flag.Bool("recreate", false, "drop and recreate security_permission database before initialization")
	flag.Parse()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		exit("连接失败", err)
	}
	defer db.Close()

	if *recreate {
		if _, err = db.Exec("DROP DATABASE IF EXISTS `security_permission`"); err != nil {
			exit("重建库:删除旧库失败", err)
		}
		fmt.Println("✅ 已删除旧库 security_permission")
	}

	// 1. 建库 + 建表(幂等)
	if err = execFile(db, "manifest/sql/schema.sql"); err != nil {
		exit("应用 schema.sql 失败", err)
	}
	fmt.Println("✅ 表结构已就绪(已存在则跳过)")

	// 2. 迁移:旧表补列(user.is_superuser / menu 新字段)
	if err = ensureColumn(db, "user", "is_superuser",
		"ALTER TABLE `security_permission`.`user` ADD COLUMN `is_superuser` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '超级管理员'"); err != nil {
		exit("迁移 user.is_superuser 失败", err)
	}
	if err = ensureColumnType(db, "user", "id", "varchar",
		"ALTER TABLE `security_permission`.`user` MODIFY COLUMN `id` VARCHAR(64) NOT NULL COMMENT '用户ID'"); err != nil {
		exit("迁移 user.id 类型失败", err)
	}
	if err = ensureColumnType(db, "user_role", "user_id", "varchar",
		"ALTER TABLE `security_permission`.`user_role` MODIFY COLUMN `user_id` VARCHAR(64) NOT NULL COMMENT '用户ID'"); err != nil {
		exit("迁移 user_role.user_id 类型失败", err)
	}
	if err = ensureColumnType(db, "role", "created_by", "varchar",
		"ALTER TABLE `security_permission`.`role` MODIFY COLUMN `created_by` VARCHAR(64) NOT NULL DEFAULT '0' COMMENT '创建人(委派来源用户),0为系统创建/不受限'"); err != nil {
		exit("迁移 role.created_by 类型失败", err)
	}
	if err = ensureSurrogatePrimary(db, "action",
		"ALTER TABLE `security_permission`.`action` DROP PRIMARY KEY, ADD COLUMN `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '操作项ID' FIRST, ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `uk_action_code` (`code`)"); err != nil {
		exit("迁移 action.id 主键失败", err)
	}
	if err = ensureSurrogatePrimary(db, "role_menu",
		"ALTER TABLE `security_permission`.`role_menu` DROP PRIMARY KEY, ADD COLUMN `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '角色菜单关系ID' FIRST, ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `uk_role_menu` (`role_id`,`menu_id`)"); err != nil {
		exit("迁移 role_menu.id 主键失败", err)
	}
	if err = ensureSurrogatePrimary(db, "role_data_scope",
		"ALTER TABLE `security_permission`.`role_data_scope` DROP PRIMARY KEY, ADD COLUMN `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '角色数据范围ID' FIRST, ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `uk_role_scope` (`role_id`,`scope_type`,`node_id`)"); err != nil {
		exit("迁移 role_data_scope.id 主键失败", err)
	}
	if err = ensureSurrogatePrimary(db, "role_resource_action",
		"ALTER TABLE `security_permission`.`role_resource_action` DROP PRIMARY KEY, ADD COLUMN `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '角色资源操作ID' FIRST, ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `uk_role_resource_action` (`role_id`,`resource_id`,`action_code`)"); err != nil {
		exit("迁移 role_resource_action.id 主键失败", err)
	}
	if err = ensureSurrogatePrimary(db, "user_role",
		"ALTER TABLE `security_permission`.`user_role` DROP PRIMARY KEY, ADD COLUMN `id` BIGINT NOT NULL AUTO_INCREMENT COMMENT '用户角色关系ID' FIRST, ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `uk_user_role` (`user_id`,`role_id`)"); err != nil {
		exit("迁移 user_role.id 主键失败", err)
	}
	for _, idx := range []struct {
		table string
		name  string
		sql   string
	}{
		{"action", "uk_action_code", "ALTER TABLE `security_permission`.`action` ADD UNIQUE KEY `uk_action_code` (`code`)"},
		{"role_menu", "uk_role_menu", "ALTER TABLE `security_permission`.`role_menu` ADD UNIQUE KEY `uk_role_menu` (`role_id`,`menu_id`)"},
		{"role_data_scope", "uk_role_scope", "ALTER TABLE `security_permission`.`role_data_scope` ADD UNIQUE KEY `uk_role_scope` (`role_id`,`scope_type`,`node_id`)"},
		{"role_resource_action", "uk_role_resource_action", "ALTER TABLE `security_permission`.`role_resource_action` ADD UNIQUE KEY `uk_role_resource_action` (`role_id`,`resource_id`,`action_code`)"},
		{"user_role", "uk_user_role", "ALTER TABLE `security_permission`.`user_role` ADD UNIQUE KEY `uk_user_role` (`user_id`,`role_id`)"},
	} {
		if err = ensureIndex(db, idx.table, idx.name, idx.sql); err != nil {
			exit("迁移唯一索引 "+idx.table+"."+idx.name+" 失败", err)
		}
	}
	if err = ensureMenuColumns(db); err != nil {
		exit("迁移 menu 表失败", err)
	}
	if err = execFile(db, "manifest/sql/menu.sql"); err != nil {
		exit("同步 menu.sql 失败", err)
	}
	fmt.Println("✅ 菜单/权限点已同步")

	// 3. 空库才灌种子
	var cnt int
	if err = db.QueryRow("SELECT COUNT(*) FROM `security_permission`.`role`").Scan(&cnt); err != nil {
		exit("检查种子状态失败", err)
	}
	if cnt > 0 {
		fmt.Printf("ℹ️  role 表已有 %d 条数据,保留现有数据,跳过种子导入\n", cnt)
	} else {
		if err = execFile(db, "manifest/sql/seed.sql"); err != nil {
			exit("导入 seed.sql 失败", err)
		}
		fmt.Println("✅ 空库,已导入种子数据")
	}

	// 4. 确保超级管理员存在(幂等:无任何 superuser 才建)
	if err = ensureAdmin(db); err != nil {
		exit("确保超级管理员失败", err)
	}
}

// ensureColumn 列不存在时执行 alterSQL(幂等迁移)。
func ensureColumn(db *sql.DB, table, col, alterSQL string) error {
	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='security_permission' AND TABLE_NAME=? AND COLUMN_NAME=?",
		table, col).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil // 列已存在
	}
	if _, err := db.Exec(alterSQL); err != nil {
		return err
	}
	fmt.Printf("✅ 迁移:已为 %s 表补加列 %s\n", table, col)
	return nil
}

func ensureColumnType(db *sql.DB, table, col, wantDataType, alterSQL string) error {
	var dataType string
	if err := db.QueryRow(
		"SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='security_permission' AND TABLE_NAME=? AND COLUMN_NAME=?",
		table, col).Scan(&dataType); err != nil {
		return err
	}
	if strings.EqualFold(dataType, wantDataType) {
		return nil
	}
	if _, err := db.Exec(alterSQL); err != nil {
		return err
	}
	fmt.Printf("✓ 迁移:已修改 %s.%s 类型为 %s\n", table, col, wantDataType)
	return nil
}

func ensureSurrogatePrimary(db *sql.DB, table, alterSQL string) error {
	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='security_permission' AND TABLE_NAME=? AND COLUMN_NAME='id'",
		table).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := db.Exec(alterSQL); err != nil {
		return err
	}
	fmt.Printf("✅ 迁移:已为 %s 表改为 id 单列主键\n", table)
	return nil
}

// ensureMenuColumns 兼容旧版库里的 menu 表。
// CREATE TABLE IF NOT EXISTS 不会修改旧表结构,所以这里显式补齐本轮菜单表设计需要的列和唯一索引。
func ensureMenuColumns(db *sql.DB) error {
	migrations := []struct {
		column string
		sql    string
	}{
		{"type", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `type` VARCHAR(20) NOT NULL DEFAULT 'MENU' COMMENT '类型' AFTER `domain`"},
		{"route", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `route` VARCHAR(200) DEFAULT NULL COMMENT '前端路由' AFTER `type`"},
		{"component", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `component` VARCHAR(200) DEFAULT NULL COMMENT '前端组件标识' AFTER `route`"},
		{"icon", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `icon` VARCHAR(100) DEFAULT NULL COMMENT '图标' AFTER `component`"},
		{"sort", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `sort` INT NOT NULL DEFAULT 0 COMMENT '同级排序' AFTER `icon`"},
		{"visible", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `visible` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否显示' AFTER `sort`"},
		{"enabled", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `enabled` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用' AFTER `visible`"},
		{"description", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `description` VARCHAR(255) DEFAULT NULL COMMENT '说明' AFTER `enabled`"},
		{"created_at", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `created_at` DATETIME DEFAULT NULL COMMENT '创建时间' AFTER `description`"},
		{"updated_at", "ALTER TABLE `security_permission`.`menu` ADD COLUMN `updated_at` DATETIME DEFAULT NULL COMMENT '更新时间' AFTER `created_at`"},
	}
	for _, m := range migrations {
		if err := ensureColumn(db, "menu", m.column, m.sql); err != nil {
			return err
		}
	}
	return ensureIndex(db, "menu", "uk_menu_code",
		"ALTER TABLE `security_permission`.`menu` ADD UNIQUE KEY `uk_menu_code` (`code`)")
}

func ensureIndex(db *sql.DB, table, indexName, alterSQL string) error {
	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='security_permission' AND TABLE_NAME=? AND INDEX_NAME=?",
		table, indexName).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := db.Exec(alterSQL); err != nil {
		return err
	}
	fmt.Printf("✅ 迁移:已为 %s 表补加索引 %s\n", table, indexName)
	return nil
}

// ensureAdmin 确保存在至少一个超级管理员账号(仿海康内置 root)。幂等:已有 superuser 则不动。
func ensureAdmin(db *sql.DB) error {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM `security_permission`.`user` WHERE `is_superuser`=1").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("ℹ️  已存在 %d 个超级管理员,跳过\n", n)
		return nil
	}
	if _, err := db.Exec(
		"INSERT INTO `security_permission`.`user` (`id`,`name`,`org_id`,`is_superuser`) VALUES ('4','admin(超级管理员)',1,1) ON DUPLICATE KEY UPDATE `name`=VALUES(`name`),`org_id`=VALUES(`org_id`),`is_superuser`=VALUES(`is_superuser`)"); err != nil {
		return err
	}
	fmt.Println("✅ 已创建超级管理员账号:admin(超级管理员)")
	return nil
}

func execFile(db *sql.DB, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = db.Exec(string(b))
	return err
}

func exit(msg string, err error) {
	fmt.Println("❌", msg, ":", err)
	os.Exit(1)
}
