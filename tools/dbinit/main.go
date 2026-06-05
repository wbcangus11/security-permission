// 数据库初始化工具(幂等):
//   1. 总是应用 schema.sql(CREATE ... IF NOT EXISTS),库/表已存在则不动;
//   2. 迁移:为已存在的旧表补加新列(如 user.is_superuser),MySQL 无 ADD COLUMN IF NOT EXISTS,故查 information_schema;
//   3. 仅当 role 表为空时,才导入 seed.sql 种子数据;
//   4. 确保存在一个超级管理员(is_superuser=1),新库旧库都补;
//   5. 已有数据一律保留,可反复安全执行。
//
// 用法(项目根目录):go run ./tools/dbinit
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

const dsn = "root:123456@tcp(127.0.0.1:3306)/?multiStatements=true&charset=utf8mb4&parseTime=true&loc=Local"

func main() {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		exit("连接失败", err)
	}
	defer db.Close()

	// 1. 建库 + 建表(幂等)
	if err = execFile(db, "manifest/sql/schema.sql"); err != nil {
		exit("应用 schema.sql 失败", err)
	}
	fmt.Println("✅ 表结构已就绪(已存在则跳过)")

	// 2. 迁移:旧表补列(user.is_superuser)
	if err = ensureColumn(db, "user", "is_superuser",
		"ALTER TABLE `security_permission`.`user` ADD COLUMN `is_superuser` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '超级管理员'"); err != nil {
		exit("迁移 user.is_superuser 失败", err)
	}

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
		"INSERT INTO `security_permission`.`user` (`name`,`org_id`,`is_superuser`) VALUES ('admin(超级管理员)',1,1)"); err != nil {
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
