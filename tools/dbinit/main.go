// 数据库初始化工具(幂等):
//   1. 总是应用 schema.sql(CREATE ... IF NOT EXISTS),库/表已存在则不动;
//   2. 仅当 role 表为空时,才导入 seed.sql 种子数据;
//   3. 已有数据一律保留,可反复安全执行。
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

	// 2. 空库才灌种子
	var cnt int
	if err = db.QueryRow("SELECT COUNT(*) FROM `security_permission`.`role`").Scan(&cnt); err != nil {
		exit("检查种子状态失败", err)
	}
	if cnt > 0 {
		fmt.Printf("ℹ️  role 表已有 %d 条数据,保留现有数据,跳过种子导入\n", cnt)
		return
	}
	if err = execFile(db, "manifest/sql/seed.sql"); err != nil {
		exit("导入 seed.sql 失败", err)
	}
	fmt.Println("✅ 空库,已导入种子数据")
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
