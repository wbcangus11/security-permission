// dbinit always rebuilds the demo database from the current schema and seed.
// It intentionally provides no migration or data-preservation behavior.
package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

const defaultDSN = "root:123456@tcp(127.0.0.1:3306)/?multiStatements=true&charset=utf8mb4&parseTime=true&loc=Local"

func main() {
	dsn := strings.TrimSpace(os.Getenv("DB_INIT_DSN"))
	if dsn == "" {
		dsn = defaultDSN
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		exit("连接数据库失败", err)
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		exit("连接数据库失败", err)
	}

	for _, path := range []string{
		"manifest/sql/schema.sql",
		"manifest/sql/menu.sql",
		"manifest/sql/seed.sql",
	} {
		if err = execFile(db, path); err != nil {
			exit("执行 "+path+" 失败", err)
		}
	}
	fmt.Println("✅ 已按当前 schema 重建 security_permission 并导入种子数据")
}

func execFile(db *sql.DB, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = db.Exec(string(content))
	return err
}

func exit(message string, err error) {
	fmt.Println("❌", message+":", err)
	os.Exit(1)
}
