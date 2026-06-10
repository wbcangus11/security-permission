// 造数工具(opt-in,演示/压测用):在「园区A」下批量生成区域 + 摄像头,
// 让"区域树按层分页"和"资源列表分页"真正可见、可验证。
//
// 设计:
//   - 所有生成的节点名带前缀「压测」,便于一键清理与重跑(幂等:先清旧的再造新的)。
//   - 物化路径严格维护:每插一条 area,path = 父.path + 新id + "/"。
//   - 默认在园区A下生成 150 栋楼,每栋 2 层,每层 3 个摄像头 → 园区A 直接子节点 >100(触发分页),
//     园区A 子树资源 900 个(触发资源分页)。
//
// 用法(项目根目录):
//   go run ./tools/genbulk            # 清旧 + 造数(默认 150 栋)
//   go run ./tools/genbulk 300        # 自定义楼栋数
//   go run ./tools/genbulk clean      # 仅清理压测数据
//
// 造完需重启服务(让 service.S.Reload 把新数据载入缓存)。
package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

const dsn = "root:123456@tcp(127.0.0.1:3306)/security_permission?charset=utf8mb4&parseTime=true&loc=Local"

const (
	mark            = "压测"  // 生成数据的名称前缀(清理识别用)
	floorsPerBldg   = 2     // 每栋楼层数
	camerasPerFloor = 3     // 每层摄像头数
)

func main() {
	db, err := sql.Open("mysql", dsn)
	must("连接失败", err)
	defer db.Close()

	// 先清理旧的压测数据(幂等可重跑)
	cleanup(db)
	if len(os.Args) > 1 && os.Args[1] == "clean" {
		fmt.Println("✅ 已清理压测数据(clean 模式,不再造数)")
		return
	}

	buildings := 150
	if len(os.Args) > 1 {
		if n, e := strconv.Atoi(os.Args[1]); e == nil && n > 0 {
			buildings = n
		}
	}

	// 找「园区A」作为生成根
	var parentId int
	var parentPath string
	err = db.QueryRow("SELECT id, path FROM area WHERE name='园区A' LIMIT 1").Scan(&parentId, &parentPath)
	if err == sql.ErrNoRows {
		must("未找到名为「园区A」的区域(请先跑 dbinit 灌种子)", fmt.Errorf("park A not found"))
	}
	must("查询园区A失败", err)
	fmt.Printf("📍 生成根:园区A(id=%d, path=%s)\n", parentId, parentPath)

	nArea, nCam := 0, 0
	for b := 1; b <= buildings; b++ {
		bId, bPath := insertArea(db, parentId, parentPath, fmt.Sprintf("%s%d号楼", mark, b), b)
		nArea++
		for f := 1; f <= floorsPerBldg; f++ {
			fId, _ := insertArea(db, bId, bPath, fmt.Sprintf("%s%d-%d层", mark, b, f), f)
			nArea++
			for k := 1; k <= camerasPerFloor; k++ {
				insertCamera(db, fId, fmt.Sprintf("%sCam-%d-%d-%d", mark, b, f, k))
				nCam++
			}
		}
		if b%50 == 0 {
			fmt.Printf("  ... 已生成 %d 栋\n", b)
		}
	}
	fmt.Printf("✅ 完成:园区A 下新增 %d 栋楼,共 %d 个区域 + %d 个摄像头\n", buildings, nArea, nCam)
	fmt.Printf("   园区A 直接子节点现已 >%d 条(触发树分页);园区A 子树资源 %d 个(触发资源分页)\n", buildings, nCam)
	fmt.Println("👉 重启服务后,用李四(园区A值班员)登录应用端浏览即可看到懒加载分页。")
}

// insertArea 插入一个区域并维护物化路径,返回新 id 与其 path。
func insertArea(db *sql.DB, parentId int, parentPath, name string, sort int) (int, string) {
	res, err := db.Exec("INSERT INTO area (parent_id, name, path, sort) VALUES (?,?,'',?)", parentId, name, sort)
	must("插入区域失败", err)
	id64, _ := res.LastInsertId()
	id := int(id64)
	path := fmt.Sprintf("%s%d/", parentPath, id)
	_, err = db.Exec("UPDATE area SET path=? WHERE id=?", path, id)
	must("更新区域 path 失败", err)
	return id, path
}

func insertCamera(db *sql.DB, areaId int, name string) {
	_, err := db.Exec("INSERT INTO resource (area_id, type, name) VALUES (?, 'camera', ?)", areaId, name)
	must("插入摄像头失败", err)
}

// cleanup 删除所有压测生成的数据(摄像头 + 区域)。
func cleanup(db *sql.DB) {
	rc, err := db.Exec("DELETE FROM resource WHERE name LIKE ?", mark+"%")
	must("清理压测摄像头失败", err)
	ra, err := db.Exec("DELETE FROM area WHERE name LIKE ?", mark+"%")
	must("清理压测区域失败", err)
	nc, _ := rc.RowsAffected()
	na, _ := ra.RowsAffected()
	if nc > 0 || na > 0 {
		fmt.Printf("🧹 已清理旧压测数据:区域 %d 个,摄像头 %d 个\n", na, nc)
	}
}

func must(msg string, err error) {
	if err != nil {
		fmt.Println("❌", msg, ":", err)
		os.Exit(1)
	}
}
