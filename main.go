package main

import (
	_ "github.com/gogf/gf/contrib/drivers/mysql/v2" // 注册 MySQL 驱动

	"github.com/gogf/gf/v2/os/gctx"

	"security-permission/internal/cmd"
)

func main() {
	cmd.Main.Run(gctx.GetInitCtx())
}
