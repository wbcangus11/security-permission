# Security Permission

基于 GoFrame v2 的 RBAC + 数据权限工程，模拟海康 iSecure Center 的功能权限、树形数据范围和受控委派行为。

## Architecture

项目采用 GoFrame 官方复杂业务工程分层：

```text
api/                         HTTP Req/Res 契约
internal/controller/         HTTP 参数转换与响应
internal/service/            业务接口及实现注册
internal/logic/permission/   权限业务实现
internal/dao/                GoFrame DAO
internal/model/              领域模型、业务 Input/Output、DO、Entity
internal/middleware/         请求身份边界
internal/cmd/                启动、路由和中间件注册
manifest/                    配置与 SQL
resource/public/             无构建步骤的演示前端
tools/dbinit/                幂等数据库初始化和迁移
```

依赖方向固定为：`api → controller → service(interface) → logic → dao`。控制器和其他业务模块不直接依赖 `logic`。

GoFrame 官方参考：<https://goframe.org/en/2.9.x/docs/design/project-structure>

## Run

本地默认连接 MySQL `security_permission`。可用 `DB_INIT_DSN` 覆盖初始化工具连接；应用环境建议通过独立配置文件覆盖数据库连接。

```powershell
go run ./tools/dbinit
go run main.go
```

浏览器访问 <http://127.0.0.1:8000/>。

端口被占用时可临时覆盖：`$env:APP_SERVER_ADDRESS=":8001"`。

本地配置启用 `security.demoMode=true`，用于保留页面上的“切换当前登录用户”。生产配置必须关闭 demo 模式，并由可信认证网关写入 `security.trustedUserHeader`；HTTP 请求永远不能使用内部维护身份 `"0"`。

生产环境推荐准备独立配置文件并通过 GoFrame 标准环境变量选择：

```powershell
$env:GF_GCFG_FILE = "config.prod.yaml"
go run main.go
```

## Verify

```powershell
go test ./...
go build ./...
```

权限语义、种子账号和人工验证场景见 `docs/权限设计说明.md`、`docs/设计导读.md` 和 `docs/测试报告.md`。
