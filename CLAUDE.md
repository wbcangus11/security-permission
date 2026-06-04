# 项目:基于角色的权限系统(仿海康安防平台)

GoFrame(gf v2)实现的 RBAC + 数据权限演示系统,前端仿**海康安防管理平台**红黑风格。
核心是**功能权限 + 数据权限**两个维度,并实现了**受控委派(二次授权)**。

> **接着干之前先读这份 CLAUDE.md + `docs/权限设计说明.md`(完整设计)+ `docs/测试报告.md`(已验证场景)。**
> 这是一个持续完善中的项目,用户会不断提需求让你迭代。

---

## 一句话现状

功能已相当完整:鉴权引擎、二次授权合并、MySQL 持久化、前端有「应用端(卡片首页+区域资源浏览)」和「系统管理后台(深色菜单驱动配置界面)」两大块,4 类管理界面(区域/组织/角色/账号)。**31/31 自动化测试通过**。

---

## 关键设计决策(已和用户确认,勿擅自改变)

1. **两个权限维度**:功能权限(角色→菜单,菜单分 SYS 系统管理域 / APP 应用域)+ 数据权限(角色→区域树/组织树/业务资源)。两者同时满足才放行。
2. **数据权限挂在树上,物化路径 `path` 前缀判断子树**:存 `{节点, include_child}`,不展开子节点;授权子树后**新增子节点自动继承**(`path LIKE '授权节点path%'`)。**系统只有一个根区域**,故授权根=拥有现在及将来全部区域;新增区域时必须算对 `path`=父.path+新ID+"/"。
3. **业务资源权限两层**:区域范围(粗,继承新资源)+ 资源级操作精细配置(细;有精细=覆盖模式只给所列操作,无精细=继承区域全部操作)。
4. **二次授权 = 受控委派,模型 A(写时校验 + 合并,不级联)**,已实测对齐海康:
   - 已建角色有效权限**不级联**(创建人被收权,旧角色不变)。
   - 编辑界面按创建人当前权限**实时过滤**(超范围节点前端**隐藏**)。
   - 保存时**合并**:`最终 = (提交 ∩ 创建人可授范围) ∪ (原有 \ 创建人可授范围)`,范围外原有权限原样保留(看不到也删不掉)。
   - 实现:`service/delegation.go` 的 `GrantableSet` 与 `MergeDelegated`。
   - **未来若要升级**到模型 B(运行时取交集)/ C(变更级联):`role.created_by` 字段已预留。
5. **存储**:MySQL(库 `security_permission`,root/123456)为持久层;启动 `service.S.Reload(ctx)` 全量载入内存缓存,鉴权读缓存,写角色/用户落库后刷新缓存。`role_data_scope` 一张表用 `scope_type`(AREA/ORG/RES_AREA)统一三种树范围。
6. **前端两大块对应两个域**:应用端=应用域(看监控,RES_AREA);系统管理后台=系统域(系统菜单 + 安保区域管理 AREA + 组织管理 ORG)。"应用域有权 ≠ 管理域有权"(如李四能看监控但后台为空)。

---

## 代码结构

```
internal/
  model/permission.go        领域模型(Area/Org/Menu/Resource/Role/User…)
  service/
    store.go                 内存缓存 + 读方法
    db.go                    MySQL 加载(Reload)/ 写回(SaveRole, SaveUser)
    auth.go                  鉴权引擎(菜单/区域/组织/资源 三关)★
    delegation.go            二次授权:GrantableSet + MergeDelegated ★
    runtime.go               应用端/后台体验:可见树、资源、菜单(VisibleAreas/ManageAreas/ManageOrgs/AreaResources/SysMenus/AppMenus…)
  controller/perm/perm.go    全部 HTTP 接口
  cmd/cmd.go                 路由 + 启动时 Reload + 静态目录
resource/public/index.html   前端单页(所有 UI + JS,无构建步骤)★
manifest/sql/schema.sql      建表 DDL(幂等)
manifest/sql/seed.sql        种子数据
tools/dbinit/main.go         幂等初始化:建表 + 空库才灌种子(保留已有数据)
tools/debug-build.ps1        带重试的 debug 二进制构建(绕 360 拦截,见下)
docs/权限设计说明.md          通俗设计文档
docs/测试报告.md              31/31 场景测试报告
```

## 前端 UI 结构(index.html,纯 JS 无框架)

- 顶部:深色栏 + 红色品牌;右上「当前登录」用户切换(驱动体验);两个主 Tab。
- **应用端(体验)**:卡片首页(应用菜单按父分组成卡片)→ 点视频监控类卡片进"区域树+资源浏览"(按权限置灰操作按钮;点无权区域→暂无操作权限)。
- **系统管理(后台)**:深色左侧菜单(登录用户有权的系统菜单),点击切换右侧:
  - 人员信息 → 组织机构(左树右详情)
  - 安保区域管理 → 区域(左树右详情)
  - 角色管理 → 角色配置(含二次授权"操作者"选择 + 鉴权测试面板)
  - 账号管理 → 用户/账号管理(建用户绑角色)
  - 其他菜单 → 演示占位
- 路由表在 JS 的 `SYS_ROUTE`。

## HTTP 接口一览

`/api/meta` `/api/roles[/{id}]`(GET) `/api/roles?actor=`(POST,委派合并) `/api/grantable?actor=`
`/api/check`(鉴权测试) `/api/users`(POST 建用户)
应用端:`/api/app-menus` `/api/visible-areas` `/api/area-resources`(均 ?userId=)
后台:`/api/sys-menus` `/api/manage-areas` `/api/manage-orgs` `/api/manage-area-detail` `/api/manage-org-detail`

---

## 怎么跑

```bash
go run ./tools/dbinit   # 幂等初始化数据库(可反复运行)
go run main.go          # 启动,访问 http://127.0.0.1:8000/
```
种子用户:张三(uid=1,安防管理员,全菜单+区域/组织/资源)、李四(uid=2,园区A值班员,仅应用域)、王五(uid=3,双角色)。
**测试动线**:配角色/建用户需先把"当前登录"切到有系统管理权的用户(张三),进后台操作;再切到目标用户去应用端体验。

---

## 已知环境坑(重要)

- **GoLand debug 报 `usage: compile`**:是 **360安全卫士**拦截 debug 全量重编(`all=-N -l`)瞬间拉起的大量 `compile.exe`,与代码/dlv 无关(flaky)。360 退不掉。**绕法**:`powershell -ExecutionPolicy Bypass -File tools\debug-build.ps1` 构建 `app_debug.exe`(带重试会收敛),再 GoLand **Attach to Process**。
- **重启服务前务必按 PID 杀旧进程**(端口 8000 易被占,否则 curl/浏览器打到旧实例的旧缓存):
  `PID=$(netstat -ano | grep ":8000 " | head -1 | awk '{print $NF}'); taskkill //F //PID $PID`
- Windows 控制台对中文 JSON 显示乱码是编码问题,数据本身是好的 UTF-8。
- 每次重大改动后建议 `go vet ./...`;index.html 改完用 `grep -c '<div' / '</div>'` 验 div 平衡。

---

## git 状态(2026-06-03)

- 已提交到 `1a6b9cd`(初始化→红黑风格→后台IA重排)。
- **工作区有未提交改动**:`manifest/sql/seed.sql`(给管理员加 ORG 授权)、`resource/public/index.html`(前台卡片化 + 组织挪到"人员信息"左树右详情)。
- **重要约定:用户明确要求"我说提交再提交",不要自动 git commit。** 改完等用户确认。

---

## 待办 / 用户可能继续提的方向

- 新增/移动区域接口(自动维护 path,移动子树批量更新子孙 path)——这是把"自动继承"用起来的关键。
- `gf gen dao` 生成标准 dao 替代手写 `g.Model`。
- 角色删除接口、组织/区域的增删改真实落库(目前后台详情是只读展示)。
- 二次授权升级到模型 B/C(`created_by` 已预留)。
- 应用端更多模块卡片的真实界面(目前非视频类是占位)。
- 用户偏好:决策(如委派模型)倾向**先调研真实海康行为再定**;喜欢**每步有验证/测试**;前端**仿海康红黑风格**。
