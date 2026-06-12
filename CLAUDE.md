# 项目:基于角色的权限系统(仿海康安防平台)

GoFrame(gf v2)实现的 RBAC + 数据权限演示系统,前端仿**海康安防管理平台**红黑风格。
核心是**功能权限 + 数据权限**两个维度,并实现了**受控委派(二次授权)**。

> **接着干之前先读这份 CLAUDE.md + `docs/权限设计说明.md`(完整设计)+ `docs/测试报告.md`(已验证场景)。**
> 这是一个持续完善中的项目,用户会不断提需求让你迭代。

---

## 一句话现状

功能已相当完整:鉴权引擎、二次授权合并、MySQL 持久化、前端有「应用端(卡片首页+区域资源浏览)」和「系统管理后台(深色菜单驱动配置界面)」两大块,4 类管理界面(区域/组织/角色/账号)。**核心 31/31 + 区域 11 + 超管 10 + 组织 12 + 角色删除 14 + 资源 13 + 显式角色范围/模型B 11 + 资源级可见 6 + 数据下推分页 17 全部测试通过**。
区域**与组织**均已支持**真实增删改 + 物化路径自动维护**(写时鉴权;移动子树批量重写 path;删除清理授权引用):区域见测试报告 §九(11 项),组织见 §十一(12 项),两者共用同一套 path-维护引擎,仅「非空」判定不同(区域=无资源,组织=无子组织且无下属用户)。
**角色**支持**真实删除**(§十二,14 项):委派校验(普通操作人只能删自己创建的 `created_by`,超管/不受限删任意)+ 级联清理(含 `user_role`,绑用户也直接删 → 用户失权);配套修正了 `created_by`(仅新建时记,编辑不覆盖)。
**资源(摄像头)**支持**真实增删改**(§十三,13 项):功能关 `sys.resource` + 数据关 `CheckArea(所在区域)`;新增自动被覆盖该区域 RES_AREA 的角色继承;移动改 `area_id`;删除清理 `role_resource_action`。至此**数据树增删改三件套(区域/组织/资源)全部完成**。
**委派已升级到模型 A + 模型 B**(§十四,11 项):新增**显式角色范围**——角色可配「可管理哪些其他角色」。**「可见」与「可编辑/删除」分离**(2026-06-11 细化):可见集 = (自己创建的 `created_by`) ∪ (本人各角色「角色范围」并集),驱动角色列表显示 + 角色范围维度可再委派上限;可编辑/删除集 = **仅自建**(`OwnedRoles`),角色范围内的角色对操作者**只读**(可见、可再委派,但不能编辑/删除)。对照真实海康(`docs/海康对照.md`)补齐的唯一结构性差距;复用 `role_data_scope` 的 `scope_type='ROLE'`,零 DDL 迁移。
**应用端资源级可见**(§十五,6 项):业务资源两级数据权限补齐 L2 可见性——精细模式且零操作=该资源应用端列表隐藏(对齐海康「区域级继承 + 资源级查看」)。「精细模式」显式持久化(`Role.ResourceOverrides`,复用 `role_data_scope` `scope_type='RESOVR'`,零 DDL,向后兼容)。
**数据权限下推 + 懒加载分页**(§十六,17 项):把数据权限从「点查鉴权」扩展到「列表过滤 + 分页下推 SQL」,支撑大数据量。区域树**按层懒加载**(每次只查一层 `parent_id`)、资源列表**分页**,数据权限作为 SQL WHERE **下推数据库**(含子树授权→`path LIKE '根path%'` 走 `idx_path`;仅本节点→`id=节点`;根含子树/超管→不加过滤;无范围→空结果)。鉴权(`auth.go` 点查,读缓存微秒级)与过滤分页(`paging.go` 列表,scope 拼进 WHERE)互补。应用树(RES_AREA)/管理树(AREA)/移动选择器共用 `paging.go` 同一核心(`scopePicker` 注入差异)。**搜索对齐真实海康**:结果按局部树展示(`SearchAreas` 回传祖先链 `Ancestors`,前端拼命中分支 + 匹配高亮)、**最多前 500 条**(`searchLimit`,超出给横幅)、同样叠加可见性 WHERE 下推。配 `tools/genbulk` 造数(园区A 下 150 栋楼=450 区域+900 摄像头,触发分页;搜索 500 截断验证用 `genbulk 200`)。**零 DDL**(只读 `area.path`/`idx_path`)。

---

## 关键设计决策(已和用户确认,勿擅自改变)

1. **两个权限维度**:功能权限(角色→菜单,菜单分 SYS 系统管理域 / APP 应用域)+ 数据权限(角色→区域树/组织树/业务资源)。两者同时满足才放行。**例外:超级管理员**(`user.is_superuser`,仿海康内置 root)鉴权三关直接放行,拥有现有及将来全部权限,与数据权限模型解耦(引擎层特例,不依赖角色/数据范围)。短路点:`auth.go` 三关 + `delegation.go` 的 `userHasMenuId`/`userResAreaCovers`/`GrantableSet`/`MergeDelegated`。种子内置 admin 账号(`tools/dbinit` 幂等补列 + 确保至少一个超管)。
2. **数据权限挂在树上,物化路径 `path` 前缀判断子树**:存 `{节点, include_child}`,不展开子节点;授权子树后**新增子节点自动继承**(`path LIKE '授权节点path%'`)。**系统只有一个根区域**,故授权根=拥有现在及将来全部区域;新增区域时必须算对 `path`=父.path+新ID+"/"。
3. **业务资源权限两层**:区域范围(粗,继承新资源)+ 资源级操作精细配置(细;有精细=覆盖模式只给所列操作,无精细=继承区域全部操作)。**资源级可见**(对齐海康前台两级):精细模式且零操作=该资源零权限→应用端列表隐藏;为此「精细模式」显式持久化(`Role.ResourceOverrides`,复用 `role_data_scope` `scope_type='RESOVR'`,零 DDL),`auth.go` `hasOverride = ResourceOverrides ∪ 有操作行`(兼容旧数据),`runtime.go` `AreaResources` 过滤零操作资源,`delegation.go` 把精细标记并入合并(第6维)。
4. **二次授权 = 受控委派,模型 A(写时校验 + 合并,不级联)+ 模型 B(显式角色范围)**,已实测对齐海康:
   - **权限维度合并(模型 A)**:已建角色有效权限**不级联**(创建人被收权,旧角色不变);编辑界面按创建人当前权限**实时过滤**(超范围节点前端**隐藏**);保存时**合并**:`最终 = (提交 ∩ 创建人可授范围) ∪ (原有 \ 创建人可授范围)`,范围外原有权限原样保留(看不到也删不掉)。实现:`service/delegation.go` 的 `GrantableSet` 与 `MergeDelegated`(5 个维度:菜单/区域/组织/资源操作/**角色范围**)。
   - **操作者(actor)= 当前登录用户**(2026-06-11):前端角色管理已**移除独立「操作者(创建人)」下拉**(原默认「系统管理员(不受限)」会让任何登录用户越权——这是用户反馈的 bug:王五能删 admin 创建的角色)。现 `actorId()` 恒等于 `loginUserId()`,可见/编辑/删除全按登录用户身份判定;切「当前登录」即换操作者身份。
   - **可管理角色集(模型 B)·「可见」与「可编辑/删除」分离**(2026-06-11 按用户要求细化):
     - **可见集**(角色管理列表显示哪些角色)= `manageable(actor) = (自己创建的 created_by) ∪ (本人各角色「角色范围」RoleScopes 并集)`,单层不级联。同时也是「角色范围」维度可再委派的上限(`Grantable.RoleIds`)。实现:`delegation.go` 的 `ManageableRoles`/`GrantableSet`;前端 `GRANT.roleIds`→`roleCanSee` 过滤列表 + 置灰委派树。对齐海康原文「可选择的角色范围 = 勾选的角色 ∪ 用户自行创建的角色」。
     - **可编辑/删除集** = `owned(actor) = (仅自己创建的 created_by)`。**角色范围内的角色对本操作者只读**:列表可见、可作为他人角色范围再委派,但不能编辑/删除。实现:`delegation.go` 的 `OwnedRoles`;`role.go` 的 `GuardManageRole`(编辑删除共用门禁);`perm.go` saveRole 编辑门禁。前端 `roleCanManage`=`createdBy==actorId`(驱动列表 🔒/删除按钮 + 编辑只读 banner)。
   - **角色删除**(`service/role.go` `DeleteRole`):不受限(actor=0)/超管删任意;普通操作人须有「角色管理」菜单(`sys.person.role`)且角色为**自己创建**(`owned` 集,经 `GuardManageRole`)。绑用户也直接删(级联清 `user_role`,用户失权);**并清理别的角色对被删角色的 `scope_type='ROLE'` 引用**(与删区域清授权引用对称)。
   - **`created_by` 语义**:仅**新建**时记为操作人,**编辑**时保持原值不变(`perm.go` 区分 old==nil)。这是 `owned`(=可编辑/删除)与 `manageable` 含「自建角色」那一半的共同前提。
   - 角色范围存储复用 `role_data_scope`(`scope_type='ROLE'`,`node_id`=被管理角色 id,角色无树故 `include_child` 不参与判定);**模型 C(变更级联)**仍可后续升级。
5. **存储**:MySQL(库 `security_permission`,root/123456)为持久层;启动 `service.S.Reload(ctx)` 全量载入内存缓存,鉴权读缓存,写角色/用户落库后刷新缓存。`role_data_scope` 一张表用 `scope_type`(AREA/ORG/RES_AREA/**ROLE**)统一三种树范围 + 角色范围(模型 B)。
6. **前端两大块对应两个域**:应用端=应用域(看监控,RES_AREA);系统管理后台=系统域(系统菜单 + 安保区域管理 AREA + 组织管理 ORG)。"应用域有权 ≠ 管理域有权"(如李四能看监控但后台为空)。

---

## 代码结构

```
api/
  perm/v1/perm.go           GoFrame 规范路由请求定义(g.Meta path/method),仅 GET/POST、动作式路径
internal/
  model/permission.go        领域模型(Area/Org/Menu/Resource/Role/User…)
  service/
    store.go                 内存缓存 + 读方法
    db.go                    MySQL 加载(Reload)/ 写回(SaveRole, SaveUser)
    auth.go                  鉴权引擎(菜单/区域/组织/资源 三关)★
    delegation.go            二次授权:GrantableSet(含 RoleIds)+ MergeDelegated(5 维含角色范围)+ ManageableRoles(模型B 可见集=自建∪角色范围)+ OwnedRoles(可编辑/删除=仅自建)★
    runtime.go               应用端/后台体验:可见树、资源、菜单(VisibleAreas/ManageAreas/ManageOrgs/AreaResources/SysMenus/AppMenus…)
    paging.go                数据权限「用」之二:scope→SQL WHERE 下推 + 按层懒加载树 + 列表分页(treeScopeFilter/areaScopeWhere/AreaChildren/ManageAreaChildren/SearchAreas/AreaResourcesPaged)★
    area.go                  区域增删改:写时鉴权 + path 自动维护(SaveArea 新增/重命名/移动 + DeleteArea)★
    org.go                   组织增删改:与 area.go 完全对称,功能关=人员信息 sys.person.info,删除前置=无子组织且无下属用户 ★
    role.go                  角色删除 + GuardManageRole(编辑/删除共用门禁=功能关 sys.person.role + 角色须在 owned 集=仅自建;角色范围内的角色只读);级联清理(含 user_role + 清别角色的 ROLE 范围引用)★
    resource.go              资源(摄像头)增删改:功能关 sys.resource + 数据关 CheckArea(所在区域);新增自动被 RES_AREA 角色继承;删除清理 role_resource_action ★
  controller/perm/perm.go    HTTP 处理函数 + Register(group.Bind(NewV1()))
  controller/perm/perm_v1_routes.go GoFrame 规范路由方法,复用现有处理函数
  cmd/cmd.go                 路由 + 启动时 Reload + 静态目录
resource/public/index.html   前端单页(所有 UI + JS,无构建步骤)★
manifest/sql/schema.sql      建表 DDL(幂等)
manifest/sql/seed.sql        种子数据
tools/dbinit/main.go         幂等初始化:建表 + 空库才灌种子(保留已有数据)
tools/genbulk/main.go        造数(演示/压测):园区A 下批量生成区域+摄像头,触发懒加载分页;`压测` 前缀幂等可清(`go run ./tools/genbulk clean`)
tools/debug-build.ps1        带重试的 debug 二进制构建(绕 360 拦截,见下)
tools/shot.mjs               UI 截图验证(零依赖,CDP 驱动 Chrome):node tools/shot.mjs out.png "页面内JS" [等待ms]
docs/设计导读.md              新人入门:一步步看懂设计的阅读路线(心智模型→引擎→难点,边读边验证)
docs/权限设计说明.md          通俗设计文档
docs/测试报告.md              场景测试报告(核心+各专项)
docs/海康对照.md              真实海康 iSecure Center 对照验证
```

## 前端 UI 结构(index.html,纯 JS 无框架)

- **视觉**:海康风设计系统(CSS 变量 `:root` 定义 --brand 海康红/深色顶栏渐变/侧栏/卡片阴影圆角);**全站线性 SVG 图标**(body 顶部 `<svg><defs><symbol id="i-*">` sprite,JS 用 `svgIco('i-xxx')` 渲染,`menuIcon`/`sysIcon` 按 code 映射图标),已无 emoji。改图标只在 sprite 加 symbol + 映射函数加分支。
- 顶部:深色渐变栏 + 海康红盾 LOGO + 横向 Tab(带图标);右上「当前登录」用户切换(头像 + 下拉,驱动体验)。
- **应用端(体验)**:卡片首页(应用菜单按父分组成卡片)→ 点视频监控类卡片进"区域树+资源浏览"(按权限置灰操作按钮;点无权区域→暂无操作权限)。
- **系统管理(后台)**:深色左侧菜单(登录用户有权的系统菜单),点击切换右侧:
  - 人员信息 → 组织机构(左树右详情)
  - 安保区域管理 → 区域(左树右详情)
  - 角色管理 → 角色配置(**操作者=当前登录用户**,2026-06-11 移除了原独立「操作者(创建人)」下拉以杜绝越权 + 鉴权测试面板)
  - 账号管理 → 用户/账号管理(建用户绑角色)
  - 其他菜单 → 演示占位
- 路由表在 JS 的 `SYS_ROUTE`。

## HTTP 接口一览

接口统一采用 GoFrame 分组 + 动作式路由,不使用 RESTful 路径参数,仅 GET/POST:
`/api/meta`
角色:`/api/role/list`(GET) `/api/role/detail?id=`(GET) `/api/role/save?actor=`(POST,委派合并) `/api/role/delete?actor=`(POST,body 含 id,委派校验+级联清理) `/api/role/grantable?actor=` `/api/role/area-children?actor=&parentId=&kind=`
鉴权:`/api/auth/check`(POST)
用户:`/api/user/list` `/api/user/detail?id=` `/api/user/save?userId=`(POST) `/api/user/delete?userId=`(POST)
区域管理:`/api/manage/area-save`(POST,?userId= 新增/重命名/移动,写时鉴权+path 维护) `/api/manage/area-reorder`(POST) `/api/manage/area-delete`(POST)
组织管理:`/api/manage/org-save`(POST,?userId= 新增/重命名/移动) `/api/manage/org-delete`(POST)
资源管理:`/api/manage/resource-save`(POST,?userId= 新增/重命名/改类型/移动) `/api/manage/resource-delete`(POST)
应用端:`/api/app/menu` `/api/app/area-tree`(全量) `/api/app/area-children`(按层懒加载+分页 ?parentId=&page=&size=) `/api/app/area-search`(?q=&scope=app|manage) `/api/app/resource-list`(资源分页 ?areaId=&page=&size=)(均 ?userId=)
后台:`/api/manage/menu` `/api/manage/area-tree`(全量) `/api/manage/area-children`(按层懒加载+分页 AREA 域) `/api/manage/org-tree` `/api/manage/area-detail` `/api/manage/org-detail`

---

## 怎么跑

```bash
go run ./tools/dbinit   # 幂等初始化数据库(可反复运行)
go run main.go          # 启动,访问 http://127.0.0.1:8000/
```
种子用户:张三(uid=1,安防管理员,全菜单+区域/组织/资源,但区域只到"事件图片测试"子树,看不到园区A)、李四(uid=2,园区A值班员,仅应用域)、王五(uid=3,双角色)、**admin(uid=4,超级管理员 is_superuser=1,绕过鉴权拥有全部)**。
**测试动线**:角色管理「操作者=当前登录用户」——配角色/建用户先把"当前登录"切到有系统管理权的用户,进后台操作;再切到目标用户去应用端体验。**注意**:角色列表只显示「当前登录用户自己创建的 ∪ 其角色被授予查看(角色范围)的」角色,仅自建可编辑/删除。种子角色 created_by=0(系统建),故**只有 admin(超管)能看到/管理全部角色**;张三/王五 等普通用户登录后角色列表为空(需自己新建,或被 admin 通过「角色范围」授予查看)。

---

## 已知环境坑(重要)

- **GoLand debug 报 `usage: compile`**:是 **360安全卫士**拦截 debug 全量重编(`all=-N -l`)瞬间拉起的大量 `compile.exe`,与代码/dlv 无关(flaky)。360 退不掉。**绕法**:`powershell -ExecutionPolicy Bypass -File tools\debug-build.ps1` 构建 `app_debug.exe`(带重试会收敛),再 GoLand **Attach to Process**。
- **重启服务前务必按 PID 杀旧进程**(端口 8000 易被占,否则 curl/浏览器打到旧实例的旧缓存):
  `PID=$(netstat -ano | grep ":8000 " | head -1 | awk '{print $NF}'); taskkill //F //PID $PID`
- Windows 控制台对中文 JSON 显示乱码是编码问题,数据本身是好的 UTF-8。
- 每次重大改动后建议 `go vet ./...`;index.html 改完用 `grep -c '<div' / '</div>'` 验 div 平衡。

---

## git 状态(2026-06-10)

- 已提交到 `0930fc6`(初始化→…→海康对照+委派模型B(`8489620`)→应用端资源级可见(`38c7022`)→**数据权限下推+懒加载分页+海康式搜索·前后台(`0930fc6`)**)。
- `8489620` 内容回顾(已落库):
  - 海康对照:`docs/海康对照.md`(CDP 登录真实 iSecure Center,逐项校验设计;核心全对,唯一差距=显式角色范围)。
  - **模型 B 显式角色范围**:`model/permission.go`(Role 加 `RoleScopes`)、`service/db.go`(Reload/SaveRole 加 `ROLE` 类型读写)、`service/delegation.go`(`Grantable.RoleIds`/`GrantableSet`/`MergeDelegated` 第5维/`ManageableRoles`)、`service/role.go`(`GuardManageRole` + 删除清 ROLE 引用)、`controller/perm/perm.go`(saveRole 编辑门禁)、`index.html`(「角色范围」子 Tab + 树 + `roleCanManage`/🔒 只读;顺修 `renderResTable` 二次渲染 NPE)、`docs/{测试报告 §十四,权限设计说明 5.3}`。
  - **零 DDL 迁移**:角色范围复用 `role_data_scope` 的 `scope_type='ROLE'`(列宽够用),现有库直接可用,无需改 schema/seed/dbinit。
- `38c7022` 内容回顾(已落库)· **应用端资源级可见(§十五)**:`model/permission.go`(Role 加 `ResourceOverrides`)、`service/db.go`(RESOVR 读写)、`service/auth.go`(`CheckResource` 精细判定=ResourceOverrides∪操作行,兼容旧数据)、`service/delegation.go`(`MergeDelegated` 第6维=精细标记)、`service/runtime.go`(`AreaResources` 过滤零操作资源)、`index.html`(saveRole/loadRole 持久化精细模式 + tip)、`docs/{测试报告 §十五,权限设计说明 3.3.1}`。**零 DDL**(复用 `role_data_scope` `scope_type='RESOVR'`)。
- `61ad052` 内容回顾(已落库):角色删除(`role.go` `DeleteRole` + `/api/role/delete` + created_by 修正)、资源增删改(`resource.go` + 区域详情卡片 ➕/✏️/📦/🗑)。均不改 schema/seed。
- `0930fc6` 内容回顾(已落库)· **数据权限下推 + 懒加载分页 + 海康式搜索(§十六)**:
  - 新增 `internal/service/paging.go`(scope→SQL WHERE 下推 + 按层懒加载树 + 列表分页 + `SearchAreas`)、`tools/genbulk/`(造数工具)、`docs/设计导读.md`(新人入门导读)。
  - 改 `internal/controller/perm/perm.go`(新接口 area-children/area-search/manage-area-children;area-resources 加分页)、`internal/service/runtime.go`(`ManageAreaDetail` 改 COUNT 子区域不平铺,加 ctx)、`resource/public/index.html`(懒加载树 `lazyTreeLevel`/`lazyTreeNode` + 「加载更多」+ 树搜索框 + 移动选择器弹框;顺带 `extractScopes` 区分 includeChild true/false)、`docs/{测试报告 §十六,设计导读,权限设计说明 §3.4}`。
  - **搜索对齐真实海康 · 前后台双树**:`SearchAreas`(scope=app/manage 共用核心,可见性 WHERE 下推)返回局部树祖先链(`AncestorRef`/`areaAncestors`)+ 硬上限 `searchLimit=500`;前端 `mountTreeSearch` 同时挂应用端(`appAreaTree`/scope=app)与后台管理(`manageAreaTree`/scope=manage)两棵树,共用 `searchTreeInto`/`renderSearchTree`/`hlMatch` 拼命中分支树、子串高亮、超 500 给「搜索结果过多,仅展示前 500 条」横幅。
  - **已端到端验证**:curl 验前后台双树各用户(李四 600→截 500、张三按 RES_AREA/AREA 各自域过滤、admin 超管 All)+ 截图验前端(应用端搜索树/高亮/截断 + **后台管理树搜索** admin「压测」截断横幅+高亮),见测试报告 §十六 **17/17**。**零 DDL**(只读 `area.path`/`idx_path`)。
- **重要约定:用户明确要求"我说提交再提交",不要自动 git commit。** 改完等用户确认。

---

## 待办 / 用户可能继续提的方向

- ~~新增/移动区域接口(自动维护 path,移动子树批量更新子孙 path)~~ **已完成**(`service/area.go`,后台"安保区域管理"右侧已有➕/✏️/📦/🗑 按钮,真实落库)。
- ~~**组织**的增删改真实落库~~ **已完成**(`service/org.go`,后台"人员信息→组织机构"右侧已有真实增删改按钮,§十一)。
- `gf gen dao` 生成标准 dao 替代手写 `g.Model`。
- ~~角色删除接口~~ **已完成**(`service/role.go`,前端角色列表 🗑 按钮,§十二)。
- ~~资源(摄像头)的增删改落库~~ **已完成**(`service/resource.go`,后台区域详情"本区域资源"卡片有 ➕/✏️/📦/🗑,§十三)。**数据树增删改三件套(区域/组织/资源)已全部完成**。
- ~~二次授权升级到模型 B(显式角色范围)~~ **已完成**(`delegation.go` `ManageableRoles`/`role.go` `GuardManageRole`,前端「角色范围」子 Tab,§十四)。**模型 C(变更级联)** 仍可后续做。
- ~~大数据量:区域树/资源列表全量载入内存的扩展性问题~~ **已完成**(`service/paging.go` 数据权限下推 SQL + 懒加载分页,§十六)。**后续可对称做**:组织树同样懒加载分页(现仍全量 `ManageOrgs`)、资源全局搜索框、`area-children` 的 `HasChildren` 批量预取优化。
- 应用端更多模块卡片的真实界面(目前非视频类是占位)。
- 用户偏好:决策(如委派模型)倾向**先调研真实海康行为再定**;前端**仿海康红黑风格**。验证默认**精简档**(小改一次快验即可);**「请验证X」只针对当下那一处,不要推广成对所有场景/今后都充分验证**。
