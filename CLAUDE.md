# 项目:基于角色的权限系统(仿海康安防平台)

GoFrame(gf v2)实现的 RBAC + 数据权限演示系统。核心是**功能权限 + 数据权限**两个维度。

> **改动权限相关代码前,先读 `docs/权限设计说明.md`(通俗易懂的完整设计文档)。**
> 数据库表见 `manifest/sql/schema.sql`(建表)+ `seed.sql`(种子)。

## 关键设计决策(已和用户确认,勿擅自改变)

1. **两个权限维度**:功能权限(角色→菜单,菜单分 SYS 系统管理域 / APP 应用域)+ 数据权限(角色→区域树/组织树/业务资源)。两者同时满足才放行。
2. **数据权限挂在树上,用物化路径 `path` 前缀判断子树**:存 `{节点, include_child}`,不展开子节点。授权一棵子树后,**新增子节点自动继承**(`path LIKE '授权节点path%'`)。
3. **系统只有一个根区域**:给角色授权根区域(含子树)= 自动拥有现在和将来全部区域。新增区域时**必须正确写 `path` = 父.path + 新ID + "/"**,否则前缀匹配失效。
4. **业务资源权限两层**:区域范围(粗,继承新资源)+ 资源级操作精细配置(细,覆盖模式;无配置则继承区域=全部操作)。
5. **二次授权 = 受控委派,采用模型 A(写时校验 + 合并,不级联)**,已实测对齐海康行为:
   - 已建角色有效权限不级联(创建人被收权,旧角色不变)。
   - 编辑界面按创建人当前权限**实时过滤**(超范围节点在前端**隐藏**)。
   - 保存时**合并**:`最终 = (提交 ∩ 创建人可授范围) ∪ (原有 \ 创建人可授范围)`,即范围外原有权限原样保留(看不到也删不掉)。
   - 实现见 `service/delegation.go` 的 `GrantableSet` 和 `MergeDelegated`。
6. **存储**:MySQL 是持久层(库 `security_permission`,root/123456);启动 `service.S.Reload(ctx)` 全量载入内存缓存,鉴权读缓存,写角色落库后刷新缓存。`role_data_scope` 一张表用 `scope_type`(AREA/ORG/RES_AREA)统一承载三种树范围。

## 代码结构

- `internal/service/auth.go` — 鉴权引擎(功能/区域/组织/资源三关)
- `internal/service/delegation.go` — 二次授权(可授范围 + 合并)
- `internal/service/db.go` — MySQL 加载(Reload)/ 写回(SaveRole)
- `internal/service/store.go` — 内存缓存 + 读方法
- `internal/controller/perm/perm.go` — HTTP 接口
- `resource/public/index.html` — 前端测试页(仿海康角色编辑 UI + 鉴权测试)

## 运行

```bash
go run ./tools/dbinit   # 幂等初始化数据库(空库才灌种子,保留已有数据)
go run main.go          # 启动,访问 http://127.0.0.1:8000/
```

## 已知环境坑

- **GoLand debug 报 `usage: compile`**:是 **360安全卫士**拦截 debug 全量重编(`all=-N -l`)瞬间拉起的大量 `compile.exe`,与代码/dlv 无关(flaky)。360 退不掉时用 `tools/debug-build.ps1` 构建 + GoLand **Attach to Process** 绕开。详见 `docs/权限设计说明.md`。
- Windows 下重启服务前务必先按 PID 杀掉旧进程(端口 8000 易被占,否则 curl 打到旧实例的旧缓存)。

## 待办 / 可扩展(用户尚未决定)

- 新增/移动区域接口(自动维护 path)
- `gf gen dao` 生成标准 dao 替代手写 `g.Model`
- 角色删除接口、用户/角色绑定管理界面
- 二次授权升级到模型 B(运行时取交集)/ C(级联重算)——`role.created_by` 字段已预留
