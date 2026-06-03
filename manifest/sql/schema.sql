-- =============================================================================
-- 表结构(幂等:CREATE ... IF NOT EXISTS,可反复执行,不会丢数据)
-- 基于角色的「功能权限 + 数据权限」(仿海康安防平台)
--
-- 设计要点(与 internal/model/permission.go 一一对应):
--   1. 功能权限:role_menu(角色 -> 菜单),菜单用 domain 区分系统管理域/应用域。
--   2. 数据权限:role_data_scope 统一承载「安保区域 / 组织 / 业务资源范围」三种树范围,
--      用 scope_type 区分;存「节点 + 是否含子树」,不展开子节点。
--   3. 树(area/org)用物化路径 path 实现子树判断:WHERE path LIKE '授权节点path%'。
--   4. 资源级操作精细授权:role_resource_action(角色 x 资源 x 操作)。
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `security_permission` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `security_permission`;

SET NAMES utf8mb4;

-- 区域树(物理空间:园区/楼栋/楼层),资源挂在其下
CREATE TABLE IF NOT EXISTS `area` (
  `id`        BIGINT       NOT NULL AUTO_INCREMENT COMMENT '区域ID',
  `parent_id` BIGINT       NOT NULL DEFAULT 0      COMMENT '父区域ID,0为根',
  `name`      VARCHAR(128) NOT NULL DEFAULT ''     COMMENT '区域名称',
  `path`      VARCHAR(512) NOT NULL DEFAULT ''     COMMENT '物化路径,含自身,形如 /1/3/4/',
  `sort`      INT          NOT NULL DEFAULT 0      COMMENT '同级排序',
  PRIMARY KEY (`id`),
  KEY `idx_parent` (`parent_id`),
  KEY `idx_path`   (`path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='安保区域(树形)';

-- 组织树(人员/车辆归属:集团/公司/部门)
CREATE TABLE IF NOT EXISTS `org` (
  `id`        BIGINT       NOT NULL AUTO_INCREMENT COMMENT '组织ID',
  `parent_id` BIGINT       NOT NULL DEFAULT 0      COMMENT '父组织ID,0为根',
  `name`      VARCHAR(128) NOT NULL DEFAULT ''     COMMENT '组织名称',
  `path`      VARCHAR(512) NOT NULL DEFAULT ''     COMMENT '物化路径,含自身',
  `sort`      INT          NOT NULL DEFAULT 0      COMMENT '同级排序',
  PRIMARY KEY (`id`),
  KEY `idx_parent` (`parent_id`),
  KEY `idx_path`   (`path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='组织(树形)';

-- 菜单/功能项(树形),domain 区分系统管理域(SYS)与应用域(APP)
CREATE TABLE IF NOT EXISTS `menu` (
  `id`        BIGINT       NOT NULL AUTO_INCREMENT COMMENT '菜单ID',
  `parent_id` BIGINT       NOT NULL DEFAULT 0      COMMENT '父菜单ID,0为根',
  `code`      VARCHAR(128) NOT NULL                COMMENT '菜单编码,唯一,鉴权用',
  `name`      VARCHAR(128) NOT NULL DEFAULT ''     COMMENT '菜单名称',
  `domain`    VARCHAR(16)  NOT NULL DEFAULT 'SYS'  COMMENT '权限域:SYS=系统管理 / APP=应用',
  `sort`      INT          NOT NULL DEFAULT 0      COMMENT '同级排序',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_code` (`code`),
  KEY `idx_parent_domain` (`domain`, `parent_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='菜单/功能项(树形)';

-- 业务资源(如摄像头),挂在区域下
CREATE TABLE IF NOT EXISTS `resource` (
  `id`      BIGINT       NOT NULL AUTO_INCREMENT COMMENT '资源ID',
  `area_id` BIGINT       NOT NULL                COMMENT '所属区域ID',
  `type`    VARCHAR(32)  NOT NULL DEFAULT ''     COMMENT '资源类型,如 camera',
  `name`    VARCHAR(128) NOT NULL DEFAULT ''     COMMENT '资源名称',
  PRIMARY KEY (`id`),
  KEY `idx_area` (`area_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='业务资源';

-- 操作项(资源上的动作:实时预览/远程回放/图片查询)
CREATE TABLE IF NOT EXISTS `action` (
  `code` VARCHAR(32)  NOT NULL            COMMENT '操作编码,如 live/playback/picture',
  `name` VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '操作名称',
  `sort` INT          NOT NULL DEFAULT 0  COMMENT '排序',
  PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='资源操作项';

-- 角色
CREATE TABLE IF NOT EXISTS `role` (
  `id`          BIGINT       NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `name`        VARCHAR(128) NOT NULL                COMMENT '角色名称',
  `description` VARCHAR(255) NOT NULL DEFAULT ''      COMMENT '描述',
  `created_by`  BIGINT       NOT NULL DEFAULT 0       COMMENT '创建人(委派来源用户),0为系统创建/不受限',
  `created_at`  DATETIME              DEFAULT NULL    COMMENT '创建时间',
  `updated_at`  DATETIME              DEFAULT NULL    COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_created_by` (`created_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色';

-- 角色-菜单(功能权限)
CREATE TABLE IF NOT EXISTS `role_menu` (
  `role_id` BIGINT NOT NULL COMMENT '角色ID',
  `menu_id` BIGINT NOT NULL COMMENT '菜单ID',
  PRIMARY KEY (`role_id`, `menu_id`),
  KEY `idx_menu` (`menu_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-菜单(功能权限)';

-- 角色-数据范围(统一承载:安保区域 / 组织 / 业务资源范围)
--   scope_type: AREA / ORG / RES_AREA;include_child=1 表示授权整棵子树
CREATE TABLE IF NOT EXISTS `role_data_scope` (
  `role_id`       BIGINT      NOT NULL COMMENT '角色ID',
  `scope_type`    VARCHAR(16) NOT NULL COMMENT 'AREA / ORG / RES_AREA',
  `node_id`       BIGINT      NOT NULL COMMENT '授权的树节点ID(area.id 或 org.id)',
  `include_child` TINYINT(1)  NOT NULL DEFAULT 1 COMMENT '是否含子树',
  PRIMARY KEY (`role_id`, `scope_type`, `node_id`),
  KEY `idx_role_type` (`role_id`, `scope_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-数据范围(树范围授权)';

-- 角色-资源操作(应用域精细授权,仅对已存在资源生效)
--   某资源在本表有记录 => 覆盖模式,仅授予列出的操作;无记录 => 继承模式(范围内默认全部操作)
CREATE TABLE IF NOT EXISTS `role_resource_action` (
  `role_id`     BIGINT      NOT NULL COMMENT '角色ID',
  `resource_id` BIGINT      NOT NULL COMMENT '资源ID',
  `action_code` VARCHAR(32) NOT NULL COMMENT '操作编码',
  PRIMARY KEY (`role_id`, `resource_id`, `action_code`),
  KEY `idx_role_res` (`role_id`, `resource_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-资源操作(精细授权)';

-- 用户(账号)
CREATE TABLE IF NOT EXISTS `user` (
  `id`     BIGINT       NOT NULL AUTO_INCREMENT COMMENT '用户ID',
  `name`   VARCHAR(128) NOT NULL DEFAULT ''     COMMENT '用户名',
  `org_id` BIGINT       NOT NULL DEFAULT 0      COMMENT '所属组织ID',
  PRIMARY KEY (`id`),
  KEY `idx_org` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户(账号)';

-- 用户-角色
CREATE TABLE IF NOT EXISTS `user_role` (
  `user_id` BIGINT NOT NULL COMMENT '用户ID',
  `role_id` BIGINT NOT NULL COMMENT '角色ID',
  PRIMARY KEY (`user_id`, `role_id`),
  KEY `idx_role` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户-角色';
