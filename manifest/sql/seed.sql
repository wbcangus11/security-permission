-- =============================================================================
-- 种子(演示)数据。仅在空库首次初始化时由 tools/dbinit 执行。
-- 用 INSERT IGNORE,即使手动重复执行也不会报错、不覆盖已有行。
-- =============================================================================
USE `security_permission`;
SET NAMES utf8mb4;

-- 区域树:根区域 >(事件图片测试 / 园区A >(1号楼、2号楼))
INSERT IGNORE INTO `area` (`id`,`parent_id`,`name`,`path`) VALUES
 (1,0,'根区域','/1/'),
 (2,1,'事件图片测试','/1/2/'),
 (3,1,'园区A','/1/3/'),
 (4,3,'1号楼','/1/3/4/'),
 (5,3,'2号楼','/1/3/5/');

-- 组织树
INSERT IGNORE INTO `org` (`id`,`parent_id`,`name`,`path`) VALUES
 (1,0,'根组织','/1/'),
 (2,1,'技术部','/1/2/'),
 (3,2,'安防组','/1/2/3/'),
 (4,1,'行政部','/1/4/');

-- 菜单(系统管理域)
INSERT IGNORE INTO `menu` (`id`,`parent_id`,`code`,`name`,`domain`) VALUES
 (1,0,'sys.person','人员管理','SYS'),
 (2,1,'sys.person.info','人员信息','SYS'),
 (3,1,'sys.person.role','角色管理','SYS'),
 (4,1,'sys.person.account','账号管理','SYS'),
 (5,1,'sys.person.face','人脸管理','SYS'),
 (6,0,'sys.vehicle','车辆信息管理','SYS'),
 (7,0,'sys.area','安保区域管理','SYS'),
 (8,0,'sys.device','设备管理','SYS'),
 (9,0,'sys.resource','资源管理','SYS'),
 (10,0,'sys.videocfg','视频监控配置','SYS'),
 (11,0,'sys.servicecfg','综合服务配置','SYS'),
 (12,0,'sys.network','网络配置管理','SYS'),
 (13,0,'sys.advanced','高级系统管理','SYS');

-- 菜单(应用域)
INSERT IGNORE INTO `menu` (`id`,`parent_id`,`code`,`name`,`domain`) VALUES
 (101,0,'app.integrated','综合管控','APP'),
 (102,101,'app.integrated.eventsearch','事件检索','APP'),
 (103,101,'app.integrated.mapmonitor','图上监控','APP'),
 (104,101,'app.integrated.smartsearch','智能检索','APP'),
 (105,101,'app.integrated.broadcast','广播','APP'),
 (106,0,'app.video','视频监控','APP'),
 (107,106,'app.video.live','实时预览','APP'),
 (108,106,'app.video.playback','远程回放','APP'),
 (109,106,'app.video.picture','图片查询','APP'),
 (110,0,'app.network','网络管控','APP'),
 (111,110,'app.network.monitor','视频网管监控','APP');

-- 资源
INSERT IGNORE INTO `resource` (`id`,`area_id`,`type`,`name`) VALUES
 (101,2,'camera','图片测试-枪机01'),
 (102,4,'camera','1号楼-大厅球机'),
 (103,4,'camera','1号楼-电梯口'),
 (104,5,'camera','2号楼-停车场');

-- 操作项
INSERT IGNORE INTO `action` (`code`,`name`,`sort`) VALUES
 ('live','实时预览',1),
 ('playback','远程回放',2),
 ('picture','图片查询',3);

-- 角色
INSERT IGNORE INTO `role` (`id`,`name`,`description`,`created_by`) VALUES
 (1,'安防管理员','全菜单 + 事件图片测试区域',0),
 (2,'园区A值班员','应用域视频 + 园区A,1号楼大厅球机仅实时预览',0);

-- 角色1:全部菜单
INSERT IGNORE INTO `role_menu` (`role_id`,`menu_id`)
 SELECT 1, id FROM `menu`;
-- 角色2:部分应用菜单
INSERT IGNORE INTO `role_menu` (`role_id`,`menu_id`) VALUES
 (2,101),(2,102),(2,103),(2,106),(2,107),(2,108),(2,109);

-- 数据范围
INSERT IGNORE INTO `role_data_scope` (`role_id`,`scope_type`,`node_id`,`include_child`) VALUES
 (1,'AREA',2,1),
 (1,'ORG',1,1),
 (1,'RES_AREA',2,1),
 (2,'RES_AREA',3,1);

-- 资源精细授权:角色2 对 102 摄像头仅授予实时预览
INSERT IGNORE INTO `role_resource_action` (`role_id`,`resource_id`,`action_code`) VALUES
 (2,102,'live');

-- 用户与绑定
INSERT IGNORE INTO `user` (`id`,`name`,`org_id`) VALUES
 (1,'张三(安防管理员)',3),
 (2,'李四(园区A值班员)',2),
 (3,'王五(双角色)',2);

INSERT IGNORE INTO `user_role` (`user_id`,`role_id`) VALUES
 (1,1),(2,2),(3,1),(3,2);
