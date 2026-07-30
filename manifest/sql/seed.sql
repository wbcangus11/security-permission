-- =============================================================================
-- 当前基础种子数据。数据库由 dbinit 全量重建,这里直接插入基线数据。
-- =============================================================================
USE `security_permission`;
SET NAMES utf8mb4;

-- 区域树:根区域 >(事件图片测试 / 园区A >(1号楼、2号楼))
INSERT INTO `area` (`id`,`parent_id`,`name`,`path`) VALUES
 (1,0,'根区域','/1/'),
 (2,1,'事件图片测试','/1/2/'),
 (3,1,'园区A','/1/3/'),
 (4,3,'1号楼','/1/3/4/'),
 (5,3,'2号楼','/1/3/5/');

-- 组织树
INSERT INTO `org` (`id`,`parent_id`,`name`,`path`) VALUES
 (1,0,'根组织','/1/'),
 (2,1,'技术部','/1/2/'),
 (3,2,'安防组','/1/2/3/'),
 (4,1,'行政部','/1/4/');

-- 资源
INSERT INTO `resource` (`id`,`area_id`,`type`,`name`) VALUES
 (101,2,'camera','图片测试-枪机01'),
 (102,4,'camera','1号楼-大厅球机'),
 (103,4,'camera','1号楼-电梯口'),
 (104,5,'camera','2号楼-停车场');

-- 角色
INSERT INTO `role` (`id`,`name`,`description`,`created_by`) VALUES
 (1,'安防管理员','全菜单 + 事件图片测试区域','0'),
 (2,'园区A值班员','应用域视频 + 园区A资源范围','0');

-- 角色1：全部菜单。
INSERT INTO `role_menu` (`role_id`,`menu_code`)
 SELECT 1, code FROM `menu`;
-- 角色2:部分应用菜单
INSERT INTO `role_menu` (`role_id`,`menu_code`)
 SELECT 2, code FROM `menu`
 WHERE `code` IN (
  'app.integrated','app.integrated.eventsearch','app.integrated.mapmonitor',
  'app.video','app.video.live','app.video.playback','app.video.picture'
 );

-- 数据范围
INSERT INTO `role_data_scope` (`role_id`,`scope_type`,`node_id`,`include_child`) VALUES
 (1,'AREA',2,1),
 (1,'ORG',1,1),
 (1,'RES_AREA',2,1),
 (2,'RES_AREA',3,1);

-- 用户与绑定
INSERT INTO `user` (`id`,`name`,`org_id`,`is_superuser`) VALUES
 ('1','张三(安防管理员)',3,0),
 ('2','李四(园区A值班员)',2,0),
 ('3','王五(双角色)',2,0),
 ('4','admin(超级管理员)',1,1);

INSERT INTO `user_role` (`user_id`,`role_id`) VALUES
 ('1',1),('2',2),('3',1),('3',2);
