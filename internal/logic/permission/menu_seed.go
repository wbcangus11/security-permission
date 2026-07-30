package permission

import (
	"context"

	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/consts"
	"security-permission/internal/model/do"
)

// builtInMenus 是随程序版本发布的菜单与功能权限点基线。
// Code 是菜单、父子关系、角色关系和业务鉴权共同使用的唯一稳定标识。
var builtInMenus = []do.Menu{
	{Code: consts.MenuCodeSysPerson, Name: "人员管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysPersonInfo, ParentCode: consts.MenuCodeSysPerson, Name: "人员信息", Domain: "SYS"},
	{Code: consts.MenuCodeSysPersonRole, ParentCode: consts.MenuCodeSysPerson, Name: "角色管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysPersonAccount, ParentCode: consts.MenuCodeSysPerson, Name: "账号管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysPersonFace, ParentCode: consts.MenuCodeSysPerson, Name: "人脸管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysBusiness, Name: "业务数据管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysBusinessPassenger, ParentCode: consts.MenuCodeSysBusiness, Name: "客流统计", Domain: "SYS"},
	{Code: consts.MenuCodeSysVehicle, Name: "车辆信息管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysArea, Name: "安保区域管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysDevice, Name: "设备管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysDeviceEncode, ParentCode: consts.MenuCodeSysDevice, Name: "编码设备", Domain: "SYS"},
	{Code: consts.MenuCodeSysDeviceBroadcast, ParentCode: consts.MenuCodeSysDevice, Name: "广播设备", Domain: "SYS"},
	{Code: consts.MenuCodeSysDeviceAlarm, ParentCode: consts.MenuCodeSysDevice, Name: "报警设备", Domain: "SYS"},
	{Code: consts.MenuCodeSysResource, Name: "资源管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysResourcePoint, ParentCode: consts.MenuCodeSysResource, Name: "监控点", Domain: "SYS"},
	{Code: consts.MenuCodeSysResourceTerminal, ParentCode: consts.MenuCodeSysResource, Name: "终端", Domain: "SYS"},
	{Code: consts.MenuCodeSysResourceIO, ParentCode: consts.MenuCodeSysResource, Name: "报警输入输出", Domain: "SYS"},
	{Code: consts.MenuCodeSysResourceZone, ParentCode: consts.MenuCodeSysResource, Name: "防区", Domain: "SYS"},
	{Code: consts.MenuCodeSysVideoConfig, Name: "视频监控配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysVideoConfigRecord, ParentCode: consts.MenuCodeSysVideoConfig, Name: "录像计划", Domain: "SYS"},
	{Code: consts.MenuCodeSysVideoConfigCapture, ParentCode: consts.MenuCodeSysVideoConfig, Name: "抓图计划", Domain: "SYS"},
	{Code: consts.MenuCodeSysVideoConfigDefense, ParentCode: consts.MenuCodeSysVideoConfig, Name: "事件布撤防", Domain: "SYS"},
	{Code: consts.MenuCodeSysVideoConfigParam, ParentCode: consts.MenuCodeSysVideoConfig, Name: "参数配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysServiceConfig, Name: "综合服务配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysServiceConfigEvent, ParentCode: consts.MenuCodeSysServiceConfig, Name: "事件联动", Domain: "SYS"},
	{Code: consts.MenuCodeSysServiceConfigMap, ParentCode: consts.MenuCodeSysServiceConfig, Name: "地图配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysServiceConfigRecognition, ParentCode: consts.MenuCodeSysServiceConfig, Name: "识别计划配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysNetwork, Name: "网络配置管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysNetworkPatrol, ParentCode: consts.MenuCodeSysNetwork, Name: "巡检计划配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvanced, Name: "高级系统管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedParam, ParentCode: consts.MenuCodeSysAdvanced, Name: "高级参数配置", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedPlatformUpgrade, ParentCode: consts.MenuCodeSysAdvanced, Name: "平台升级管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedAppUpgrade, ParentCode: consts.MenuCodeSysAdvanced, Name: "APP升级管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedStreamUpgrade, ParentCode: consts.MenuCodeSysAdvanced, Name: "流媒体升级管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedSMS, ParentCode: consts.MenuCodeSysAdvanced, Name: "短信管理", Domain: "SYS"},
	{Code: consts.MenuCodeSysAdvancedEmail, ParentCode: consts.MenuCodeSysAdvanced, Name: "邮箱管理", Domain: "SYS"},
	{Code: consts.MenuCodeAppIntegrated, Name: "综合管控", Domain: "APP"},
	{Code: consts.MenuCodeAppIntegratedEventSearch, ParentCode: consts.MenuCodeAppIntegrated, Name: "事件检索", Domain: "APP"},
	{Code: consts.MenuCodeAppIntegratedMapMonitor, ParentCode: consts.MenuCodeAppIntegrated, Name: "图上监控", Domain: "APP"},
	{Code: consts.MenuCodeAppIntegratedSmartSearch, ParentCode: consts.MenuCodeAppIntegrated, Name: "智能检索", Domain: "APP"},
	{Code: consts.MenuCodeAppIntegratedBroadcast, ParentCode: consts.MenuCodeAppIntegrated, Name: "广播", Domain: "APP"},
	{Code: consts.MenuCodeAppVideo, Name: "视频监控", Domain: "APP"},
	{Code: consts.MenuCodeAppVideoLive, ParentCode: consts.MenuCodeAppVideo, Name: "实时预览", Domain: "APP"},
	{Code: consts.MenuCodeAppVideoPlayback, ParentCode: consts.MenuCodeAppVideo, Name: "远程回放", Domain: "APP"},
	{Code: consts.MenuCodeAppVideoPicture, ParentCode: consts.MenuCodeAppVideo, Name: "图片查询", Domain: "APP"},
	{Code: consts.MenuCodeAppNetwork, Name: "网络管控", Domain: "APP"},
	{Code: consts.MenuCodeAppNetworkMonitor, ParentCode: consts.MenuCodeAppNetwork, Name: "视频网管监控", Domain: "APP"},
}

// saveBuiltInMenus 在构建内存菜单目录前把代码中的基线写入数据库。
// Save 生成批量 UPSERT：重复启动不会产生重复数据，已有菜单会按唯一 code 同步其余字段。
func saveBuiltInMenus(ctx context.Context) error {
	_, err := g.DB().Model("menu").Ctx(ctx).
		Data(builtInMenus).
		OnDuplicate("parent_code,name,domain").
		Save()
	return err
}
