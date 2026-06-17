package service

// 业务资源(摄像头)增删改:写时鉴权 + 删除清理精细授权引用。
//
// 资源与区域/组织不同:它不是树、无 path,而是"挂在某个安保区域下的叶子对象"(model.Resource.AreaId)。
// 鉴权规则(管理域,资源是安装在安保区域里的设备):
//   功能关:操作人须有「资源管理」菜单(sys.resource);
//   数据关:对资源所在区域有「安保区域管理」权限(CheckArea);移动还要对新区域有权。
//
// 与 area.go/org.go 的对称点:
//   新增:挂到父区域下;授权了该区域 RES_AREA 子树的角色自动继承新资源(继承模式,无需配精细);
//   移动:改 area_id(精细授权 role_resource_action 按资源 id 走,随资源迁移,不清);
//   删除:同步清理 role_resource_action 对该资源的精细授权行,避免悬挂引用。

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
)

// menuResourceManage 资源管理菜单 code(资源写操作的功能关)。
const menuResourceManage = "sys.resource"

// ResourceSaveInput 新增/重命名/改类型/移动资源的入参。
// Id<=0 为新增(AreaId=所在区域);更新时 AreaId 非 0 且与原值不同即移动到新区域。
type ResourceSaveInput struct {
	Id     int    `json:"id"`
	AreaId int    `json:"areaId"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

// SaveResource 新增或更新(重命名/改类型/移动)资源,写时鉴权,成功后刷新缓存。actorId=操作人。
func (s *Store) SaveResource(ctx context.Context, actorId int, in *ResourceSaveInput) (*model.Resource, error) {
	actor, err := s.checkResourceWriter(actorId)
	if err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, gerror.New("资源名称不能为空")
	}
	if in.Id <= 0 {
		return s.createResource(ctx, actor, in)
	}
	return s.updateResource(ctx, actor, in)
}

// DeleteResource 删除资源,同步清理对该资源的精细授权(role_resource_action)。
func (s *Store) DeleteResource(ctx context.Context, actorId, resId int) error {
	actor, err := s.checkResourceWriter(actorId)
	if err != nil {
		return err
	}
	target := s.ResourceById(resId)
	if target == nil {
		return gerror.New("资源不存在")
	}
	if d := s.CheckArea(actor, target.AreaId); !d.Allow {
		return gerror.New("无权删除「" + target.Name + "」:" + d.Reason)
	}
	err = dao.Resource.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.Resource.Table()).Ctx(ctx).Where(dao.Resource.Columns().Id, resId).Delete(); err != nil {
			return err
		}
		// 清理引用该资源的精细授权(资源级操作覆盖)
		_, err := tx.Model(dao.RoleResourceAction.Table()).Ctx(ctx).
			Where(dao.RoleResourceAction.Columns().ResourceId, resId).
			Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.Reload(ctx)
}

// checkResourceWriter 写操作公共前置:操作人存在 + 功能关(sys.resource 菜单)。
func (s *Store) checkResourceWriter(actorId int) (*model.User, error) {
	actor := s.User(actorId)
	if actor == nil {
		return nil, gerror.New("操作人不存在")
	}
	if d := s.CheckMenu(actor, menuResourceManage); !d.Allow {
		return nil, gerror.New("功能权限不足:" + d.Reason)
	}
	return actor, nil
}

// createResource 在某区域下新增资源:数据关看所在区域;新增后授权了该区域 RES_AREA 子树的角色自动继承。
func (s *Store) createResource(ctx context.Context, actor *model.User, in *ResourceSaveInput) (*model.Resource, error) {
	area := s.AreaById(in.AreaId)
	if area == nil {
		return nil, gerror.New("所在区域不存在")
	}
	if d := s.CheckArea(actor, area.Id); !d.Allow {
		return nil, gerror.New("无权在「" + area.Name + "」下新增资源:" + d.Reason)
	}
	if in.Type == "" {
		in.Type = "camera"
	}
	if s.resourceNameTaken(area.Id, in.Name, 0) {
		return nil, gerror.New("同区域已存在同名资源:" + in.Name)
	}
	var newId int64
	err := dao.Resource.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		res, err := tx.Model(dao.Resource.Table()).Ctx(ctx).
			Data(do.Resource{AreaId: area.Id, Type: in.Type, Name: in.Name}).Insert()
		if err != nil {
			return err
		}
		newId, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.Reload(ctx); err != nil {
		return nil, err
	}
	return s.ResourceById(int(newId)), nil
}

// updateResource 重命名/改类型 + 可选移动:移动需对原区域和新区域都有权。
func (s *Store) updateResource(ctx context.Context, actor *model.User, in *ResourceSaveInput) (*model.Resource, error) {
	old := s.ResourceById(in.Id)
	if old == nil {
		return nil, gerror.New("资源不存在")
	}
	if d := s.CheckArea(actor, old.AreaId); !d.Allow {
		return nil, gerror.New("无权管理「" + old.Name + "」所在区域:" + d.Reason)
	}
	typeVal := in.Type
	if typeVal == "" {
		typeVal = old.Type // 未传类型则保持原值
	}

	moving := in.AreaId != 0 && in.AreaId != old.AreaId
	targetArea := old.AreaId
	if moving {
		newArea := s.AreaById(in.AreaId)
		if newArea == nil {
			return nil, gerror.New("目标区域不存在")
		}
		if d := s.CheckArea(actor, newArea.Id); !d.Allow {
			return nil, gerror.New("无权移动到「" + newArea.Name + "」:" + d.Reason)
		}
		targetArea = newArea.Id
	}
	if s.resourceNameTaken(targetArea, in.Name, old.Id) {
		return nil, gerror.New("同区域已存在同名资源:" + in.Name)
	}

	data := do.Resource{Name: in.Name, Type: typeVal}
	if moving {
		data.AreaId = targetArea
	}
	if _, err := dao.Resource.Ctx(ctx).Data(data).Where(dao.Resource.Columns().Id, old.Id).Update(); err != nil {
		return nil, err
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s.ResourceById(old.Id), nil
}

// resourceNameTaken 同一区域下是否已存在同名资源(excludeId 排除自身,用于更新)。
func (s *Store) resourceNameTaken(areaId int, name string, excludeId int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.resources {
		if r.AreaId == areaId && r.Name == name && r.Id != excludeId {
			return true
		}
	}
	return false
}
