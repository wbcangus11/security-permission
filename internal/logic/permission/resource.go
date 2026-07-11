package permission

// 业务资源(摄像头)增删改:写时鉴权 + 运行时缓存刷新。
//
// 资源与区域/组织不同:它不是树、无 path,而是"挂在某个安保区域下的叶子对象"(model.Resource.AreaId)。
// 鉴权规则(管理域,资源是安装在安保区域里的设备):
//   功能关:操作人须有「资源管理」菜单(sys.resource);
//   数据关:对资源所在区域有「安保区域管理」权限(CheckArea);移动还要对新区域有权。
//
// 与 area.go/org.go 的对称点:
//   新增:挂到父区域下;授权了该区域 RES_AREA 子树的角色自动继承新资源;
//   移动:只改 area_id,资源是否可见随新的区域范围实时计算;
//   删除:删除资源主表记录后刷新资源缓存即可。

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
)

// Save 新增或更新(重命名/改类型/移动)资源,写时鉴权,成功后刷新缓存。actorId=操作人。
func (s *ResourceService) Save(ctx context.Context, actorId string, in *model.ResourceSaveInput) (*model.Resource, error) {
	// 资源写操作先统一过功能关：必须有“资源管理”菜单权限。
	actor, err := s.checkResourceWriter(actorId)
	if err != nil {
		return nil, err
	}
	// 名称先清洗再做同区域重名校验，避免靠空格制造重复资源。
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, gerror.New("资源名称不能为空")
	}
	// Id<=0 是新增；否则是重命名/改类型/移动。新增看目标区域，更新要先看旧区域。
	if in.Id <= 0 {
		return s.createResource(ctx, actor, in)
	}
	return s.updateResource(ctx, actor, in)
}

// Delete 删除资源。当前资源权限只来自 RES_AREA 区域范围,所以删除资源不需要清理额外授权表。
func (s *ResourceService) Delete(ctx context.Context, actorId string, resId int) error {
	// 删除资源先过功能关；真正的数据边界看资源当前所在的安防区域。
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
	if _, err = dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().Id, resId).Delete(); err != nil {
		return err
	}
	// 资源删除会影响应用端列表和资源鉴权结果,刷新资源缓存并失效权限快照。
	return s.reloadResources(ctx)
}

// checkResourceWriter 写操作公共前置:操作人存在 + 功能关(sys.resource 菜单)。
func (s *ResourceService) checkResourceWriter(actorId string) (*model.User, error) {
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
func (s *ResourceService) createResource(ctx context.Context, actor *model.User, in *model.ResourceSaveInput) (*model.Resource, error) {
	area := s.AreaById(in.AreaId)
	if area == nil {
		return nil, gerror.New("所在区域不存在")
	}
	// 新增资源的数据关看“所在区域”；没有该区域管理权的人不能往里面挂设备。
	if d := s.CheckArea(actor, area.Id); !d.Allow {
		return nil, gerror.New("无权在「" + area.Name + "」下新增资源:" + d.Reason)
	}
	// 资源类型缺省按摄像头处理，保持当前系统主业务对象一致。
	if in.Type == "" {
		in.Type = "camera"
	}
	// 同区域资源名称保持唯一，避免前端树/列表展示无法区分。
	if s.resourceNameTaken(area.Id, in.Name, 0) {
		return nil, gerror.New("同区域已存在同名资源:" + in.Name)
	}
	var newId int64
	err := dao.Resource.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 资源不是树节点，不需要 path；挂到 area_id 后由 RES_AREA 范围自然覆盖。
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
	if err = s.reloadResources(ctx); err != nil {
		return nil, err
	}
	// 返回重载后的对象，保证后续展示读取的是最新缓存。
	return s.ResourceById(int(newId)), nil
}

// updateResource 重命名/改类型 + 可选移动:移动需对原区域和新区域都有权。
func (s *ResourceService) updateResource(ctx context.Context, actor *model.User, in *model.ResourceSaveInput) (*model.Resource, error) {
	old := s.ResourceById(in.Id)
	if old == nil {
		return nil, gerror.New("资源不存在")
	}
	// 更新资源先校验旧区域：没有当前所在区域权限的人不能改这个资源。
	if d := s.CheckArea(actor, old.AreaId); !d.Allow {
		return nil, gerror.New("无权管理「" + old.Name + "」所在区域:" + d.Reason)
	}
	typeVal := in.Type
	if typeVal == "" {
		typeVal = old.Type // 未传类型则保持原值
	}

	// AreaId 不传或等于原区域时只改基本信息；传了新区域才算移动资源。
	moving := in.AreaId != 0 && in.AreaId != old.AreaId
	targetArea := old.AreaId
	if moving {
		newArea := s.AreaById(in.AreaId)
		if newArea == nil {
			return nil, gerror.New("目标区域不存在")
		}
		// 移动资源要同时有新区域权限，否则可以把设备转移到无权管理的区域。
		if d := s.CheckArea(actor, newArea.Id); !d.Allow {
			return nil, gerror.New("无权移动到「" + newArea.Name + "」:" + d.Reason)
		}
		targetArea = newArea.Id
	}
	// 重名校验使用最终区域：移动时检查新区域，不移动时检查旧区域。
	if s.resourceNameTaken(targetArea, in.Name, old.Id) {
		return nil, gerror.New("同区域已存在同名资源:" + in.Name)
	}

	data := do.Resource{Name: in.Name, Type: typeVal}
	if moving {
		// 资源权限来自所在区域,移动后无需迁移授权行,运行时按新的 area_id 重新判定。
		data.AreaId = targetArea
	}
	if _, err := dao.Resource.Ctx(ctx).Data(data).Where(dao.Resource.Columns().Id, old.Id).Update(); err != nil {
		return nil, err
	}
	if err := s.reloadResources(ctx); err != nil {
		return nil, err
	}
	// 返回重载后的对象，确保 area_id/type/name 都来自最新缓存。
	return s.ResourceById(old.Id), nil
}

// resourceNameTaken 同一区域下是否已存在同名资源(excludeId 排除自身,用于更新)。
func (s *ResourceService) resourceNameTaken(areaId int, name string, excludeId int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.resources {
		if r.AreaId == areaId && r.Name == name && r.Id != excludeId {
			return true
		}
	}
	return false
}
