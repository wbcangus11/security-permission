package permission

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
)

func SaveResource(ctx context.Context, input *model.ResourceSaveInput) (*model.Resource, error) {
	if input == nil {
		return nil, gerror.New("资源保存参数不能为空")
	}
	snapshot, err := loadAuthorizedSnapshot(ctx, menuResourceManage)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("资源名称不能为空")
	}
	if input.Id <= 0 {
		return createResource(ctx, snapshot, input)
	}
	return updateResource(ctx, snapshot, input)
}

func DeleteResource(ctx context.Context, resourceID int) error {
	snapshot, err := loadAuthorizedSnapshot(ctx, menuResourceManage)
	if err != nil {
		return err
	}
	target, err := findResource(ctx, resourceID)
	if err != nil {
		return err
	}
	if target == nil {
		return gerror.New("资源不存在")
	}
	area, err := findArea(ctx, target.AreaId)
	if err != nil {
		return err
	}
	if area == nil || !snapshot.covers(treeKindArea, area.Path, area.Id) {
		return gerror.New("无权删除“" + target.Name + "”")
	}
	if _, err = dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().Id, resourceID).Delete(); err != nil {
		return err
	}
	return nil
}

func createResource(ctx context.Context, snapshot *permissionSnapshot, input *model.ResourceSaveInput) (*model.Resource, error) {
	area, err := findArea(ctx, input.AreaId)
	if err != nil {
		return nil, err
	}
	if area == nil {
		return nil, gerror.New("所在区域不存在")
	}
	if !snapshot.covers(treeKindArea, area.Path, area.Id) {
		return nil, gerror.New("无权在“" + area.Name + "”下新增资源")
	}
	if input.Type == "" {
		input.Type = "camera"
	}
	if exists, err := resourceNameExists(ctx, area.Id, input.Name, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同区域已存在同名资源：" + input.Name)
	}
	result, err := dao.Resource.Ctx(ctx).Data(do.Resource{
		AreaId: area.Id, Type: input.Type, Name: input.Name,
	}).Insert()
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return findResource(ctx, int(id))
}

func updateResource(ctx context.Context, snapshot *permissionSnapshot, input *model.ResourceSaveInput) (*model.Resource, error) {
	old, err := findResource(ctx, input.Id)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, gerror.New("资源不存在")
	}
	oldArea, err := findArea(ctx, old.AreaId)
	if err != nil {
		return nil, err
	}
	if oldArea == nil || !snapshot.covers(treeKindArea, oldArea.Path, oldArea.Id) {
		return nil, gerror.New("无权管理“" + old.Name + "”所在区域")
	}
	targetAreaID := old.AreaId
	if input.AreaId != 0 && input.AreaId != old.AreaId {
		area, err := findArea(ctx, input.AreaId)
		if err != nil {
			return nil, err
		}
		if area == nil {
			return nil, gerror.New("目标区域不存在")
		}
		if !snapshot.covers(treeKindArea, area.Path, area.Id) {
			return nil, gerror.New("无权移动到“" + area.Name + "”")
		}
		targetAreaID = area.Id
	}
	resourceType := input.Type
	if resourceType == "" {
		resourceType = old.Type
	}
	if exists, err := resourceNameExists(ctx, targetAreaID, input.Name, old.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同区域已存在同名资源：" + input.Name)
	}
	if _, err := dao.Resource.Ctx(ctx).Data(do.Resource{
		AreaId: targetAreaID, Name: input.Name, Type: resourceType,
	}).Where(dao.Resource.Columns().Id, old.Id).Update(); err != nil {
		return nil, err
	}
	return findResource(ctx, old.Id)
}

func resourceNameExists(ctx context.Context, areaID int, name string, excludeID int) (bool, error) {
	query := dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().AreaId, areaID).
		Where(dao.Resource.Columns().Name, name)
	if excludeID > 0 {
		query = query.Where(dao.Resource.Columns().Id+" <> ?", excludeID)
	}
	count, err := query.Count()
	return count > 0, err
}
