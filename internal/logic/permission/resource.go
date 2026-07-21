package permission

import (
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
)

func (e *evaluator) checkResourceWriter(userID string) (*model.User, error) {
	user := e.user(userID)
	if e.err != nil {
		return nil, e.err
	}
	if user == nil {
		return nil, gerror.New("操作人不存在")
	}
	decision := e.checkMenu(user, menuResourceManage)
	if e.err != nil {
		return nil, e.err
	}
	if !decision.Allow {
		return nil, gerror.New("功能权限不足：" + decision.Reason)
	}
	return user, nil
}

func SaveResource(ctx context.Context, userID string, input *model.ResourceSaveInput) (*model.Resource, error) {
	ev := newEvaluator(ctx)
	user, err := ev.checkResourceWriter(userID)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("资源名称不能为空")
	}
	if input.Id <= 0 {
		return createResource(ctx, ev, user, input)
	}
	return updateResource(ctx, ev, user, input)
}

func DeleteResource(ctx context.Context, userID string, resourceID int) error {
	ev := newEvaluator(ctx)
	user, err := ev.checkResourceWriter(userID)
	if err != nil {
		return err
	}
	target := ev.resource(resourceID)
	if ev.err != nil {
		return ev.err
	}
	if target == nil {
		return gerror.New("资源不存在")
	}
	decision := ev.checkTree(user, target.AreaId, treeKindArea)
	if !decision.Allow {
		return gerror.New("无权删除“" + target.Name + "”：" + decision.Reason)
	}
	if ev.err != nil {
		return ev.err
	}
	if _, err = dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().Id, resourceID).Delete(); err != nil {
		return err
	}
	permissionHotCache.invalidateAll()
	return nil
}

func createResource(ctx context.Context, ev *evaluator, user *model.User, input *model.ResourceSaveInput) (*model.Resource, error) {
	area := ev.area(input.AreaId)
	if ev.err != nil {
		return nil, ev.err
	}
	if area == nil {
		return nil, gerror.New("所在区域不存在")
	}
	decision := ev.checkTree(user, area.Id, treeKindArea)
	if !decision.Allow {
		return nil, gerror.New("无权在“" + area.Name + "”下新增资源：" + decision.Reason)
	}
	if ev.err != nil {
		return nil, ev.err
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
	permissionHotCache.invalidateAll()
	return findResource(ctx, int(id))
}

func updateResource(ctx context.Context, ev *evaluator, user *model.User, input *model.ResourceSaveInput) (*model.Resource, error) {
	old := ev.resource(input.Id)
	if ev.err != nil {
		return nil, ev.err
	}
	if old == nil {
		return nil, gerror.New("资源不存在")
	}
	if decision := ev.checkTree(user, old.AreaId, treeKindArea); !decision.Allow {
		return nil, gerror.New("无权管理“" + old.Name + "”所在区域：" + decision.Reason)
	}
	targetAreaID := old.AreaId
	if input.AreaId != 0 && input.AreaId != old.AreaId {
		area := ev.area(input.AreaId)
		if area == nil {
			return nil, gerror.New("目标区域不存在")
		}
		if decision := ev.checkTree(user, area.Id, treeKindArea); !decision.Allow {
			return nil, gerror.New("无权移动到“" + area.Name + "”：" + decision.Reason)
		}
		targetAreaID = area.Id
	}
	if ev.err != nil {
		return nil, ev.err
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
	permissionHotCache.invalidateAll()
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
