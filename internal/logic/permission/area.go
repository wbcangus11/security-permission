package permission

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
	"security-permission/internal/model/entity"
)

func SaveArea(ctx context.Context, userID string, input *model.AreaSaveInput) (*model.Area, error) {
	if input == nil {
		return nil, gerror.New("区域保存参数不能为空")
	}
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAreaManage)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("区域名称不能为空")
	}
	var saved *model.Area
	if input.Id <= 0 {
		saved, err = createArea(ctx, snapshot, input)
	} else {
		saved, err = updateArea(ctx, snapshot, input)
	}
	if err != nil {
		return nil, err
	}
	InvalidateAll()
	return saved, nil
}

func DeleteArea(ctx context.Context, userID string, areaID int) error {
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAreaManage)
	if err != nil {
		return err
	}
	target, err := findArea(ctx, areaID)
	if err != nil {
		return err
	}
	if target == nil {
		return gerror.New("区域不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根区域不允许删除")
	}
	if !snapshot.covers(treeKindArea, target.Path, target.Id) {
		return gerror.New("无权删除“" + target.Name + "”")
	}
	if count, err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, areaID).Count(); err != nil {
		return err
	} else if count > 0 {
		return gerror.New("“" + target.Name + "”下还有子区域，请先删除或移走")
	}
	if count, err := dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().AreaId, areaID).Count(); err != nil {
		return err
	} else if count > 0 {
		return gerror.New("“" + target.Name + "”下还有资源，请先移除")
	}
	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
			Where(dao.RoleDataScope.Columns().NodeId, areaID).
			WhereIn(dao.RoleDataScope.Columns().ScopeType, []string{model.ScopeTypeArea, model.ScopeTypeResourceArea}).
			Delete(); err != nil {
			return err
		}
		_, err := tx.Model(dao.Area.Table()).Ctx(ctx).Where(dao.Area.Columns().Id, areaID).Delete()
		return err
	})
	if err != nil {
		return err
	}
	InvalidateAll()
	return nil
}

func ReorderArea(ctx context.Context, userID string, input *model.AreaReorderInput) error {
	if input == nil {
		return gerror.New("区域排序参数不能为空")
	}
	snapshot, err := loadAuthorizedSnapshot(ctx, userID, menuAreaManage)
	if err != nil {
		return err
	}
	target, err := findArea(ctx, input.AreaId)
	if err != nil {
		return err
	}
	destination, err := findArea(ctx, input.ToAreaId)
	if err != nil {
		return err
	}
	if target == nil {
		return gerror.New("区域不存在")
	}
	if destination == nil {
		return gerror.New("目标区域不存在")
	}
	if target.Id == destination.Id {
		return nil
	}
	if target.ParentId == 0 || destination.ParentId == 0 {
		return gerror.New("根区域不允许参与排序")
	}
	if target.ParentId != destination.ParentId {
		return gerror.New("只能调整同一父区域下的区域顺序")
	}
	if !snapshot.covers(treeKindArea, target.Path, target.Id) {
		return gerror.New("无权调整“" + target.Name + "”排序")
	}
	if !snapshot.covers(treeKindArea, destination.Path, destination.Id) {
		return gerror.New("无权与目标区域“" + destination.Name + "”换序")
	}
	var rows []entity.Area
	if err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, target.ParentId).
		Order(dao.Area.Columns().Sort + "," + dao.Area.Columns().Id).Scan(&rows); err != nil {
		return err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Sort == rows[j].Sort {
			return rows[i].Id < rows[j].Id
		}
		return rows[i].Sort < rows[j].Sort
	})
	left, right := -1, -1
	for index := range rows {
		if int(rows[index].Id) == target.Id {
			left = index
		}
		if int(rows[index].Id) == destination.Id {
			right = index
		}
	}
	if left < 0 || right < 0 {
		return gerror.New("同级区域排序数据异常")
	}
	rows[left], rows[right] = rows[right], rows[left]
	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		for index, row := range rows {
			nextSort := (index + 1) * 10
			if row.Sort == nextSort {
				continue
			}
			if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{Sort: nextSort}).
				Where(dao.Area.Columns().Id, row.Id).Update(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func createArea(ctx context.Context, snapshot *permissionSnapshot, input *model.AreaSaveInput) (*model.Area, error) {
	parent, err := findArea(ctx, input.ParentId)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, gerror.New("父区域不存在")
	}
	if !snapshot.covers(treeKindArea, parent.Path, parent.Id) {
		return nil, gerror.New("无权在“" + parent.Name + "”下新增子区域")
	}
	if exists, err := areaNameExists(ctx, parent.Id, input.Name, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同级已存在同名区域：" + input.Name)
	}
	grantRoleID := snapshot.areaAutoGrantRole(parent)
	nextSort, err := nextAreaSort(ctx, parent.Id)
	if err != nil {
		return nil, err
	}
	var newID int64
	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		result, err := tx.Model(dao.Area.Table()).Ctx(ctx).
			Data(do.Area{ParentId: parent.Id, Name: input.Name, Path: "", Sort: nextSort}).Insert()
		if err != nil {
			return err
		}
		newID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		path := parent.Path + strconv.FormatInt(newID, 10) + "/"
		if _, err = tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{Path: path}).
			Where(dao.Area.Columns().Id, newID).Update(); err != nil {
			return err
		}
		if grantRoleID > 0 {
			_, err = tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
				RoleId: grantRoleID, ScopeType: model.ScopeTypeArea,
				NodeId: newID, IncludeChild: true,
			}).Insert()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return findArea(ctx, int(newID))
}

func updateArea(ctx context.Context, snapshot *permissionSnapshot, input *model.AreaSaveInput) (*model.Area, error) {
	old, err := findArea(ctx, input.Id)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, gerror.New("区域不存在")
	}
	if old.ParentId == 0 {
		return nil, gerror.New("根区域不允许修改")
	}
	if !snapshot.covers(treeKindArea, old.Path, old.Id) {
		return nil, gerror.New("无权管理“" + old.Name + "”")
	}
	moving := input.ParentId != 0 && input.ParentId != old.ParentId
	var newParent *model.Area
	if moving {
		newParent, err = findArea(ctx, input.ParentId)
		if err != nil {
			return nil, err
		}
		if newParent == nil {
			return nil, gerror.New("目标父区域不存在")
		}
		if strings.HasPrefix(newParent.Path, old.Path) {
			return nil, gerror.New("不能把区域移动到自己或自己的子区域下")
		}
		if !snapshot.covers(treeKindArea, newParent.Path, newParent.Id) {
			return nil, gerror.New("无权移动到“" + newParent.Name + "”下")
		}
	}
	parentID := old.ParentId
	if moving {
		parentID = newParent.Id
	}
	if exists, err := areaNameExists(ctx, parentID, input.Name, old.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同级已存在同名区域：" + input.Name)
	}
	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{Name: input.Name}).
			Where(dao.Area.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		if !moving {
			return nil
		}
		if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{ParentId: newParent.Id}).
			Where(dao.Area.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		newPrefix := newParent.Path + strconv.Itoa(old.Id) + "/"
		_, err := tx.Exec("UPDATE `area` SET `path`=CONCAT(?, SUBSTRING(`path`, ?)) WHERE `path` LIKE ?",
			newPrefix, len(old.Path)+1, old.Path+"%")
		return err
	})
	if err != nil {
		return nil, err
	}
	return findArea(ctx, old.Id)
}

func areaNameExists(ctx context.Context, parentID int, name string, excludeID int) (bool, error) {
	query := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, parentID).
		Where(dao.Area.Columns().Name, name)
	if excludeID > 0 {
		query = query.Where(dao.Area.Columns().Id+" <> ?", excludeID)
	}
	count, err := query.Count()
	return count > 0, err
}

func nextAreaSort(ctx context.Context, parentID int) (int, error) {
	var row struct{ MaxSort int }
	if err := dao.Area.Ctx(ctx).Fields("COALESCE(MAX(sort),0) AS max_sort").
		Where(dao.Area.Columns().ParentId, parentID).Scan(&row); err != nil {
		return 0, err
	}
	return row.MaxSort + 10, nil
}
