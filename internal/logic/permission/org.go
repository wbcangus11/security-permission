package permission

import (
	"context"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
)

func SaveOrg(ctx context.Context, input *model.OrgSaveInput) (*model.Org, error) {
	if input == nil {
		return nil, gerror.New("组织保存参数不能为空")
	}
	snapshot, err := loadAuthorizedSnapshot(ctx, menuOrgManage)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("组织名称不能为空")
	}
	var saved *model.Org
	if input.Id <= 0 {
		saved, err = createOrg(ctx, snapshot, input)
	} else {
		saved, err = updateOrg(ctx, snapshot, input)
	}
	if err != nil {
		return nil, err
	}
	InvalidateAll()
	return saved, nil
}

func DeleteOrg(ctx context.Context, orgID int) error {
	snapshot, err := loadAuthorizedSnapshot(ctx, menuOrgManage)
	if err != nil {
		return err
	}
	target, err := findOrg(ctx, orgID)
	if err != nil {
		return err
	}
	if target == nil {
		return gerror.New("组织不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根组织不允许删除")
	}
	if !snapshot.covers(treeKindOrg, target.Path, target.Id) {
		return gerror.New("无权删除“" + target.Name + "”")
	}
	if count, err := dao.Org.Ctx(ctx).Where(dao.Org.Columns().ParentId, orgID).Count(); err != nil {
		return err
	} else if count > 0 {
		return gerror.New("“" + target.Name + "”下还有子组织，请先删除或移走")
	}
	if count, err := dao.User.Ctx(ctx).Where(dao.User.Columns().OrgId, orgID).Count(); err != nil {
		return err
	} else if count > 0 {
		return gerror.New("“" + target.Name + "”下还有用户，请先移走")
	}
	err = dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
			Where(dao.RoleDataScope.Columns().NodeId, orgID).
			Where(dao.RoleDataScope.Columns().ScopeType, model.ScopeTypeOrg).Delete(); err != nil {
			return err
		}
		_, err := tx.Model(dao.Org.Table()).Ctx(ctx).Where(dao.Org.Columns().Id, orgID).Delete()
		return err
	})
	if err != nil {
		return err
	}
	InvalidateAll()
	return nil
}

func createOrg(ctx context.Context, snapshot *permissionSnapshot, input *model.OrgSaveInput) (*model.Org, error) {
	parent, err := findOrg(ctx, input.ParentId)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, gerror.New("父组织不存在")
	}
	if !snapshot.covers(treeKindOrg, parent.Path, parent.Id) {
		return nil, gerror.New("无权在“" + parent.Name + "”下新增子组织")
	}
	if exists, err := orgNameExists(ctx, parent.Id, input.Name, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同级已存在同名组织：" + input.Name)
	}
	var newID int64
	err = dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		result, err := tx.Model(dao.Org.Table()).Ctx(ctx).
			Data(do.Org{ParentId: parent.Id, Name: input.Name, Path: ""}).Insert()
		if err != nil {
			return err
		}
		newID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		path := parent.Path + strconv.FormatInt(newID, 10) + "/"
		_, err = tx.Model(dao.Org.Table()).Ctx(ctx).Data(do.Org{Path: path}).
			Where(dao.Org.Columns().Id, newID).Update()
		return err
	})
	if err != nil {
		return nil, err
	}
	return findOrg(ctx, int(newID))
}

func updateOrg(ctx context.Context, snapshot *permissionSnapshot, input *model.OrgSaveInput) (*model.Org, error) {
	old, err := findOrg(ctx, input.Id)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, gerror.New("组织不存在")
	}
	if old.ParentId == 0 {
		return nil, gerror.New("根组织不允许修改")
	}
	if !snapshot.covers(treeKindOrg, old.Path, old.Id) {
		return nil, gerror.New("无权管理“" + old.Name + "”")
	}
	moving := input.ParentId != 0 && input.ParentId != old.ParentId
	var newParent *model.Org
	if moving {
		newParent, err = findOrg(ctx, input.ParentId)
		if err != nil {
			return nil, err
		}
		if newParent == nil {
			return nil, gerror.New("目标父组织不存在")
		}
		if strings.HasPrefix(newParent.Path, old.Path) {
			return nil, gerror.New("不能把组织移动到自己或自己的子组织下")
		}
		if !snapshot.covers(treeKindOrg, newParent.Path, newParent.Id) {
			return nil, gerror.New("无权移动到“" + newParent.Name + "”下")
		}
	}
	parentID := old.ParentId
	if moving {
		parentID = newParent.Id
	}
	if exists, err := orgNameExists(ctx, parentID, input.Name, old.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同级已存在同名组织：" + input.Name)
	}
	err = dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.Org.Table()).Ctx(ctx).Data(do.Org{Name: input.Name}).
			Where(dao.Org.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		if !moving {
			return nil
		}
		if _, err := tx.Model(dao.Org.Table()).Ctx(ctx).Data(do.Org{ParentId: newParent.Id}).
			Where(dao.Org.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		newPrefix := newParent.Path + strconv.Itoa(old.Id) + "/"
		_, err := tx.Exec("UPDATE `org` SET `path`=CONCAT(?, SUBSTRING(`path`, ?)) WHERE `path` LIKE ?",
			newPrefix, len(old.Path)+1, old.Path+"%")
		return err
	})
	if err != nil {
		return nil, err
	}
	return findOrg(ctx, old.Id)
}

func orgNameExists(ctx context.Context, parentID int, name string, excludeID int) (bool, error) {
	query := dao.Org.Ctx(ctx).Where(dao.Org.Columns().ParentId, parentID).
		Where(dao.Org.Columns().Name, name)
	if excludeID > 0 {
		query = query.Where(dao.Org.Columns().Id+" <> ?", excludeID)
	}
	count, err := query.Count()
	return count > 0, err
}
