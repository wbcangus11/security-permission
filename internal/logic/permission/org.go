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

func (e *evaluator) checkOrgWriter(userID string) (*model.User, error) {
	user := e.user(userID)
	if e.err != nil {
		return nil, e.err
	}
	if user == nil {
		return nil, gerror.New("操作人不存在")
	}
	decision := e.checkMenu(user, menuOrgManage)
	if e.err != nil {
		return nil, e.err
	}
	if !decision.Allow {
		return nil, gerror.New("功能权限不足：" + decision.Reason)
	}
	return user, nil
}

func SaveOrg(ctx context.Context, userID string, input *model.OrgSaveInput) (*model.Org, error) {
	ev := newEvaluator(ctx)
	user, err := ev.checkOrgWriter(userID)
	if err != nil {
		return nil, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, gerror.New("组织名称不能为空")
	}
	if input.Id <= 0 {
		return createOrg(ctx, ev, user, input)
	}
	return updateOrg(ctx, ev, user, input)
}

func DeleteOrg(ctx context.Context, userID string, orgID int) error {
	ev := newEvaluator(ctx)
	user, err := ev.checkOrgWriter(userID)
	if err != nil {
		return err
	}
	target := ev.org(orgID)
	if ev.err != nil {
		return ev.err
	}
	if target == nil {
		return gerror.New("组织不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根组织不允许删除")
	}
	decision := ev.checkTree(user, orgID, treeKindOrg)
	if !decision.Allow {
		return gerror.New("无权删除“" + target.Name + "”：" + decision.Reason)
	}
	if ev.err != nil {
		return ev.err
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
	permissionHotCache.invalidateAll()
	return nil
}

func createOrg(ctx context.Context, ev *evaluator, user *model.User, input *model.OrgSaveInput) (*model.Org, error) {
	parent := ev.org(input.ParentId)
	if ev.err != nil {
		return nil, ev.err
	}
	if parent == nil {
		return nil, gerror.New("父组织不存在")
	}
	decision := ev.checkTree(user, parent.Id, treeKindOrg)
	if !decision.Allow {
		return nil, gerror.New("无权在“" + parent.Name + "”下新增子组织：" + decision.Reason)
	}
	if ev.err != nil {
		return nil, ev.err
	}
	if exists, err := orgNameExists(ctx, parent.Id, input.Name, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, gerror.New("同级已存在同名组织：" + input.Name)
	}
	var newID int64
	err := dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
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
	permissionHotCache.invalidateAll()
	return findOrg(ctx, int(newID))
}

func updateOrg(ctx context.Context, ev *evaluator, user *model.User, input *model.OrgSaveInput) (*model.Org, error) {
	old := ev.org(input.Id)
	if ev.err != nil {
		return nil, ev.err
	}
	if old == nil {
		return nil, gerror.New("组织不存在")
	}
	if old.ParentId == 0 {
		return nil, gerror.New("根组织不允许修改")
	}
	if decision := ev.checkTree(user, old.Id, treeKindOrg); !decision.Allow {
		return nil, gerror.New("无权管理“" + old.Name + "”：" + decision.Reason)
	}
	moving := input.ParentId != 0 && input.ParentId != old.ParentId
	var newParent *model.Org
	if moving {
		newParent = ev.org(input.ParentId)
		if newParent == nil {
			return nil, gerror.New("目标父组织不存在")
		}
		if strings.HasPrefix(newParent.Path, old.Path) {
			return nil, gerror.New("不能把组织移动到自己或自己的子组织下")
		}
		if decision := ev.checkTree(user, newParent.Id, treeKindOrg); !decision.Allow {
			return nil, gerror.New("无权移动到“" + newParent.Name + "”下：" + decision.Reason)
		}
	}
	if ev.err != nil {
		return nil, ev.err
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
	err := dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
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
	permissionHotCache.invalidateAll()
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
