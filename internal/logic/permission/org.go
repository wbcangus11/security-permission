package permission

// 组织(组织机构树)增删改:写时鉴权 + 物化路径 path 自动维护。
// 与区域(area.go)完全对称,仅差三处:
//   功能关菜单 = 「人员信息」sys.person.info(组织树挂在人员信息下);
//   数据关 = CheckOrg / OrgScopes(scope_type=ORG);
//   删除前置 = 仅允许"无子组织且无下属用户"的叶子(区域是无资源,组织是无人员)。
//
// path 维护规则同区域:
//   新增:path = 父.path + 新ID + "/" —— 授权了父子树的角色零配置自动覆盖新组织;
//   移动:本节点改 parent_id,整棵子树(含自身)批量前缀替换 path —— 权限随树走;
//   删除:同步清理 role_data_scope 对该节点的 ORG 授权行,避免悬挂引用。

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

// Save 新增或更新(重命名/移动)组织,写时鉴权,成功后刷新缓存。actorId=操作人。
func (s *OrgService) Save(ctx context.Context, actorId string, in *model.OrgSaveInput) (*model.Org, error) {
	// 所有组织写操作先统一过功能关：必须拥有“人员信息”菜单权限。
	actor, err := s.checkOrgWriter(actorId)
	if err != nil {
		return nil, err
	}
	// 名称在进入新增/更新分支前清洗，避免同级重名校验被空格绕过。
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, gerror.New("组织名称不能为空")
	}
	// Id<=0 代表新增；否则进入重命名/移动逻辑。两个分支的数据权限校验对象不同。
	if in.Id <= 0 {
		return s.createOrg(ctx, actor, in)
	}
	return s.updateOrg(ctx, actor, in)
}

// Delete 删除组织(仅叶子且无下属用户),同步清理对该节点的数据范围授权。
func (s *OrgService) Delete(ctx context.Context, actorId string, orgId int) error {
	// 删除同样先过功能关；后续再判断目标组织是否在操作人的 ORG 数据范围内。
	actor, err := s.checkOrgWriter(actorId)
	if err != nil {
		return err
	}
	target := s.OrgById(orgId)
	if target == nil {
		return gerror.New("组织不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根组织不允许删除")
	}
	if d := s.CheckOrg(actor, orgId); !d.Allow {
		return gerror.New("无权删除「" + target.Name + "」:" + d.Reason)
	}
	// 对齐海康:非空组织不允许删除,先处理子组织与下属用户
	for _, o := range s.Orgs() {
		if o.ParentId == orgId {
			return gerror.New("「" + target.Name + "」下还有子组织,请先删除或移走")
		}
	}
	for _, u := range s.Users() {
		if u.OrgId == orgId {
			return gerror.New("「" + target.Name + "」下还有用户(如" + u.Name + "),请先移走")
		}
	}
	err = dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 组织主表和授权引用必须在同一事务内处理，避免删了一半留下悬挂授权。
		if _, err := tx.Model(dao.Org.Table()).Ctx(ctx).Where(dao.Org.Columns().Id, orgId).Delete(); err != nil {
			return err
		}
		// 清理引用该节点的组织树范围授权(仅 ORG;AREA/RES_AREA 不涉及组织)
		_, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
			Where(dao.RoleDataScope.Columns().NodeId, orgId).
			Where(dao.RoleDataScope.Columns().ScopeType, model.ScopeTypeOrg).
			Delete()
		return err
	})
	if err != nil {
		return err
	}
	// 删除组织可能改变角色的 ORG 范围，也会改变用户有效权限快照，所以组织和角色一起重载。
	return s.reloadOrgsAndRoles(ctx)
}

// checkOrgWriter 写操作公共前置:操作人存在 + 功能关(sys.person.info 菜单)。
func (s *OrgService) checkOrgWriter(actorId string) (*model.User, error) {
	actor := s.User(actorId)
	if actor == nil {
		return nil, gerror.New("操作人不存在")
	}
	if d := s.CheckMenu(actor, menuOrgManage); !d.Allow {
		return nil, gerror.New("功能权限不足:" + d.Reason)
	}
	return actor, nil
}

// createOrg 新增子组织:数据关看父组织;插入后回填 path=父.path+新ID+"/"。
func (s *OrgService) createOrg(ctx context.Context, actor *model.User, in *model.OrgSaveInput) (*model.Org, error) {
	parent := s.OrgById(in.ParentId)
	if parent == nil {
		return nil, gerror.New("父组织不存在")
	}
	// 新增组织的数据关看父组织：只有能管理父组织的人，才能在其下创建子组织。
	if d := s.CheckOrg(actor, parent.Id); !d.Allow {
		return nil, gerror.New("无权在「" + parent.Name + "」下新增子组织:" + d.Reason)
	}
	// 同级唯一是业务约束，数据库唯一索引兜底前先给出更可读的错误。
	if s.orgNameTaken(parent.Id, in.Name, 0) {
		return nil, gerror.New("同级已存在同名组织:" + in.Name)
	}
	var newId int64
	err := dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 先插入空 path 拿自增 id；path 必须包含自身 id，所以只能回填。
		res, err := tx.Model(dao.Org.Table()).Ctx(ctx).
			Data(do.Org{ParentId: parent.Id, Name: in.Name, Path: ""}).Insert()
		if err != nil {
			return err
		}
		if newId, err = res.LastInsertId(); err != nil {
			return err
		}
		// 物化路径含自身;授权了父子树的角色自此自动覆盖新组织(无需改 role_data_scope)
		path := parent.Path + strconv.FormatInt(newId, 10) + "/"
		_, err = tx.Model(dao.Org.Table()).Ctx(ctx).Data(do.Org{Path: path}).Where(dao.Org.Columns().Id, newId).Update()
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.reloadOrgs(ctx); err != nil {
		return nil, err
	}
	// 返回重载后的对象，确保调用方拿到的是最终 path，而不是插入时的空 path。
	return s.OrgById(int(newId)), nil
}

// updateOrg 重命名 + 可选移动:移动需对本节点和新父都有权,且防环(新父不能是自己或后代)。
func (s *OrgService) updateOrg(ctx context.Context, actor *model.User, in *model.OrgSaveInput) (*model.Org, error) {
	old := s.OrgById(in.Id)
	if old == nil {
		return nil, gerror.New("组织不存在")
	}
	if old.ParentId == 0 {
		return nil, gerror.New("根组织不允许修改")
	}
	if d := s.CheckOrg(actor, old.Id); !d.Allow {
		return nil, gerror.New("无权管理「" + old.Name + "」:" + d.Reason)
	}

	// ParentId 不传或等于原父级时只重命名；传了新的父级才进入移动逻辑。
	moving := in.ParentId != 0 && in.ParentId != old.ParentId
	var newParent *model.Org
	if moving {
		if newParent = s.OrgById(in.ParentId); newParent == nil {
			return nil, gerror.New("目标父组织不存在")
		}
		// 防环:新父的 path 以本节点 path 为前缀 => 新父是自己或自己的后代
		if strings.HasPrefix(newParent.Path, old.Path) {
			return nil, gerror.New("不能把组织移动到自己或自己的子组织下")
		}
		// 移动组织要同时有“原组织”和“新父组织”权限，否则可以借移动把组织转移到无权范围。
		if d := s.CheckOrg(actor, newParent.Id); !d.Allow {
			return nil, gerror.New("无权移动到「" + newParent.Name + "」下:" + d.Reason)
		}
	}
	// 重名校验的父级取决于是否移动：移动时按新父级查，不移动按原父级查。
	dupParent := old.ParentId
	if moving {
		dupParent = newParent.Id
	}
	if s.orgNameTaken(dupParent, in.Name, old.Id) {
		return nil, gerror.New("同级已存在同名组织:" + in.Name)
	}

	err := dao.Org.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 名称总是更新；父级和 path 只有移动时才更新。
		if _, err := tx.Model(dao.Org.Table()).Ctx(ctx).
			Data(do.Org{Name: in.Name}).Where(dao.Org.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		if !moving {
			return nil
		}
		if _, err := tx.Model(dao.Org.Table()).Ctx(ctx).
			Data(do.Org{ParentId: newParent.Id}).Where(dao.Org.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		// 整棵子树(含自身)批量前缀替换:旧前缀=old.Path,新前缀=新父.path+本ID+"/"
		// path 仅由数字和 "/" 组成,LIKE 无需转义;SUBSTRING 从旧前缀之后接回剩余路径
		newPrefix := newParent.Path + strconv.Itoa(old.Id) + "/"
		_, err := tx.Exec(
			"UPDATE `org` SET `path`=CONCAT(?, SUBSTRING(`path`, ?)) WHERE `path` LIKE ?",
			newPrefix, len(old.Path)+1, old.Path+"%")
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.reloadOrgs(ctx); err != nil {
		return nil, err
	}
	// 移动后 path 已批量重写，必须从新缓存里返回对象。
	return s.OrgById(old.Id), nil
}

// orgNameTaken 同一父节点下是否已存在同名组织(excludeId 排除自身,用于更新)。
func (s *OrgService) orgNameTaken(parentId int, name string, excludeId int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, o := range s.orgs {
		if o.ParentId == parentId && o.Name == name && o.Id != excludeId {
			return true
		}
	}
	return false
}
