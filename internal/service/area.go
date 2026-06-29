package service

// 区域(安保区域树)增删改:写时鉴权 + 物化路径 path 自动维护。
//
// 鉴权规则(写操作同样过"两个维度",复用运行时鉴权引擎):
//   功能关:操作人须有「安保区域管理」菜单(sys.area);
//   数据关:新增看父区域、重命名/删除看本区域、移动还要看新父区域。
//
// path 维护规则(这是"授权子树 → 新增节点自动继承"真正用起来的关键):
//   新增:path = 父.path + 新ID + "/" —— 授权了父子树的角色零配置自动覆盖新区域;
//   移动:本节点改 parent_id,整棵子树(含自身)批量前缀替换 path —— 权限随树走;
//   删除:对齐海康,仅允许"无子区域且无资源"的叶子,删除时同步清理
//         role_data_scope 对该节点的 AREA / RES_AREA 授权行,避免悬挂引用。

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
)

// menuAreaManage 安保区域管理菜单 code(写操作的功能关)。
const menuAreaManage = "sys.area"

// AreaSaveInput 新增/重命名/移动区域的入参。
// Id<=0 为新增(ParentId=父区域);更新时 ParentId 非 0 且与原值不同即移动。
type AreaSaveInput struct {
	Id       int    `json:"id"`
	ParentId int    `json:"parentId"`
	Name     string `json:"name"`
}

type AreaReorderInput struct {
	Id        int    `json:"id"`
	Direction string `json:"direction"` // up/down
}

// SaveArea 新增或更新(重命名/移动)区域,写时鉴权,成功后刷新缓存。actorId=操作人。
func (s *Store) SaveArea(ctx context.Context, actorId int, in *AreaSaveInput) (*model.Area, error) {
	actor, err := s.checkAreaWriter(actorId)
	if err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, gerror.New("区域名称不能为空")
	}
	if in.Id <= 0 {
		return s.createArea(ctx, actor, in)
	}
	return s.updateArea(ctx, actor, in)
}

// DeleteArea 删除区域(仅叶子且无资源),同步清理对该节点的数据范围授权。
func (s *Store) DeleteArea(ctx context.Context, actorId, areaId int) error {
	actor, err := s.checkAreaWriter(actorId)
	if err != nil {
		return err
	}
	target := s.AreaById(areaId)
	if target == nil {
		return gerror.New("区域不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根区域不允许删除")
	}
	if d := s.CheckArea(actor, areaId); !d.Allow {
		return gerror.New("无权删除「" + target.Name + "」:" + d.Reason)
	}
	// 对齐海康:非空区域不允许删除,先处理子区域与资源
	for _, a := range s.Areas() {
		if a.ParentId == areaId {
			return gerror.New("「" + target.Name + "」下还有子区域,请先删除或移走")
		}
	}
	for _, r := range s.Resources() {
		if r.AreaId == areaId {
			return gerror.New("「" + target.Name + "」下还有资源,请先移除")
		}
	}
	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).Where(dao.Area.Columns().Id, areaId).Delete(); err != nil {
			return err
		}
		// 清理引用该节点的树范围授权(管理域 AREA + 应用域 RES_AREA;ORG 不涉及区域)
		_, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).
			Where(dao.RoleDataScope.Columns().NodeId, areaId).
			WhereIn(dao.RoleDataScope.Columns().ScopeType, []string{model.ScopeTypeArea, model.ScopeTypeResourceArea}).
			Delete()
		return err
	})
	if err != nil {
		return err
	}
	return s.reloadAreasAndRoles(ctx)
}

func (s *Store) ReorderArea(ctx context.Context, actorId int, in *AreaReorderInput) error {
	actor, err := s.checkAreaWriter(actorId)
	if err != nil {
		return err
	}
	target := s.AreaById(in.Id)
	if target == nil {
		return gerror.New("区域不存在")
	}
	if target.ParentId == 0 {
		return gerror.New("根区域不允许排序")
	}
	if d := s.CheckArea(actor, target.Id); !d.Allow {
		return gerror.New("无权调整「" + target.Name + "」排序:" + d.Reason)
	}
	if in.Direction != sortDirectionUp && in.Direction != sortDirectionDown {
		return gerror.New("排序方向只能是 up/down")
	}

	siblings := make([]*model.Area, 0)
	for _, a := range s.Areas() {
		if a.ParentId == target.ParentId {
			siblings = append(siblings, a)
		}
	}
	sort.Slice(siblings, func(i, j int) bool {
		if siblings[i].Sort == siblings[j].Sort {
			return siblings[i].Id < siblings[j].Id
		}
		return siblings[i].Sort < siblings[j].Sort
	})

	idx := -1
	for i, a := range siblings {
		if a.Id == target.Id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return gerror.New("区域不存在")
	}
	swapIdx := idx - 1
	if in.Direction == sortDirectionDown {
		swapIdx = idx + 1
	}
	if swapIdx < 0 || swapIdx >= len(siblings) {
		return nil
	}
	if d := s.CheckArea(actor, siblings[swapIdx].Id); !d.Allow {
		return gerror.New("无权与相邻区域「" + siblings[swapIdx].Name + "」换序:" + d.Reason)
	}

	err = dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		siblings[idx], siblings[swapIdx] = siblings[swapIdx], siblings[idx]
		for i, a := range siblings {
			nextSort := (i + 1) * 10
			if a.Sort == nextSort {
				continue
			}
			if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{Sort: nextSort}).Where(dao.Area.Columns().Id, a.Id).Update(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.reloadAreas(ctx)
}

// checkAreaWriter 写操作公共前置:操作人存在 + 功能关(sys.area 菜单)。
func (s *Store) checkAreaWriter(actorId int) (*model.User, error) {
	actor := s.User(actorId)
	if actor == nil {
		return nil, gerror.New("操作人不存在")
	}
	if d := s.CheckMenu(actor, menuAreaManage); !d.Allow {
		return nil, gerror.New("功能权限不足:" + d.Reason)
	}
	return actor, nil
}

// createArea 新增子区域:数据关看父区域;插入后回填 path=父.path+新ID+"/"。
func (s *Store) createArea(ctx context.Context, actor *model.User, in *AreaSaveInput) (*model.Area, error) {
	parent := s.AreaById(in.ParentId)
	if parent == nil {
		return nil, gerror.New("父区域不存在")
	}
	if d := s.CheckArea(actor, parent.Id); !d.Allow {
		return nil, gerror.New("无权在「" + parent.Name + "」下新增子区域:" + d.Reason)
	}
	if s.areaNameTaken(parent.Id, in.Name, 0) {
		return nil, gerror.New("同级已存在同名区域:" + in.Name)
	}
	// 创建即授权:父区域若是「仅本节点」授权(include_child=false),新区域不会被现有数据范围
	// 自动继承 → 创建者建完却看不到自己建的区域。此时把「新区域(含子树)」补进赋予创建者建权的
	// 那个角色,确保创建者立刻能在区域树/角色配置里看到并管理它(对齐「谁建谁能看」)。
	// 父若已是子树授权,新区域本就自动继承,grantRoleId=0 不重复记,保持数据干净。
	grantRoleId := s.areaAutoGrantRole(actor, parent)
	nextSort := s.nextAreaSort(parent.Id)
	var newId int64
	err := dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		res, err := tx.Model(dao.Area.Table()).Ctx(ctx).
			Data(do.Area{ParentId: parent.Id, Name: in.Name, Path: "", Sort: nextSort}).Insert()
		if err != nil {
			return err
		}
		if newId, err = res.LastInsertId(); err != nil {
			return err
		}
		// 物化路径含自身;授权了父子树的角色自此自动覆盖新区域(无需改 role_data_scope)
		path := parent.Path + strconv.FormatInt(newId, 10) + "/"
		if _, err = tx.Model(dao.Area.Table()).Ctx(ctx).Data(do.Area{Path: path}).Where(dao.Area.Columns().Id, newId).Update(); err != nil {
			return err
		}
		if grantRoleId > 0 {
			_, err = tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
				RoleId:       grantRoleId,
				ScopeType:    model.ScopeTypeArea,
				NodeId:       newId,
				IncludeChild: true,
			}).Insert()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.reloadAreasAndRoles(ctx); err != nil {
		return nil, err
	}
	return s.AreaById(int(newId)), nil
}

func (s *Store) nextAreaSort(parentId int) int {
	maxSort := 0
	for _, a := range s.Areas() {
		if a.ParentId == parentId && a.Sort > maxSort {
			maxSort = a.Sort
		}
	}
	return maxSort + 10
}

// areaAutoGrantRole 决定「创建即授权」是否需要补一条 AREA 范围、补给哪个角色。
// 返回 roleId>0 表示要把新区域授给该角色;返回 0 表示新区域本就会被自动继承(无需补)或操作人是超管。
// 规则:
//   - 超管 → 0(本就看全部)。
//   - 若操作人已有「含子树且覆盖父区域」的授权 → 新区域会自动继承 → 0(不重复记)。
//   - 否则取「第一个授权覆盖了父区域(直接节点或子树)的角色」= 赋予其建权的角色,补给它。
func (s *Store) areaAutoGrantRole(actor *model.User, parent *model.Area) int {
	if actor == nil || actor.IsSuperuser || parent == nil {
		return 0
	}
	coveringRole := 0      // 第一个覆盖父区域的角色(赋予建权来源)
	childInherits := false // 父已落在某含子树授权内 → 新子区域自动继承
	for _, r := range s.effectiveRoles(actor) {
		for _, sc := range r.AreaScopes {
			a := s.AreaById(sc.NodeId)
			if a == nil || a.Path == "" {
				continue
			}
			subtreeCoversParent := sc.IncludeChild && strings.HasPrefix(parent.Path, a.Path)
			if (sc.NodeId == parent.Id || subtreeCoversParent) && coveringRole == 0 {
				coveringRole = r.Id
			}
			if subtreeCoversParent {
				childInherits = true
			}
		}
	}
	if childInherits {
		return 0
	}
	return coveringRole
}

// updateArea 重命名 + 可选移动:移动需对本节点和新父都有权,且防环(新父不能是自己或后代)。
func (s *Store) updateArea(ctx context.Context, actor *model.User, in *AreaSaveInput) (*model.Area, error) {
	old := s.AreaById(in.Id)
	if old == nil {
		return nil, gerror.New("区域不存在")
	}
	if old.ParentId == 0 {
		return nil, gerror.New("根区域不允许修改")
	}
	if d := s.CheckArea(actor, old.Id); !d.Allow {
		return nil, gerror.New("无权管理「" + old.Name + "」:" + d.Reason)
	}

	moving := in.ParentId != 0 && in.ParentId != old.ParentId
	var newParent *model.Area
	if moving {
		if newParent = s.AreaById(in.ParentId); newParent == nil {
			return nil, gerror.New("目标父区域不存在")
		}
		// 防环:新父的 path 以本节点 path 为前缀 => 新父是自己或自己的后代
		if strings.HasPrefix(newParent.Path, old.Path) {
			return nil, gerror.New("不能把区域移动到自己或自己的子区域下")
		}
		if d := s.CheckArea(actor, newParent.Id); !d.Allow {
			return nil, gerror.New("无权移动到「" + newParent.Name + "」下:" + d.Reason)
		}
	}
	dupParent := old.ParentId
	if moving {
		dupParent = newParent.Id
	}
	if s.areaNameTaken(dupParent, in.Name, old.Id) {
		return nil, gerror.New("同级已存在同名区域:" + in.Name)
	}

	err := dao.Area.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).
			Data(do.Area{Name: in.Name}).Where(dao.Area.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		if !moving {
			return nil
		}
		if _, err := tx.Model(dao.Area.Table()).Ctx(ctx).
			Data(do.Area{ParentId: newParent.Id}).Where(dao.Area.Columns().Id, old.Id).Update(); err != nil {
			return err
		}
		// 整棵子树(含自身)批量前缀替换:旧前缀=old.Path,新前缀=新父.path+本ID+"/"
		// path 仅由数字和 "/" 组成,LIKE 无需转义;SUBSTRING 从旧前缀之后接回剩余路径
		newPrefix := newParent.Path + strconv.Itoa(old.Id) + "/"
		_, err := tx.Exec(
			"UPDATE `area` SET `path`=CONCAT(?, SUBSTRING(`path`, ?)) WHERE `path` LIKE ?",
			newPrefix, len(old.Path)+1, old.Path+"%")
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = s.reloadAreas(ctx); err != nil {
		return nil, err
	}
	return s.AreaById(old.Id), nil
}

// areaNameTaken 同一父节点下是否已存在同名区域(excludeId 排除自身,用于更新)。
func (s *Store) areaNameTaken(parentId int, name string, excludeId int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.areas {
		if a.ParentId == parentId && a.Name == name && a.Id != excludeId {
			return true
		}
	}
	return false
}
