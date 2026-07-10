package permission

import (
	"strings"

	"security-permission/internal/model"
)

// 受控委派(二次授权)—— 模型 A:写时合并 + 运行时按创建人当前权限收窄。
//
// 规则:保存角色时,新角色的权限必须 ⊆ 操作者(创建人)的有效权限。
// 校验通过后子角色权限独立存储;运行时再与创建人的当前有效权限取交集,
// 避免上级收回创建人权限后,被委派出去的角色继续保有旧权限。
// actorId=="0" 视为系统管理员/不受限。

// ---------- 单角色级判断(供"新角色"求权限用) ----------

func roleHasMenuId(r *model.Role, menuId int) bool {
	for _, m := range r.MenuIds {
		if m == menuId {
			return true
		}
	}
	return false
}

// roleAllowsTree 判断某角色的树范围是否覆盖目标节点(精确命中或含子树)。
func (s *PermissionService) roleAllowsTree(scopes []model.DataScope, kind string, nodeId int) bool {
	targetPath := s.nodePath(kind, nodeId)
	if targetPath == "" {
		return false
	}
	for _, sc := range scopes {
		if sc.NodeId == nodeId {
			return true
		}
		if sc.IncludeChild {
			if p := s.nodePath(kind, sc.NodeId); p != "" && strings.HasPrefix(targetPath, p) {
				return true
			}
		}
	}
	return false
}

// ---------- 操作者(用户)级判断 ----------

func (s *PermissionService) userHasMenuId(u *model.User, menuId int) bool {
	return s.userHasMenuIdWithSkip(u, menuId, nil)
}

func (s *PermissionService) userHasMenuIdWithSkip(u *model.User, menuId int, skip map[int]bool) bool {
	if skip == nil {
		if isSuper(u) {
			return true
		}
		if p := s.userPermissions(u); p != nil {
			return p.MenuIds[menuId]
		}
		return false
	}
	return s.userHasMenuIdUncachedWithSkip(u, menuId, skip)
}

func (s *PermissionService) userHasMenuIdUncachedWithSkip(u *model.User, menuId int, skip map[int]bool) bool {
	if isSuper(u) { // 超级管理员拥有全部菜单 → SysMenus/AppMenus 自动返回全集
		return true
	}
	for _, r := range s.effectiveRoles(u) {
		if roleSkipped(skip, r.Id) {
			continue
		}
		if roleHasMenuId(r, menuId) && s.creatorAllowsMenu(r, menuId, skip) {
			return true
		}
	}
	return false
}

func (s *PermissionService) userResAreaCovers(u *model.User, areaId int) bool {
	return s.userResAreaCoversWithSkip(u, areaId, nil)
}

func (s *PermissionService) userResAreaCoversWithSkip(u *model.User, areaId int, skip map[int]bool) bool {
	return s.userResAreaCoversUncachedWithSkip(u, areaId, skip)
}

func (s *PermissionService) userResAreaCoversUncachedWithSkip(u *model.User, areaId int, skip map[int]bool) bool {
	if isSuper(u) { // 超级管理员覆盖全部区域资源 → 应用端可见全部
		return true
	}
	for _, r := range s.effectiveRoles(u) {
		if roleSkipped(skip, r.Id) {
			continue
		}
		if s.roleAllowsTree(r.ResourceAreaScopes, treeKindArea, areaId) && s.creatorAllowsResArea(r, areaId, skip) {
			return true
		}
	}
	return false
}

// ---------- 合并:海康式委派(模型 A) ----------
//
// 保存角色时:
//   - 操作者「范围内」的权限 = 以本次提交为准(可增可删);
//   - 操作者「范围外」、角色原有的权限 = 原样保留(编辑者看不到也删不掉)。
// 即  最终 = (提交 ∩ 操作者可授范围) ∪ (原有 \ 操作者可授范围)。
// 这样既防越权(超范围的提交被丢弃),又防误删(看不见的权限被保留)。
// actorId<=0(系统管理员)直接采用提交内容。
// 返回合并后的角色,以及被保留的范围外权限条数。

func intSet(ids []int) map[int]bool {
	m := make(map[int]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// mergeScopes 合并树范围:范围内取提交,范围外保留原有。
func mergeScopes(old, sub []model.DataScope, grant map[int]bool) ([]model.DataScope, int) {
	out := []model.DataScope{}
	seen := map[int]bool{}
	// 范围内以本次提交为准：前端取消勾选就真正删除，新增勾选也可以写入。
	for _, sc := range sub {
		if grant[sc.NodeId] {
			out = append(out, sc)
			seen[sc.NodeId] = true
		}
	}
	preserved := 0
	// 范围外保留旧值：编辑者看不到/无权触碰的授权不能被一次保存误删。
	for _, sc := range old {
		if !grant[sc.NodeId] && !seen[sc.NodeId] {
			out = append(out, sc)
			seen[sc.NodeId] = true
			preserved++
		}
	}
	return out, preserved
}

// MergeDelegated 合并角色基础权限。
// 当前用户只能改自己可授范围内的菜单和树范围;范围外旧权限会保留,避免编辑时误删看不见的权限。
func isUnrestrictedActor(actorId string) bool {
	return actorId == "0"
}

func (s *PermissionService) MergeDelegated(actorId string, old, sub *model.Role) (*model.Role, int) {
	if old == nil {
		old = &model.Role{}
	}
	// 不受限入口用于初始化/维护，直接采用提交内容，不做受控委派裁剪。
	if isUnrestrictedActor(actorId) {
		return sub, 0 // 不受限,直接采用提交
	}
	// 后端重新计算操作者当前可授范围,不能信任前端置灰/隐藏结果。
	g := s.GrantableSet(actorId)
	if g.Unlimited { // 超级管理员作为操作者:可授全部,直接采用提交
		return sub, 0
	}
	menuG, areaG, orgG, resAreaG := intSet(g.MenuIds), intSet(g.AreaIds), intSet(g.OrgIds), intSet(g.ResAreaIds)

	res := &model.Role{Id: sub.Id, Name: sub.Name, Description: sub.Description, CreatedBy: sub.CreatedBy}
	preserved := 0

	// 菜单
	seenM := map[int]bool{}
	// 可授范围内:以本次提交为准,用户取消勾选就真正删除。
	for _, m := range sub.MenuIds {
		if menuG[m] {
			res.MenuIds = append(res.MenuIds, m)
			seenM[m] = true
		}
	}
	// 可授范围外:编辑者本来就看不到/无权改,旧值必须保留,防止低权限编辑误删高权限。
	for _, m := range old.MenuIds {
		if !menuG[m] && !seenM[m] {
			res.MenuIds = append(res.MenuIds, m)
			seenM[m] = true
			preserved++
		}
	}

	// 三类树范围
	var p int
	// AREA=后台安保区域管理范围;ORG=人员组织范围;RES_AREA=应用端业务资源区域范围。
	// 三者都使用相同合并公式:范围内采用提交,范围外保留旧值。
	res.AreaScopes, p = mergeScopes(old.AreaScopes, sub.AreaScopes, areaG)
	preserved += p
	res.OrgScopes, p = mergeScopes(old.OrgScopes, sub.OrgScopes, orgG)
	preserved += p
	res.ResourceAreaScopes, p = mergeScopes(old.ResourceAreaScopes, sub.ResourceAreaScopes, resAreaG)
	preserved += p

	return res, preserved
}

// ---------- 供前端置灰:操作者可授出的范围上限 ----------

// Grantable 是当前用户的可授权上限。
// Unlimited=true 表示超级管理员/不受限,前端可展示全部权限;否则各列表只包含当前用户可授出的 ID。
type Grantable = model.Grantable

// GrantableSet 计算当前用户“能授出去什么”。
// 角色编辑页用它隐藏或置灰超范围权限;保存时也用同一套结果做后端合并兜底。
func (s *PermissionService) GrantableSet(actorId string) *Grantable {
	g := &Grantable{MenuIds: []int{}, MenuCodes: []string{}, AreaIds: []int{}, OrgIds: []int{}, ResAreaIds: []int{}, RoleIds: []int{}}
	// actorId=0 是系统维护入口，前端可以展示全部权限，保存时也不做裁剪。
	if isUnrestrictedActor(actorId) {
		g.Unlimited = true
		return g
	}
	actor := s.User(actorId)
	if actor == nil {
		return g
	}
	if actor.IsSuperuser { // 超级管理员可授出全部权限
		g.Unlimited = true
		return g
	}
	// 菜单、区域、组织、业务资源区域都按“当前最终生效权限”推导，可授权范围不会超过自己实际拥有的范围。
	for _, m := range s.Menus() {
		if s.userHasMenuId(actor, m.Id) {
			g.MenuIds = append(g.MenuIds, m.Id)
			g.MenuCodes = append(g.MenuCodes, m.Code)
		}
	}
	for _, a := range s.Areas() {
		if s.CheckArea(actor, a.Id).Allow {
			g.AreaIds = append(g.AreaIds, a.Id)
		}
		if s.userResAreaCovers(actor, a.Id) {
			g.ResAreaIds = append(g.ResAreaIds, a.Id)
		}
	}
	for _, o := range s.Orgs() {
		if s.CheckOrg(actor, o.Id).Allow {
			g.OrgIds = append(g.OrgIds, o.Id)
		}
	}
	// 可见 + 可分配的角色集:普通用户仅自建角色,超管全部。
	mset, _ := s.ManageableRoles(actorId)
	for _, r := range s.Roles() { // 按角色 id 有序输出,便于前端/截图稳定
		if mset[r.Id] {
			g.RoleIds = append(g.RoleIds, r.Id)
		}
	}
	return g
}

// ManageableRoles 返回操作者可见/可分配的角色集合。
//
//	manageable(actor) = { 自己创建的角色 }
//
// actorId<=0(不受限)或超级管理员 → unlimited=true(可见全部角色)。
func (s *PermissionService) ManageableRoles(actorId string) (set map[int]bool, unlimited bool) {
	set = map[int]bool{}
	if isUnrestrictedActor(actorId) {
		return set, true
	}
	actor := s.User(actorId)
	if actor == nil {
		return set, false
	}
	if actor.IsSuperuser {
		return set, true
	}
	for _, r := range s.Roles() { // 1) 自己创建的角色(模型 A)
		if r.CreatedBy == actorId {
			set[r.Id] = true
		}
	}
	return set, false
}

// OwnedRoles 返回操作者「可编辑/删除」的角色集合 = 仅自己创建的角色(created_by)。
//
// 与 ManageableRoles 当前保持一致:普通用户只能看到、分配、编辑、删除自己创建的角色。
// actorId<=0(不受限)或超级管理员 → unlimited=true(可编辑/删除全部角色)。
func (s *PermissionService) OwnedRoles(actorId string) (set map[int]bool, unlimited bool) {
	set = map[int]bool{}
	if isUnrestrictedActor(actorId) {
		return set, true
	}
	actor := s.User(actorId)
	if actor == nil {
		return set, false
	}
	if actor.IsSuperuser {
		return set, true
	}
	for _, r := range s.Roles() {
		if r.CreatedBy == actorId {
			set[r.Id] = true
		}
	}
	return set, false
}
