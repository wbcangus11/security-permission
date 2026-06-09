package service

import (
	"strconv"
	"strings"

	"security-permission/internal/model"
)

// 受控委派(二次授权)—— 模型 A:写时校验,不级联。
//
// 规则:保存角色时,新角色的权限必须 ⊆ 操作者(创建人)的有效权限。
// 校验通过后子角色权限独立存储;之后操作者权限变化不影响已建角色。
// actorId<=0 视为系统管理员/不受限。

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
func (s *Store) roleAllowsTree(scopes []model.DataScope, kind string, nodeId int) bool {
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

func (s *Store) userHasMenuId(u *model.User, menuId int) bool {
	if isSuper(u) { // 超级管理员拥有全部菜单 → SysMenus/AppMenus 自动返回全集
		return true
	}
	for _, r := range s.effectiveRoles(u) {
		if roleHasMenuId(r, menuId) {
			return true
		}
	}
	return false
}

func (s *Store) userResAreaCovers(u *model.User, areaId int) bool {
	if isSuper(u) { // 超级管理员覆盖全部区域资源 → 应用端可见全部
		return true
	}
	for _, r := range s.effectiveRoles(u) {
		if s.roleAllowsTree(r.ResourceAreaScopes, "area", areaId) {
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

func raKey(resId int, code string) string { return strconv.Itoa(resId) + ":" + code }

// mergeScopes 合并树范围:范围内取提交,范围外保留原有。
func mergeScopes(old, sub []model.DataScope, grant map[int]bool) ([]model.DataScope, int) {
	out := []model.DataScope{}
	seen := map[int]bool{}
	for _, sc := range sub {
		if grant[sc.NodeId] {
			out = append(out, sc)
			seen[sc.NodeId] = true
		}
	}
	preserved := 0
	for _, sc := range old {
		if !grant[sc.NodeId] && !seen[sc.NodeId] {
			out = append(out, sc)
			seen[sc.NodeId] = true
			preserved++
		}
	}
	return out, preserved
}

func (s *Store) MergeDelegated(actorId int, old, sub *model.Role) (*model.Role, int) {
	if old == nil {
		old = &model.Role{}
	}
	if actorId <= 0 {
		return sub, 0 // 不受限,直接采用提交
	}
	g := s.GrantableSet(actorId)
	if g.Unlimited { // 超级管理员作为操作者:可授全部,直接采用提交
		return sub, 0
	}
	menuG, areaG, orgG, resAreaG, roleG := intSet(g.MenuIds), intSet(g.AreaIds), intSet(g.OrgIds), intSet(g.ResAreaIds), intSet(g.RoleIds)
	raG := map[string]bool{}
	resOvrG := map[int]bool{} // 可精细配置的资源 = 操作者对其至少有一个可授操作
	for _, ra := range g.ResourceActions {
		raG[raKey(ra.ResourceId, ra.ActionCode)] = true
		resOvrG[ra.ResourceId] = true
	}

	res := &model.Role{Id: sub.Id, Name: sub.Name, Description: sub.Description, CreatedBy: sub.CreatedBy}
	preserved := 0

	// 菜单
	seenM := map[int]bool{}
	for _, m := range sub.MenuIds {
		if menuG[m] {
			res.MenuIds = append(res.MenuIds, m)
			seenM[m] = true
		}
	}
	for _, m := range old.MenuIds {
		if !menuG[m] && !seenM[m] {
			res.MenuIds = append(res.MenuIds, m)
			seenM[m] = true
			preserved++
		}
	}

	// 三类树范围
	var p int
	res.AreaScopes, p = mergeScopes(old.AreaScopes, sub.AreaScopes, areaG)
	preserved += p
	res.OrgScopes, p = mergeScopes(old.OrgScopes, sub.OrgScopes, orgG)
	preserved += p
	res.ResourceAreaScopes, p = mergeScopes(old.ResourceAreaScopes, sub.ResourceAreaScopes, resAreaG)
	preserved += p
	res.RoleScopes, p = mergeScopes(old.RoleScopes, sub.RoleScopes, roleG)
	preserved += p

	// 资源操作
	seenRA := map[string]bool{}
	for _, ra := range sub.ResourceActions {
		if raG[raKey(ra.ResourceId, ra.ActionCode)] {
			res.ResourceActions = append(res.ResourceActions, ra)
			seenRA[raKey(ra.ResourceId, ra.ActionCode)] = true
		}
	}
	for _, ra := range old.ResourceActions {
		k := raKey(ra.ResourceId, ra.ActionCode)
		if !raG[k] && !seenRA[k] {
			res.ResourceActions = append(res.ResourceActions, ra)
			seenRA[k] = true
			preserved++
		}
	}

	// 资源精细模式标记(同菜单逻辑:范围内取提交,范围外保留原有)
	seenOvr := map[int]bool{}
	for _, id := range sub.ResourceOverrides {
		if resOvrG[id] {
			res.ResourceOverrides = append(res.ResourceOverrides, id)
			seenOvr[id] = true
		}
	}
	for _, id := range old.ResourceOverrides {
		if !resOvrG[id] && !seenOvr[id] {
			res.ResourceOverrides = append(res.ResourceOverrides, id)
			seenOvr[id] = true
			preserved++
		}
	}
	return res, preserved
}

// ---------- 供前端置灰:操作者可授出的范围上限 ----------

type Grantable struct {
	Unlimited       bool                   `json:"unlimited"`
	MenuIds         []int                  `json:"menuIds"`
	AreaIds         []int                  `json:"areaIds"`
	OrgIds          []int                  `json:"orgIds"`
	ResAreaIds      []int                  `json:"resAreaIds"`
	ResourceActions []model.ResourceAction `json:"resourceActions"`
	RoleIds         []int                  `json:"roleIds"` // 委派维度:可管理(可编辑/删除/再委派)的角色集
}

func (s *Store) GrantableSet(actorId int) *Grantable {
	g := &Grantable{MenuIds: []int{}, AreaIds: []int{}, OrgIds: []int{}, ResAreaIds: []int{}, ResourceActions: []model.ResourceAction{}, RoleIds: []int{}}
	if actorId <= 0 {
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
	for _, m := range s.Menus() {
		if s.userHasMenuId(actor, m.Id) {
			g.MenuIds = append(g.MenuIds, m.Id)
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
	for _, res := range s.Resources() {
		for _, act := range s.actions {
			if s.CheckResource(actor, res.Id, act.Code).Allow {
				g.ResourceActions = append(g.ResourceActions, model.ResourceAction{ResourceId: res.Id, ActionCode: act.Code})
			}
		}
	}
	// 委派维度:可管理角色集 = 自建角色 ∪ 自身角色的「角色范围」并集(见 ManageableRoles)
	mset, _ := s.ManageableRoles(actorId)
	for _, r := range s.Roles() { // 按角色 id 有序输出,便于前端/截图稳定
		if mset[r.Id] {
			g.RoleIds = append(g.RoleIds, r.Id)
		}
	}
	return g
}

// ManageableRoles 返回操作者可管理(可编辑/删除/再委派)的角色集合。
//
//	manageable(actor) = { 自己创建的角色 } ∪ { actor 各有效角色的「角色范围」并集 }
//
// actorId<=0(不受限)或超级管理员 → unlimited=true(可管理全部角色)。单层不级联,与模型 A 自洽。
func (s *Store) ManageableRoles(actorId int) (set map[int]bool, unlimited bool) {
	set = map[int]bool{}
	if actorId <= 0 {
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
	for _, r := range s.effectiveRoles(actor) { // 2) 显式角色范围(模型 B)
		for _, sc := range r.RoleScopes {
			set[sc.NodeId] = true
		}
	}
	return set, false
}
