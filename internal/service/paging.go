package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/model"
)

// 数据权限的「用」:把用户的树范围(应用域 RES_AREA / 管理域 AREA)翻译成 SQL WHERE 下推,
// 让数据库带着权限做过滤 + 分页(走 area.path 的 idx_path 索引),而不是把全表捞回内存再逐行过滤。
//
// 与「鉴权」(auth.go 的点查:能不能看某个已知节点)互补:
//   - 鉴权        = authorize:已知目标,问"能不能"。O(scope 数),读缓存,微秒级。
//   - 这里(分页) = filter  :未知列表,问"哪一页能看"。必须把 scope 拼进 WHERE,否则退化成全表扫。
//
// 翻译规则(物化路径的红利):
//   - {node, includeChild:true}  → 一整棵子树 = `path LIKE '该节点path%'`(一条 LIKE 顶 N 个子节点)
//   - {node, includeChild:false} → 仅本节点   = `id = 该节点`
//   - 超管 / 持有"根含子树"      → All(不加任何范围过滤)
//   - 无任何范围                 → None(直接空结果,连库都不查)
//
// 应用端树(RES_AREA)与后台管理树(AREA)结构完全一致,仅 scope 来源不同 —— 用 scopePicker 复用同一套核心。

// scopePicker 从角色取哪一类树范围(AreaScopes / ResourceAreaScopes)。
type scopePicker func(*model.Role) []model.DataScope

func pickAreaScopes(r *model.Role) []model.DataScope    { return r.AreaScopes }         // 管理域(安保区域管理)
func pickResAreaScopes(r *model.Role) []model.DataScope { return r.ResourceAreaScopes } // 应用域(资源浏览)

// treeFilter 用户某一类树范围的 SQL 化描述。
type treeFilter struct {
	All       bool     // 看全部(超管 / 根含子树)
	None      bool     // 看不到任何东西
	Prefixes  []string // path LIKE prefix%(含子树授权)
	ExactIds  []int    // id IN (...)(仅本节点授权)
	RootPaths []string // 所有授权根的 path(含子树根 + 仅本节点根),用于判断"是否有更深的授权"(HasChildren)
}

// underPrefix 节点是否落在某含子树授权内(=其子孙都继承可见)。
func (f treeFilter) underPrefix(path string) bool {
	for _, p := range f.Prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// hasDescendantGrant 是否存在"严格在该节点之下"的授权根(=该节点有可见的子孙)。
func (f treeFilter) hasDescendantGrant(path string) bool {
	for _, rp := range f.RootPaths {
		if len(rp) > len(path) && strings.HasPrefix(rp, path) {
			return true
		}
	}
	return false
}

// covers 在内存里判断某节点是否落在范围内(给分页结果逐行标 accessible 用,免二次查库)。
// 与 auth.go 的 checkTreeScope 等价:精确命中 ∪ 含子树前缀。
func (f treeFilter) covers(path string, id int) bool {
	if f.All {
		return true
	}
	for _, p := range f.Prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, e := range f.ExactIds {
		if e == id {
			return true
		}
	}
	return false
}

// treeScopeFilter 从内存缓存计算用户某类树范围的过滤(几条 scope 根,便宜)。
func (s *Store) treeScopeFilter(u *model.User, pick scopePicker) treeFilter {
	if isSuper(u) {
		return treeFilter{All: true}
	}
	f := treeFilter{}
	seenPrefix := map[string]bool{}
	seenExact := map[int]bool{}
	for _, r := range s.effectiveRoles(u) {
		for _, sc := range pick(r) {
			a := s.AreaById(sc.NodeId)
			if a == nil || a.Path == "" {
				continue // 悬挂引用
			}
			if sc.IncludeChild {
				if a.ParentId == 0 { // 根含子树 = 拥有现在及将来全部区域
					return treeFilter{All: true}
				}
				if !seenPrefix[a.Path] {
					seenPrefix[a.Path] = true
					f.Prefixes = append(f.Prefixes, a.Path)
					f.RootPaths = append(f.RootPaths, a.Path)
				}
			} else if !seenExact[a.Id] {
				seenExact[a.Id] = true
				f.ExactIds = append(f.ExactIds, a.Id)
				f.RootPaths = append(f.RootPaths, a.Path)
			}
		}
	}
	if len(f.Prefixes) == 0 && len(f.ExactIds) == 0 {
		f.None = true
	}
	return f
}

// treeNavAncestors 计算"导航祖先"id 集合:自己无权、但其子孙在范围内的区域。
// 这些节点要在树里显示(否则用户点不进去看自己有权的深层节点)。
// 它正好 = 各 scope 根 path 上的所有 id(path 形如 /1/3/4/,段就是祖先 id 链),小而可枚举。
func (s *Store) treeNavAncestors(u *model.User, pick scopePicker) map[int]bool {
	out := map[int]bool{}
	if isSuper(u) {
		return out // 全可见,无需导航补集
	}
	for _, r := range s.effectiveRoles(u) {
		for _, sc := range pick(r) {
			a := s.AreaById(sc.NodeId)
			if a == nil {
				continue
			}
			for _, seg := range strings.Split(strings.Trim(a.Path, "/"), "/") {
				if seg == "" {
					continue
				}
				if id, err := strconv.Atoi(seg); err == nil {
					out[id] = true
				}
			}
		}
	}
	return out
}

// areaScopeWhere 把范围过滤拼成 (sql, args)。alias 为 area 表别名(""=不加前缀)。
// 返回空 sql 表示"无范围过滤"(All);调用方需先短路 None。
func areaScopeWhere(alias string, f treeFilter) (string, []interface{}) {
	if f.All {
		return "", nil
	}
	col := func(c string) string {
		if alias == "" {
			return c
		}
		return alias + "." + c
	}
	parts := []string{}
	args := []interface{}{}
	for _, p := range f.Prefixes {
		parts = append(parts, col("path")+" LIKE ?")
		args = append(args, p+"%")
	}
	if len(f.ExactIds) > 0 {
		parts = append(parts, col("id")+" IN (?)")
		args = append(args, f.ExactIds)
	}
	if len(parts) == 0 {
		return "1=0", nil // 防御:None 应已被短路
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// ---------- 树:按层懒加载 + 分页 ----------

// AreaNode 懒加载树的一个节点。
type AreaNode struct {
	Id          int           `json:"id"`
	ParentId    int           `json:"parentId"`
	Name        string        `json:"name"`
	Accessible  bool          `json:"accessible"`           // false=仅导航祖先(点进去无权限)
	HasChildren bool          `json:"hasChildren"`          // 是否有"可见的"子节点(决定是否显示展开箭头)
	Ancestors   []AncestorRef `json:"ancestors,omitempty"`  // 祖先链(root..parent),仅搜索结果用:前端据此拼局部树展示
}

// AncestorRef 祖先节点引用(搜索结果按树展示用:把匹配节点的 root..parent 链回传给前端拼局部树,对齐海康搜索)。
type AncestorRef struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

// visibilityWhere 把"可见性"(范围内 accessible 或 导航祖先)拼成 SQL 片段。
// 返回 (sql, args, anyVisible):All=>("",nil,true) 不加过滤;啥也看不到=>("",nil,false)。
func (s *Store) visibilityWhere(f treeFilter, nav map[int]bool) (string, []interface{}, bool) {
	if f.All {
		return "", nil, true
	}
	parts, args := []string{}, []interface{}{}
	if !f.None {
		if accSQL, accArgs := areaScopeWhere("", f); accSQL != "" {
			parts = append(parts, accSQL)
			args = append(args, accArgs...)
		}
	}
	if len(nav) > 0 {
		parts = append(parts, "id IN (?)")
		args = append(args, mapKeys(nav))
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, true
}

// areaAncestors 把物化路径转成祖先链(root..parent,不含自身),如 /1/3/6/ -> [{1,根区域},{3,园区A}]。
// 供搜索结果按树展示:前端用这条链把散落的匹配项拼回"局部树"(对齐海康搜索的树状结果)。
func (s *Store) areaAncestors(path string) []AncestorRef {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	out := []AncestorRef{}
	for i, seg := range segs {
		if i == len(segs)-1 || seg == "" { // 末段为自身,跳过
			continue
		}
		if id, err := strconv.Atoi(seg); err == nil {
			if a := s.AreaById(id); a != nil {
				out = append(out, AncestorRef{Id: a.Id, Name: a.Name})
			}
		}
	}
	return out
}

// PagedAreas 一层(某 parentId 下)的可见子节点分页结果。
type PagedAreas struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

// AreaChildren 应用端(RES_AREA):某节点下"可见的"直接子区域,分页。
func (s *Store) AreaChildren(ctx context.Context, userId, parentId, page, size int) *PagedAreas {
	return s.areaChildrenBy(ctx, userId, parentId, page, size, pickResAreaScopes)
}

// ManageAreaChildren 后台管理域(AREA):某节点下"可管理/可见的"直接子区域,分页。
func (s *Store) ManageAreaChildren(ctx context.Context, userId, parentId, page, size int) *PagedAreas {
	return s.areaChildrenBy(ctx, userId, parentId, page, size, pickAreaScopes)
}

// areaChildrenBy 通用核心:可见 = 范围内(accessible)或导航祖先;过滤 + 分页全部下推 SQL。
func (s *Store) areaChildrenBy(ctx context.Context, userId, parentId, page, size int, pick scopePicker) *PagedAreas {
	page, size = normPage(page, size)
	out := &PagedAreas{Items: []AreaNode{}, Page: page, Size: size}
	u := s.User(userId)
	if u == nil {
		return out
	}
	f := s.treeScopeFilter(u, pick)
	nav := s.treeNavAncestors(u, pick)

	m := g.Model("area").Ctx(ctx).Where("parent_id", parentId)
	visSQL, visArgs, anyVisible := s.visibilityWhere(f, nav)
	if !anyVisible {
		return out // 啥也看不到
	}
	if visSQL != "" {
		m = m.Where(visSQL, visArgs...)
	}

	total, _ := m.Count()
	out.Total = total
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err := m.Fields("id,parent_id,name,path").Page(page, size).Order("sort asc,id asc").Scan(&rows); err != nil {
		return out
	}

	// 一次查出本页中哪些节点"有子节点",用于 accessible 节点的 HasChildren
	pageIds := make([]int, 0, len(rows))
	for _, r := range rows {
		pageIds = append(pageIds, r.Id)
	}
	childParents := map[int]bool{}
	if len(pageIds) > 0 {
		var pps []struct{ ParentId int }
		_ = g.Model("area").Ctx(ctx).Fields("DISTINCT parent_id").Where("parent_id IN (?)", pageIds).Scan(&pps)
		for _, p := range pps {
			childParents[p.ParentId] = true
		}
	}

	for _, r := range rows {
		acc := f.covers(r.Path, r.Id)
		// HasChildren = "是否有可见的子节点"(决定展开箭头),分三种情形:
		//   - All / 落在含子树授权内:子孙都继承可见 → 有子行即可展开;
		//   - 仅本节点授权 或 导航祖先:子孙不自动可见 → 仅当存在更深的授权根才可展开。
		var hasCh bool
		switch {
		case f.All, f.underPrefix(r.Path):
			hasCh = childParents[r.Id]
		default:
			hasCh = f.hasDescendantGrant(r.Path)
		}
		out.Items = append(out.Items, AreaNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, Accessible: acc, HasChildren: hasCh})
	}
	return out
}

// searchLimit 搜索最多返回的匹配条数(对齐真实海康:超过则截断,前端提示"搜索结果过多,仅展示前 500 条")。
const searchLimit = 500

// SearchAreas 按名称搜索区域(懒加载树的"搜索框"):全树 name LIKE %q%,叠加用户可见性过滤。
// scope="manage" 用 AREA(管理域),否则 RES_AREA(应用域)。
// 对齐海康:最多返回前 searchLimit(500)条(Total 仍为真实总数,供前端判断是否被截断);
// 每条匹配回传其祖先链(Ancestors,root..parent),前端据此拼出"局部树"展示(匹配项高亮),而非平铺列表。
func (s *Store) SearchAreas(ctx context.Context, userId int, q, scope string, page, size int) *PagedAreas {
	out := &PagedAreas{Items: []AreaNode{}, Page: 1, Size: searchLimit}
	u := s.User(userId)
	q = strings.TrimSpace(q)
	if u == nil || q == "" {
		return out
	}
	pick := pickResAreaScopes
	if scope == "manage" {
		pick = pickAreaScopes
	}
	f := s.treeScopeFilter(u, pick)
	nav := s.treeNavAncestors(u, pick)
	m := g.Model("area").Ctx(ctx).Where("name LIKE ?", "%"+q+"%")
	visSQL, visArgs, anyVisible := s.visibilityWhere(f, nav)
	if !anyVisible {
		return out
	}
	if visSQL != "" {
		m = m.Where(visSQL, visArgs...)
	}
	total, _ := m.Count()
	out.Total = total // 真实总数;前端用 Total>len(Items) 判断是否被截断(展示"仅前 500 条"提示)
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err := m.Fields("id,parent_id,name,path").Limit(searchLimit).Order("name asc,id asc").Scan(&rows); err != nil {
		return out
	}
	for _, r := range rows {
		out.Items = append(out.Items, AreaNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, Accessible: f.covers(r.Path, r.Id), Ancestors: s.areaAncestors(r.Path)})
	}
	return out
}

// ---------- 角色配置树:按层惰性加载(显式「包含子节点」,整层一次返回不分页) ----------
//
// 与应用端/后台树(AreaChildren)不同:这里按「操作者可授范围」(委派)过滤,而非登录用户的数据范围;
// 且整层一次返回(不分页)——因为角色树的勾选判断(子树覆盖/继承)需要同层兄弟节点全部在手,分页会切断判断依据。

// RoleTreeNode 角色配置区域树的一个节点。
type RoleTreeNode struct {
	Id          int    `json:"id"`
	ParentId    int    `json:"parentId"`
	Name        string `json:"name"`
	HasChildren bool   `json:"hasChildren"` // 是否有子区域(决定展开箭头)
	CanCheck    bool   `json:"canCheck"`    // 操作者是否可授该节点(false=仅结构展示,不给勾选框)
}

// roleTreeGrantable 操作者在区域树某域(kind=area 管理域 / resarea 应用域)的可授节点集 + 其 path。
// actorId<=0 或超管 ⇒ unlimited(可授全部);否则只遍历区域(不碰菜单/资源),比 GrantableSet 轻。
func (s *Store) roleTreeGrantable(actorId int, kind string) (set map[int]bool, paths []string, unlimited bool) {
	set = map[int]bool{}
	if actorId <= 0 {
		return set, nil, true
	}
	actor := s.User(actorId)
	if actor == nil {
		return set, nil, false
	}
	if actor.IsSuperuser {
		return set, nil, true
	}
	for _, a := range s.Areas() {
		ok := false
		if kind == "resarea" {
			ok = s.userResAreaCovers(actor, a.Id)
		} else {
			ok = s.CheckArea(actor, a.Id).Allow
		}
		if ok {
			set[a.Id] = true
			if a.Path != "" {
				paths = append(paths, a.Path)
			}
		}
	}
	return set, paths, false
}

// RoleAreaChildren 角色配置树:父节点下「整一层」可见子区域(不分页),带 canCheck/hasChildren。
// 可见 = 操作者可授(canCheck)或其子孙中有可授节点(仅作结构展示)。kind=area|resarea 决定可授范围来源。
func (s *Store) RoleAreaChildren(ctx context.Context, actorId, parentId int, kind string) []RoleTreeNode {
	out := []RoleTreeNode{}
	set, paths, unlimited := s.roleTreeGrantable(actorId, kind)
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err := g.Model("area").Ctx(ctx).Where("parent_id", parentId).
		Fields("id,parent_id,name,path").Order("sort asc,id asc").Scan(&rows); err != nil {
		return out
	}
	ids := make([]int, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.Id)
	}
	childParents := map[int]bool{}
	if len(ids) > 0 {
		var pps []struct{ ParentId int }
		_ = g.Model("area").Ctx(ctx).Fields("DISTINCT parent_id").Where("parent_id IN (?)", ids).Scan(&pps)
		for _, p := range pps {
			childParents[p.ParentId] = true
		}
	}
	for _, r := range rows {
		canCheck := unlimited || set[r.Id]
		if !canCheck && !hasGrantPrefix(r.Path, paths) {
			continue // 自身不可授、子孙也无可授 → 隐藏(对齐海康:看不到操作者无权的部分)
		}
		out = append(out, RoleTreeNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, HasChildren: childParents[r.Id], CanCheck: canCheck})
	}
	return out
}

// hasGrantPrefix 是否存在「严格在 path 之下」的可授节点(=该节点有可授子孙,需作结构展示)。
func hasGrantPrefix(path string, grantPaths []string) bool {
	for _, gp := range grantPaths {
		if len(gp) > len(path) && strings.HasPrefix(gp, path) {
			return true
		}
	}
	return false
}

// ---------- 资源:分页 + 权限下推(应用域 RES_AREA) ----------

// AreaResourcesPage 某区域(含子树)下用户有权看的资源,分页。
type AreaResourcesPage struct {
	Accessible bool           `json:"accessible"` // false=该区域仅导航,无资源权限
	AreaName   string         `json:"areaName"`
	Resources  []ResourceView `json:"resources"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Size       int            `json:"size"`
}

// AreaResourcesPaged 点击某区域:列出其子树内、用户范围内、非零权限的资源,分页。
// 范围过滤(scope→WHERE)+ 子树前缀 + 隐藏零权限资源,全部下推 SQL;再对本页 ~size 条逐个点查操作。
func (s *Store) AreaResourcesPaged(ctx context.Context, userId, areaId, page, size int) *AreaResourcesPage {
	page, size = normPage(page, size)
	out := &AreaResourcesPage{Resources: []ResourceView{}, Page: page, Size: size}
	u := s.User(userId)
	if u == nil {
		return out
	}
	area := s.AreaById(areaId)
	if area == nil {
		return out
	}
	out.AreaName = area.Name
	if !s.userResAreaCovers(u, areaId) { // 沿用原语义:仅导航祖先 → 不可访问
		out.Accessible = false
		return out
	}
	out.Accessible = true

	f := s.treeScopeFilter(u, pickResAreaScopes)
	m := g.Model("resource").Ctx(ctx).
		LeftJoin("area", "area.id = resource.area_id").
		Where("area.path LIKE ?", area.Path+"%") // 限定 areaId 子树
	if accSQL, accArgs := areaScopeWhere("area", f); accSQL != "" {
		m = m.Where(accSQL, accArgs...) // 叠加用户 RES_AREA 范围
	}
	if hidden := s.hiddenResourceIds(u); len(hidden) > 0 {
		m = m.Where("resource.id NOT IN (?)", hidden) // 资源级可见:零权限资源隐藏
	}

	total, _ := m.Count()
	out.Total = total
	var rows []struct {
		Id     int
		AreaId int
		Name   string
	}
	if err := m.Fields("resource.id,resource.area_id,resource.name").Page(page, size).Order("resource.id asc").Scan(&rows); err != nil {
		return out
	}
	acts := s.Actions()
	for _, row := range rows {
		rv := ResourceView{Id: row.Id, Name: row.Name, Area: s.nodeName("area", row.AreaId)}
		for _, act := range acts {
			rv.Actions = append(rv.Actions, ActionAllow{Code: act.Code, Name: act.Name, Allowed: s.CheckResource(u, row.Id, act.Code).Allow})
		}
		out.Resources = append(out.Resources, rv)
	}
	return out
}

// hiddenResourceIds 用户"零权限被隐藏"的资源 id(资源级可见 L2)。
// 只可能发生在"有精细配置却净授 0 操作"的资源上,故只遍历有 override 的资源(小集合),不扫全表。
func (s *Store) hiddenResourceIds(u *model.User) []int {
	if isSuper(u) {
		return nil
	}
	cand := map[int]bool{}
	for _, r := range s.effectiveRoles(u) {
		for _, id := range r.ResourceOverrides {
			cand[id] = true
		}
		for _, ra := range r.ResourceActions {
			cand[ra.ResourceId] = true
		}
	}
	hidden := []int{}
	for id := range cand {
		any := false
		for _, act := range s.Actions() {
			if s.CheckResource(u, id, act.Code).Allow {
				any = true
				break
			}
		}
		if !any {
			hidden = append(hidden, id)
		}
	}
	return hidden
}

// ---------- 小工具 ----------

func normPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 500 {
		size = 100
	}
	return page, size
}

func mapKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
