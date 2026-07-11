package permission

import (
	"context"
	"strconv"
	"strings"

	"security-permission/internal/dao"
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

func (s *PermissionService) addFilterScope(filter *treeFilter, scope model.DataScope) {
	area := s.AreaById(scope.NodeId)
	if area == nil || area.Path == "" {
		return
	}
	if scope.IncludeChild {
		for _, prefix := range filter.Prefixes {
			if prefix == area.Path {
				return
			}
		}
		filter.Prefixes = append(filter.Prefixes, area.Path)
	} else {
		for _, id := range filter.ExactIds {
			if id == area.Id {
				return
			}
		}
		filter.ExactIds = append(filter.ExactIds, area.Id)
	}
	filter.RootPaths = append(filter.RootPaths, area.Path)
}

func (s *PermissionService) roleTreeFilter(role *model.Role, pick scopePicker) treeFilter {
	filter := treeFilter{}
	for _, scope := range pick(role) {
		s.addFilterScope(&filter, scope)
	}
	filter.None = len(filter.Prefixes) == 0 && len(filter.ExactIds) == 0
	return filter
}

func (s *PermissionService) unionTreeFilters(left, right treeFilter) treeFilter {
	if left.All || right.All {
		return treeFilter{All: true}
	}
	out := treeFilter{}
	for _, source := range []treeFilter{left, right} {
		for _, prefix := range source.Prefixes {
			s.addFilterScope(&out, model.DataScope{NodeId: pathLastID(prefix), IncludeChild: true})
		}
		for _, id := range source.ExactIds {
			s.addFilterScope(&out, model.DataScope{NodeId: id})
		}
	}
	out.None = len(out.Prefixes) == 0 && len(out.ExactIds) == 0
	return out
}

func pathLastID(path string) int {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 0 {
		return 0
	}
	id, _ := strconv.Atoi(segments[len(segments)-1])
	return id
}

func (s *PermissionService) intersectTreeFilters(left, right treeFilter) treeFilter {
	if left.None || right.None {
		return treeFilter{None: true}
	}
	if left.All {
		return right
	}
	if right.All {
		return left
	}
	out := treeFilter{}
	for _, id := range left.ExactIds {
		if area := s.AreaById(id); area != nil && right.covers(area.Path, id) {
			s.addFilterScope(&out, model.DataScope{NodeId: id})
		}
	}
	for _, id := range right.ExactIds {
		if area := s.AreaById(id); area != nil && left.covers(area.Path, id) {
			s.addFilterScope(&out, model.DataScope{NodeId: id})
		}
	}
	for _, leftPrefix := range left.Prefixes {
		for _, rightPrefix := range right.Prefixes {
			switch {
			case strings.HasPrefix(leftPrefix, rightPrefix):
				s.addFilterScope(&out, model.DataScope{NodeId: pathLastID(leftPrefix), IncludeChild: true})
			case strings.HasPrefix(rightPrefix, leftPrefix):
				s.addFilterScope(&out, model.DataScope{NodeId: pathLastID(rightPrefix), IncludeChild: true})
			}
		}
	}
	out.None = len(out.Prefixes) == 0 && len(out.ExactIds) == 0
	return out
}

// treeScopeFilter computes compact effective scopes. Delegated roles are
// intersected with their creator's current effective scopes without expanding
// the complete area tree.
func (s *PermissionService) treeScopeFilter(u *model.User, kind string) treeFilter {
	return s.treeScopeFilterWithSkip(u, kind, nil)
}

func (s *PermissionService) treeScopeFilterWithSkip(u *model.User, kind string, skip map[int]bool) treeFilter {
	if isSuper(u) {
		return treeFilter{All: true}
	}
	pick := pickAreaScopes
	if kind == treeKindResArea {
		pick = pickResAreaScopes
	}
	result := treeFilter{None: true}
	for _, role := range s.effectiveRoles(u) {
		if roleSkipped(skip, role.Id) {
			continue
		}
		roleFilter := s.roleTreeFilter(role, pick)
		if roleFilter.None {
			continue
		}
		if !s.delegatedRoleUncapped(role) {
			creator := s.creatorByRole(role)
			if creator == nil {
				continue
			}
			creatorFilter := s.treeScopeFilterWithSkip(creator, kind, withSkippedRole(skip, role.Id))
			roleFilter = s.intersectTreeFilters(roleFilter, creatorFilter)
		}
		result = s.unionTreeFilters(result, roleFilter)
	}
	return result
}

// treeNavAncestors 计算"导航祖先"id 集合:自己无权、但其子孙在范围内的区域。
// 这些节点要在树里显示(否则用户点不进去看自己有权的深层节点)。
// 它正好 = 各 scope 根 path 上的所有 id(path 形如 /1/3/4/,段就是祖先 id 链),小而可枚举。
func (s *PermissionService) treeNavAncestors(u *model.User, kind string) map[int]bool {
	out := map[int]bool{}
	filter := s.treeScopeFilter(u, kind)
	if filter.All || filter.None {
		return out // 全可见,无需导航补集
	}
	for _, path := range filter.RootPaths {
		for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
			if id, err := strconv.Atoi(seg); err == nil {
				out[id] = true
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
		return sqlAlwaysFalse, nil // 防御:None 应已被短路
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// ---------- 树:按层懒加载 + 分页 ----------

// visibilityWhere 把"可见性"(范围内 accessible 或 导航祖先)拼成 SQL 片段。
// 返回 (sql, args, anyVisible):All=>("",nil,true) 不加过滤;啥也看不到=>("",nil,false)。
func (s *ViewService) visibilityWhere(f treeFilter, nav map[int]bool) (string, []interface{}, bool) {
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
func (s *ViewService) areaAncestors(path string) []model.AncestorRef {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	out := []model.AncestorRef{}
	for i, seg := range segs {
		if i == len(segs)-1 || seg == "" { // 末段为自身,跳过
			continue
		}
		if id, err := strconv.Atoi(seg); err == nil {
			if a := s.AreaById(id); a != nil {
				out = append(out, model.AncestorRef{Id: a.Id, Name: a.Name})
			}
		}
	}
	return out
}

// AreaChildren 应用端(RES_AREA):某节点下"可见的"直接子区域,分页。
func (s *ViewService) AreaChildren(ctx context.Context, userId string, parentId, page, size int) (*model.PagedAreas, error) {
	return s.areaChildrenBy(ctx, userId, parentId, page, size, treeKindResArea)
}

// ManageAreaChildren 后台管理域(AREA):某节点下"可管理/可见的"直接子区域,分页。
func (s *ViewService) ManageAreaChildren(ctx context.Context, userId string, parentId, page, size int) (*model.PagedAreas, error) {
	return s.areaChildrenBy(ctx, userId, parentId, page, size, treeKindArea)
}

// areaChildrenBy 通用核心:可见 = 范围内(accessible)或导航祖先;过滤 + 分页全部下推 SQL。
func (s *ViewService) areaChildrenBy(ctx context.Context, userId string, parentId, page, size int, kind string) (*model.PagedAreas, error) {
	page, size = normPage(page, size)
	out := &model.PagedAreas{Items: []model.AreaNode{}, Page: page, Size: size}
	u := s.User(userId)
	if u == nil {
		return out, nil
	}
	f := s.treeScopeFilter(u, kind)
	nav := s.treeNavAncestors(u, kind)

	m := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, parentId)
	// 可见节点 = 自己可访问(accessible) + 为了通往深层授权节点必须展示的导航祖先。
	// 这一步拼到 SQL 里,避免先取出整层/整树再在内存过滤。
	visSQL, visArgs, anyVisible := s.visibilityWhere(f, nav)
	if !anyVisible {
		return out, nil // 啥也看不到
	}
	if visSQL != "" {
		m = m.Where(visSQL, visArgs...)
	}

	total, err := m.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err = m.Fields("id,parent_id,name,path").Page(page, size).Order("sort asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}

	// 一次查出本页中哪些节点"有子节点",用于 accessible 节点的 HasChildren
	pageIds := make([]int, 0, len(rows))
	for _, r := range rows {
		pageIds = append(pageIds, r.Id)
	}
	childParents := map[int]bool{}
	if len(pageIds) > 0 {
		var pps []struct{ ParentId int }
		if err = dao.Area.Ctx(ctx).Fields("DISTINCT parent_id").Where("parent_id IN (?)", pageIds).Scan(&pps); err != nil {
			return nil, err
		}
		for _, p := range pps {
			childParents[p.ParentId] = true
		}
	}

	for _, r := range rows {
		// accessible=false 不是“隐藏”,而是“仅用于导航”:前端显示为灰色,可展开但点击详情无权限。
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
		out.Items = append(out.Items, model.AreaNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, Accessible: acc, HasChildren: hasCh})
	}
	return out, nil
}

// searchLimit 搜索最多返回的匹配条数(对齐真实海康:超过则截断,前端提示"搜索结果过多,仅展示前 500 条")。
// SearchAreas 按名称搜索区域(懒加载树的"搜索框"):全树 name LIKE %q%,叠加用户可见性过滤。
// scope="manage" 用 AREA(管理域),否则 RES_AREA(应用域)。
// 对齐海康:最多返回前 searchLimit(500)条(Total 仍为真实总数,供前端判断是否被截断);
// 每条匹配回传其祖先链(Ancestors,root..parent),前端据此拼出"局部树"展示(匹配项高亮),而非平铺列表。
func (s *ViewService) SearchAreas(ctx context.Context, userId string, q, scope string, page, size int) (*model.PagedAreas, error) {
	out := &model.PagedAreas{Items: []model.AreaNode{}, Page: 1, Size: searchLimit}
	u := s.User(userId)
	q = strings.TrimSpace(q)
	if u == nil || q == "" {
		return out, nil
	}
	kind := treeKindResArea
	if scope == areaSearchScopeManage {
		kind = treeKindArea
	}
	f := s.treeScopeFilter(u, kind)
	nav := s.treeNavAncestors(u, kind)
	m := dao.Area.Ctx(ctx).Where("name LIKE ?", "%"+q+"%")
	// 搜索也必须叠加同一套可见性过滤。否则用户能通过搜索发现无权区域名称。
	visSQL, visArgs, anyVisible := s.visibilityWhere(f, nav)
	if !anyVisible {
		return out, nil
	}
	if visSQL != "" {
		m = m.Where(visSQL, visArgs...)
	}
	total, err := m.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total // 真实总数;前端用 Total>len(Items) 判断是否被截断(展示"仅前 500 条"提示)
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err = m.Fields("id,parent_id,name,path").Limit(searchLimit).Order("name asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		// 回传祖先链,让前端按“局部树”展示搜索结果,对齐海康;不是简单平铺列表。
		out.Items = append(out.Items, model.AreaNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, Accessible: f.covers(r.Path, r.Id), Ancestors: s.areaAncestors(r.Path)})
	}
	return out, nil
}

// ---------- 角色配置树:按层惰性加载(显式「包含子节点」,整层一次返回不分页) ----------
//
// 与应用端/后台树(AreaChildren)不同:这里按「操作者可授范围」(委派)过滤,而非登录用户的数据范围;
// 且整层一次返回(不分页)——因为角色树的勾选判断(子树覆盖/继承)需要同层兄弟节点全部在手,分页会切断判断依据。

// roleTreeGrantable returns compact effective scopes for the role editor.
func (s *PermissionService) roleTreeGrantable(actorId string, kind string) treeFilter {
	actor := s.User(actorId)
	if actor == nil {
		return treeFilter{None: true}
	}
	return s.treeScopeFilter(actor, kind)
}

// RoleAreaChildren 角色配置树:父节点下「整一层」可见子区域(不分页),带 canCheck/hasChildren。
// 可见 = 操作者可授(canCheck)或其子孙中有可授节点(仅作结构展示)。kind=area|resarea 决定可授范围来源。
func (s *PermissionService) RoleAreaChildren(ctx context.Context, actorId string, parentId int, kind string) ([]model.RoleTreeNode, error) {
	out := []model.RoleTreeNode{}
	filter := s.roleTreeGrantable(actorId, kind)
	var rows []struct {
		Id       int
		ParentId int
		Name     string
		Path     string
	}
	if err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, parentId).
		Fields("id,parent_id,name,path").Order("sort asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.Id)
	}
	childParents := map[int]bool{}
	if len(ids) > 0 {
		var pps []struct{ ParentId int }
		if err := dao.Area.Ctx(ctx).Fields("DISTINCT parent_id").Where("parent_id IN (?)", ids).Scan(&pps); err != nil {
			return nil, err
		}
		for _, p := range pps {
			childParents[p.ParentId] = true
		}
	}
	for _, r := range rows {
		canCheck := filter.covers(r.Path, r.Id)
		if !canCheck && !filter.hasDescendantGrant(r.Path) {
			continue // 自身不可授、子孙也无可授 → 隐藏(对齐海康:看不到操作者无权的部分)
		}
		out = append(out, model.RoleTreeNode{Id: r.Id, ParentId: r.ParentId, Name: r.Name, HasChildren: childParents[r.Id], CanCheck: canCheck})
	}
	return out, nil
}

// ---------- 资源:分页 + 权限下推(应用域 RES_AREA) ----------

// AreaResourcesPaged 点击某区域:列出其子树内、用户范围内、非零权限的资源,分页。
// 范围过滤(scope→WHERE)+ 子树前缀 + 隐藏零权限资源,全部下推 SQL;再对本页 ~size 条逐个点查操作。
func (s *ViewService) AreaResourcesPaged(ctx context.Context, userId string, areaId, page, size int) (*model.AreaResourcesPage, error) {
	page, size = normPage(page, size)
	out := &model.AreaResourcesPage{Resources: []model.ResourceView{}, Page: page, Size: size}
	u := s.User(userId)
	if u == nil {
		return out, nil
	}
	area := s.AreaById(areaId)
	if area == nil {
		return out, nil
	}
	out.AreaName = area.Name
	if !s.userResAreaCovers(u, areaId) { // 沿用原语义:仅导航祖先 → 不可访问
		out.Accessible = false
		return out, nil
	}
	out.Accessible = true

	f := s.treeScopeFilter(u, treeKindResArea)
	m := dao.Resource.Ctx(ctx).
		LeftJoin(dao.Area.Table(), "area.id = resource.area_id").
		Where("area.path LIKE ?", area.Path+"%") // 限定 areaId 子树
	if accSQL, accArgs := areaScopeWhere("area", f); accSQL != "" {
		m = m.Where(accSQL, accArgs...) // 叠加用户 RES_AREA 范围
	}

	total, err := m.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total
	var rows []struct {
		Id     int
		AreaId int
		Name   string
	}
	if err = m.Fields("resource.id,resource.area_id,resource.name").Page(page, size).Order("resource.id asc").Scan(&rows); err != nil {
		return nil, err
	}
	acts := s.Actions()
	for _, row := range rows {
		rv := model.ResourceView{Id: row.Id, Name: row.Name, Area: s.nodeName(treeKindArea, row.AreaId)}
		for _, act := range acts {
			allowed := s.CheckResource(u, row.Id, act.Code).Allow
			rv.Actions = append(rv.Actions, model.ActionAllow{Code: act.Code, Name: act.Name, Allowed: allowed})
		}
		// SQL 已按 RES_AREA 范围过滤,因此命中的资源就是可见资源;操作按钮统一按 CheckResource 标记。
		out.Resources = append(out.Resources, rv)
	}
	return out, nil
}

// ---------- 小工具 ----------

func normPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > maxPageSize {
		size = defaultPageSize
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
