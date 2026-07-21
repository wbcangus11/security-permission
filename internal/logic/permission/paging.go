package permission

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/dao"
	"security-permission/internal/model"
)

// treeFilter 是用户有效树范围的紧凑 SQL 表达。权限范围只保留少量路径前缀
// 和精确节点，不展开整棵区域/组织树。
type treeFilter struct {
	All       bool
	None      bool
	Prefixes  []string
	ExactIds  []int
	RootPaths []string
}

func (f treeFilter) underPrefix(path string) bool {
	for _, prefix := range f.Prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (f treeFilter) hasDescendantGrant(path string) bool {
	for _, root := range f.RootPaths {
		if len(root) > len(path) && strings.HasPrefix(root, path) {
			return true
		}
	}
	return false
}

func (f treeFilter) covers(path string, id int) bool {
	if f.All {
		return true
	}
	if f.underPrefix(path) {
		return true
	}
	for _, exact := range f.ExactIds {
		if exact == id {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueInt(values []int, value int) []int {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func (e *evaluator) addFilterScope(filter *treeFilter, kind string, scope model.DataScope) {
	path := e.nodePath(kind, scope.NodeId)
	if path == "" {
		return
	}
	if scope.IncludeChild {
		filter.Prefixes = appendUniqueString(filter.Prefixes, path)
	} else {
		filter.ExactIds = appendUniqueInt(filter.ExactIds, scope.NodeId)
	}
	filter.RootPaths = appendUniqueString(filter.RootPaths, path)
}

func roleScopes(role *model.Role, kind string) []model.DataScope {
	switch kind {
	case treeKindOrg:
		return role.OrgScopes
	case treeKindResArea:
		return role.ResourceAreaScopes
	default:
		return role.AreaScopes
	}
}

func (e *evaluator) roleTreeFilter(role *model.Role, kind string) treeFilter {
	filter := treeFilter{}
	for _, scope := range roleScopes(role, kind) {
		e.addFilterScope(&filter, kind, scope)
	}
	filter.None = len(filter.Prefixes) == 0 && len(filter.ExactIds) == 0
	return filter
}

func unionTreeFilters(left, right treeFilter) treeFilter {
	if left.All || right.All {
		return treeFilter{All: true}
	}
	out := treeFilter{}
	for _, source := range []treeFilter{left, right} {
		for _, prefix := range source.Prefixes {
			out.Prefixes = appendUniqueString(out.Prefixes, prefix)
		}
		for _, id := range source.ExactIds {
			out.ExactIds = appendUniqueInt(out.ExactIds, id)
		}
		for _, root := range source.RootPaths {
			out.RootPaths = appendUniqueString(out.RootPaths, root)
		}
	}
	out.None = len(out.Prefixes) == 0 && len(out.ExactIds) == 0
	return out
}

func (e *evaluator) treeScopeFilter(user *model.User, kind string) treeFilter {
	if isSuper(user) {
		return treeFilter{All: true}
	}
	result := treeFilter{None: true}
	for _, role := range e.effectiveRoles(user) {
		roleFilter := e.roleTreeFilter(role, kind)
		if roleFilter.None {
			continue
		}
		result = unionTreeFilters(result, roleFilter)
	}
	return result
}

func treeNavAncestors(filter treeFilter) map[int]bool {
	out := map[int]bool{}
	if filter.All || filter.None {
		return out
	}
	for _, path := range filter.RootPaths {
		for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
			if id, err := strconv.Atoi(segment); err == nil {
				out[id] = true
			}
		}
	}
	return out
}

// treeScopeWhere 可用于 area 或 org：两张树表都使用 id/path 字段。
func treeScopeWhere(alias string, filter treeFilter) (string, []interface{}) {
	if filter.All {
		return "", nil
	}
	column := func(name string) string {
		if alias == "" {
			return name
		}
		return alias + "." + name
	}
	parts := []string{}
	args := []interface{}{}
	for _, prefix := range filter.Prefixes {
		parts = append(parts, column("path")+" LIKE ?")
		args = append(args, prefix+"%")
	}
	if len(filter.ExactIds) > 0 {
		parts = append(parts, column("id")+" IN (?)")
		args = append(args, filter.ExactIds)
	}
	if len(parts) == 0 {
		return sqlAlwaysFalse, nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

func visibilityWhere(filter treeFilter, navigation map[int]bool) (string, []interface{}, bool) {
	if filter.All {
		return "", nil, true
	}
	parts := []string{}
	args := []interface{}{}
	if !filter.None {
		where, whereArgs := treeScopeWhere("", filter)
		parts = append(parts, where)
		args = append(args, whereArgs...)
	}
	if len(navigation) > 0 {
		parts = append(parts, "id IN (?)")
		args = append(args, mapKeys(navigation))
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, true
}

func (e *evaluator) areaAncestors(path string) []model.AncestorRef {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	out := []model.AncestorRef{}
	for index, part := range parts {
		if index == len(parts)-1 || part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		if area := e.area(id); area != nil {
			out = append(out, model.AncestorRef{Id: area.Id, Name: area.Name})
		}
	}
	return out
}

func AreaChildren(ctx context.Context, userID string, parentID, page, size int) (*model.PagedAreas, error) {
	return areaChildrenBy(ctx, userID, parentID, page, size, treeKindResArea)
}

func ManageAreaChildren(ctx context.Context, userID string, parentID, page, size int) (*model.PagedAreas, error) {
	return areaChildrenBy(ctx, userID, parentID, page, size, treeKindArea)
}

func areaChildrenBy(ctx context.Context, userID string, parentID, page, size int, kind string) (*model.PagedAreas, error) {
	page, size = normPage(page, size)
	out := &model.PagedAreas{Items: []model.AreaNode{}, Page: page, Size: size}
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	var gateMenus []string
	if kind == treeKindResArea {
		gateMenus = videoReadMenus
	} else {
		gateMenus = manageAreaReadMenus
	}
	if err := ev.requireAnyMenu(user, gateMenus...); err != nil {
		return out, err
	}
	filter := ev.treeScopeFilter(user, kind)
	navigation := treeNavAncestors(filter)
	where, args, visible := visibilityWhere(filter, navigation)
	if !visible {
		return out, ev.err
	}

	query := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, parentID)
	if where != "" {
		query = query.Where(where, args...)
	}
	total, err := query.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total
	var rows []areaListRow
	if err = query.Fields("id,parent_id,name,path").Page(page, size).
		Order("sort asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.Id)
	}
	childParents, err := areaChildParents(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		accessible := filter.covers(row.Path, row.Id)
		hasChildren := filter.hasDescendantGrant(row.Path)
		if filter.All || filter.underPrefix(row.Path) {
			hasChildren = childParents[row.Id]
		}
		out.Items = append(out.Items, model.AreaNode{
			Id: row.Id, ParentId: row.ParentId, Name: row.Name,
			Accessible: accessible, HasChildren: hasChildren,
		})
	}
	return out, ev.err
}

type areaListRow struct {
	Id       int
	ParentId int
	Name     string
	Path     string
}

func areaChildParents(ctx context.Context, ids []int) (map[int]bool, error) {
	out := map[int]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct{ ParentId int }
	if err := dao.Area.Ctx(ctx).Fields("DISTINCT parent_id").Where("parent_id IN (?)", ids).Scan(&rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.ParentId] = true
	}
	return out, nil
}

func SearchAppAreas(ctx context.Context, userID, text string) (*model.PagedAreas, error) {
	return searchAreasBy(ctx, userID, text, treeKindResArea)
}

func SearchManageAreas(ctx context.Context, userID, text string) (*model.PagedAreas, error) {
	return searchAreasBy(ctx, userID, text, treeKindArea)
}

func searchAreasBy(ctx context.Context, userID, text, kind string) (*model.PagedAreas, error) {
	out := &model.PagedAreas{Items: []model.AreaNode{}, Page: 1, Size: searchLimit}
	text = strings.TrimSpace(text)
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	var gateMenus []string
	if kind == treeKindResArea {
		gateMenus = videoReadMenus
	} else {
		gateMenus = manageAreaReadMenus
	}
	if err := ev.requireAnyMenu(user, gateMenus...); err != nil {
		return out, err
	}
	if text == "" {
		return out, nil
	}
	if utf8.RuneCountInString(text) > maxAreaSearchLength {
		return out, gerror.NewCodef(gcode.CodeInvalidParameter, "区域搜索关键字不能超过 %d 个字符", maxAreaSearchLength)
	}
	filter := ev.treeScopeFilter(user, kind)
	where, args, visible := visibilityWhere(filter, treeNavAncestors(filter))
	if !visible {
		return out, ev.err
	}
	// LOCATE performs a literal substring search, so caller supplied '%'/'_'
	// cannot turn the request into a wildcard scan of the complete visible tree.
	query := dao.Area.Ctx(ctx).Where("LOCATE(?, name) > 0", text)
	if where != "" {
		query = query.Where(where, args...)
	}
	total, err := query.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total
	var rows []areaListRow
	if err = query.Fields("id,parent_id,name,path").Limit(searchLimit).
		Order("name asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		out.Items = append(out.Items, model.AreaNode{
			Id: row.Id, ParentId: row.ParentId, Name: row.Name,
			Accessible: filter.covers(row.Path, row.Id), Ancestors: ev.areaAncestors(row.Path),
		})
	}
	return out, ev.err
}

func RoleAreaChildren(ctx context.Context, userID string, parentID int, kind string) ([]model.RoleTreeNode, error) {
	out := []model.RoleTreeNode{}
	if kind != treeKindArea && kind != treeKindResArea {
		return out, nil
	}
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	if err := ev.requireAnyMenu(user, menuRoleManage); err != nil {
		return out, err
	}
	filter := ev.treeScopeFilter(user, kind)
	if filter.None {
		return out, ev.err
	}
	var rows []areaListRow
	if err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().ParentId, parentID).
		Fields("id,parent_id,name,path").Order("sort asc,id asc").Scan(&rows); err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.Id)
	}
	childParents, err := areaChildParents(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		canCheck := filter.covers(row.Path, row.Id)
		if !canCheck && !filter.hasDescendantGrant(row.Path) {
			continue
		}
		hasChildren := filter.hasDescendantGrant(row.Path)
		if filter.All || filter.underPrefix(row.Path) {
			hasChildren = childParents[row.Id]
		}
		out = append(out, model.RoleTreeNode{
			Id: row.Id, ParentId: row.ParentId, Name: row.Name,
			CanCheck: canCheck, HasChildren: hasChildren,
		})
	}
	return out, ev.err
}

func AreaResourcesPaged(ctx context.Context, userID string, areaID, page, size int) (*model.AreaResourcesPage, error) {
	page, size = normPage(page, size)
	out := &model.AreaResourcesPage{Resources: []model.ResourceView{}, Page: page, Size: size}
	ev := newEvaluator(ctx)
	user := ev.user(userID)
	if ev.err != nil {
		return out, ev.err
	}
	if err := ev.requireAnyMenu(user, videoReadMenus...); err != nil {
		return out, err
	}
	area := ev.area(areaID)
	if ev.err != nil || area == nil {
		return out, ev.err
	}
	out.AreaName = area.Name
	if !ev.userResourceAreaCovers(user, areaID) {
		return out, ev.err
	}
	out.Accessible = true
	filter := ev.treeScopeFilter(user, treeKindResArea)
	query := dao.Resource.Ctx(ctx).
		LeftJoin(dao.Area.Table(), "area.id = resource.area_id").
		Where("area.path LIKE ?", area.Path+"%")
	if where, args := treeScopeWhere("area", filter); where != "" {
		query = query.Where(where, args...)
	}
	total, err := query.Count()
	if err != nil {
		return nil, err
	}
	out.Total = total
	var rows []struct {
		Id     int
		AreaId int
		Name   string
		Type   string
	}
	if err = query.Fields("resource.id,resource.area_id,resource.name,resource.type").
		Page(page, size).Order("resource.id asc").Scan(&rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		ev.resources[row.Id] = &model.Resource{Id: row.Id, AreaId: row.AreaId, Name: row.Name, Type: row.Type}
		ev.resLoaded[row.Id] = true
		view := model.ResourceView{Id: row.Id, Name: row.Name, Area: ev.nodeName(treeKindArea, row.AreaId)}
		for _, action := range resourceActions {
			decision := ev.checkResource(user, row.Id, action.Code)
			view.Actions = append(view.Actions, model.ActionAllow{
				Code: action.Code, Name: action.Name, Allowed: decision.Allow,
			})
		}
		out.Resources = append(out.Resources, view)
	}
	return out, ev.err
}

func normPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > maxPageSize {
		size = defaultPageSize
	}
	return page, size
}

func mapKeys(values map[int]bool) []int {
	out := make([]int, 0, len(values))
	for id := range values {
		out = append(out, id)
	}
	return out
}
