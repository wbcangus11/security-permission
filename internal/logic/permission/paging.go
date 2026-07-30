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

func addScopeToFilter(filter *treeFilter, scope model.DataScope, path string) {
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

func areaAncestors(ctx context.Context, path string) ([]model.AncestorRef, error) {
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
		area, err := findArea(ctx, id)
		if err != nil {
			return nil, err
		}
		if area != nil {
			out = append(out, model.AncestorRef{Id: area.Id, Name: area.Name})
		}
	}
	return out, nil
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
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return out, err
	}
	var gateMenus []string
	if kind == treeKindResArea {
		gateMenus = videoReadMenus
	} else {
		gateMenus = manageAreaReadMenus
	}
	if err := snapshot.requireAnyMenu(gateMenus...); err != nil {
		return out, err
	}
	filter := snapshot.treeFilter(kind)
	navigation := treeNavAncestors(filter)
	where, args, visible := visibilityWhere(filter, navigation)
	if !visible {
		return out, nil
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
	return out, nil
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
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return out, err
	}
	var gateMenus []string
	if kind == treeKindResArea {
		gateMenus = videoReadMenus
	} else {
		gateMenus = manageAreaReadMenus
	}
	if err := snapshot.requireAnyMenu(gateMenus...); err != nil {
		return out, err
	}
	if text == "" {
		return out, nil
	}
	if utf8.RuneCountInString(text) > maxAreaSearchLength {
		return out, gerror.NewCodef(gcode.CodeInvalidParameter, "区域搜索关键字不能超过 %d 个字符", maxAreaSearchLength)
	}
	filter := snapshot.treeFilter(kind)
	where, args, visible := visibilityWhere(filter, treeNavAncestors(filter))
	if !visible {
		return out, nil
	}
	// LOCATE 按字面值搜索子串，因此调用方传入的“%”或“_”不会被解释为通配符，
	// 也就不能借此把查询扩大为对整棵可见树的通配扫描。
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
		ancestors, err := areaAncestors(ctx, row.Path)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, model.AreaNode{
			Id: row.Id, ParentId: row.ParentId, Name: row.Name,
			Accessible: filter.covers(row.Path, row.Id), Ancestors: ancestors,
		})
	}
	return out, nil
}

func RoleAreaChildren(ctx context.Context, userID string, parentID int, kind string, roleID int) ([]model.RoleTreeNode, error) {
	out := []model.RoleTreeNode{}
	if kind != treeKindArea && kind != treeKindResArea {
		return out, nil
	}
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return out, err
	}
	if roleID > 0 {
		if _, err := guardManageRole(ctx, snapshot, roleID); err != nil {
			return out, err
		}
	} else if err := snapshot.requireAnyMenu(menuRoleManage); err != nil {
		return out, err
	}
	grantableFilter := snapshot.treeFilter(kind)
	// 编辑树只展示当前操作人的可授权范围；角色范围外的历史记录由后端保留。
	if grantableFilter.None {
		return out, nil
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
		visible := grantableFilter.covers(row.Path, row.Id) || grantableFilter.hasDescendantGrant(row.Path)
		if !visible {
			continue
		}
		hasChildren := grantableFilter.hasDescendantGrant(row.Path)
		if grantableFilter.All || grantableFilter.underPrefix(row.Path) {
			hasChildren = childParents[row.Id]
		}
		out = append(out, model.RoleTreeNode{
			Id: row.Id, ParentId: row.ParentId, Name: row.Name,
			CanCheck: grantableFilter.covers(row.Path, row.Id), HasChildren: hasChildren,
		})
	}
	return out, nil
}

func AreaResourcesPaged(ctx context.Context, userID string, areaID, page, size int) (*model.AreaResourcesPage, error) {
	page, size = normPage(page, size)
	out := &model.AreaResourcesPage{Resources: []model.ResourceView{}, Page: page, Size: size}
	snapshot, err := loadPermissionSnapshot(ctx, userID)
	if err != nil {
		return out, err
	}
	if err := snapshot.requireAnyMenu(videoReadMenus...); err != nil {
		return out, err
	}
	area, err := findArea(ctx, areaID)
	if err != nil || area == nil {
		return out, err
	}
	out.AreaName = area.Name
	if !snapshot.covers(treeKindResArea, area.Path, areaID) {
		return out, nil
	}
	out.Accessible = true
	filter := snapshot.treeFilter(treeKindResArea)
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
		Id       int
		AreaId   int
		Name     string
		Type     string
		AreaName string
		AreaPath string
	}
	if err = query.Fields("resource.id,resource.area_id,resource.name,resource.type,area.name AS area_name,area.path AS area_path").
		Page(page, size).Order("resource.id asc").Scan(&rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		view := model.ResourceView{Id: row.Id, Name: row.Name, Area: row.AreaName}
		for _, action := range resourceActions {
			view.Actions = append(view.Actions, model.ActionAllow{
				Code: action.Code,
				Name: action.Name,
				Allowed: snapshot.hasMenu(action.MenuCode) &&
					snapshot.covers(treeKindResArea, row.AreaPath, row.AreaId),
			})
		}
		out.Resources = append(out.Resources, view)
	}
	return out, nil
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
