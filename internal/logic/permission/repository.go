package permission

import (
	"context"
	"sort"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/google/uuid"

	"security-permission/internal/consts"
	"security-permission/internal/dao"
	"security-permission/internal/model"
	"security-permission/internal/model/do"
	"security-permission/internal/model/entity"
)

// evaluator is the request-level permission context. It lazily reads individual
// records and keeps them only for the lifetime of one service operation.
type evaluator struct {
	ctx context.Context
	err error

	users        map[string]*model.User
	userLoaded   map[string]bool
	roles        map[int]*model.Role
	roleLoaded   map[int]bool
	areas        map[int]*model.Area
	areaLoaded   map[int]bool
	orgs         map[int]*model.Org
	orgLoaded    map[int]bool
	resources    map[int]*model.Resource
	resLoaded    map[int]bool
	menusByCode  map[string]*model.Menu
	menuCodeSeen map[string]bool
	allMenus     []*model.Menu
	menusLoaded  bool
}

func newEvaluator(ctx context.Context) *evaluator {
	e := &evaluator{
		ctx:          ctx,
		users:        map[string]*model.User{},
		userLoaded:   map[string]bool{},
		roles:        map[int]*model.Role{},
		roleLoaded:   map[int]bool{},
		areas:        map[int]*model.Area{},
		areaLoaded:   map[int]bool{},
		orgs:         map[int]*model.Org{},
		orgLoaded:    map[int]bool{},
		resources:    map[int]*model.Resource{},
		resLoaded:    map[int]bool{},
		menusByCode:  map[string]*model.Menu{},
		menuCodeSeen: map[string]bool{},
	}
	// Identity middleware has already validated the current HTTP user. Seed it
	// into this operation so the service does not issue the same user query twice.
	if request := g.RequestFromCtx(ctx); request != nil {
		if user, ok := request.GetCtxVar(consts.ContextKeyUser).Interface().(*model.User); ok && user != nil {
			e.users[user.Id] = user
			e.userLoaded[user.Id] = true
		}
	}
	return e
}

func (e *evaluator) fail(err error) {
	if e.err == nil && err != nil {
		e.err = err
	}
}

func (e *evaluator) user(id string) *model.User {
	if id == "" || e.err != nil {
		return nil
	}
	if e.userLoaded[id] {
		return e.users[id]
	}
	e.userLoaded[id] = true
	u, err := cachedUser(e.ctx, id)
	e.fail(err)
	e.users[id] = u
	return u
}

func (e *evaluator) role(id int) *model.Role {
	if id <= 0 || e.err != nil {
		return nil
	}
	if e.roleLoaded[id] {
		return e.roles[id]
	}
	e.roleLoaded[id] = true
	r, err := cachedRole(e.ctx, id)
	e.fail(err)
	e.roles[id] = r
	return r
}

func (e *evaluator) effectiveRoles(u *model.User) []*model.Role {
	if u == nil {
		return nil
	}
	roles := make([]*model.Role, 0, len(u.RoleIds))
	for _, id := range u.RoleIds {
		if r := e.role(id); r != nil {
			roles = append(roles, r)
		}
	}
	return roles
}

func (e *evaluator) area(id int) *model.Area {
	if id <= 0 || e.err != nil {
		return nil
	}
	if e.areaLoaded[id] {
		return e.areas[id]
	}
	e.areaLoaded[id] = true
	a, err := cachedArea(e.ctx, id)
	e.fail(err)
	e.areas[id] = a
	return a
}

func (e *evaluator) org(id int) *model.Org {
	if id <= 0 || e.err != nil {
		return nil
	}
	if e.orgLoaded[id] {
		return e.orgs[id]
	}
	e.orgLoaded[id] = true
	o, err := cachedOrg(e.ctx, id)
	e.fail(err)
	e.orgs[id] = o
	return o
}

func (e *evaluator) resource(id int) *model.Resource {
	if id <= 0 || e.err != nil {
		return nil
	}
	if e.resLoaded[id] {
		return e.resources[id]
	}
	e.resLoaded[id] = true
	r, err := cachedResource(e.ctx, id)
	e.fail(err)
	e.resources[id] = r
	return r
}

func (e *evaluator) menuByCode(code string) *model.Menu {
	if code == "" || e.err != nil {
		return nil
	}
	if e.menuCodeSeen[code] {
		return e.menusByCode[code]
	}
	e.menuCodeSeen[code] = true
	m, err := cachedMenuByCode(e.ctx, code)
	e.fail(err)
	if m != nil {
		e.menusByCode[m.Code] = m
	}
	return m
}

func (e *evaluator) menus() []*model.Menu {
	if e.menusLoaded || e.err != nil {
		return e.allMenus
	}
	e.menusLoaded = true
	menus, err := cachedMenus(e.ctx)
	e.fail(err)
	e.allMenus = menus
	for _, m := range menus {
		e.menusByCode[m.Code] = m
		e.menuCodeSeen[m.Code] = true
	}
	return menus
}

func (e *evaluator) nodePath(kind string, id int) string {
	if kind == treeKindOrg {
		if o := e.org(id); o != nil {
			return o.Path
		}
		return ""
	}
	if a := e.area(id); a != nil {
		return a.Path
	}
	return ""
}

func (e *evaluator) nodeName(kind string, id int) string {
	if kind == treeKindOrg {
		if o := e.org(id); o != nil {
			return o.Name
		}
		return ""
	}
	if a := e.area(id); a != nil {
		return a.Name
	}
	return ""
}

func findUser(ctx context.Context, id string) (*model.User, error) {
	var row entity.User
	if err := dao.User.Ctx(ctx).Where(dao.User.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == "" {
		return nil, nil
	}
	var bindings []struct{ RoleId int64 }
	if err := dao.UserRole.Ctx(ctx).Fields(dao.UserRole.Columns().RoleId).
		Where(dao.UserRole.Columns().UserId, id).Order(dao.UserRole.Columns().RoleId).Scan(&bindings); err != nil {
		return nil, err
	}
	u := &model.User{Id: row.Id, Name: row.Name, OrgId: int(row.OrgId), IsSuperuser: row.IsSuperuser != 0}
	for _, binding := range bindings {
		u.RoleIds = append(u.RoleIds, int(binding.RoleId))
	}
	return u, nil
}

func findRole(ctx context.Context, id int) (*model.Role, error) {
	var row entity.Role
	if err := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	r := &model.Role{Id: int(row.Id), Name: row.Name, Description: row.Description, CreatedBy: row.CreatedBy}
	var menuRows []struct {
		MenuId int64
		Code   string
	}
	if err := g.DB().Model(dao.RoleMenu.Table()+" rm").Ctx(ctx).
		LeftJoin("menu m", "m.id=rm.menu_id").
		Fields("rm.menu_id,m.code").
		Where("rm.role_id", id).Order("rm.menu_id").Scan(&menuRows); err != nil {
		return nil, err
	}
	for _, m := range menuRows {
		r.MenuIds = append(r.MenuIds, int(m.MenuId))
		if m.Code != "" {
			r.MenuCodes = append(r.MenuCodes, m.Code)
		}
	}
	var scopeRows []entity.RoleDataScope
	if err := dao.RoleDataScope.Ctx(ctx).Where(dao.RoleDataScope.Columns().RoleId, id).
		Order(dao.RoleDataScope.Columns().Id).Scan(&scopeRows); err != nil {
		return nil, err
	}
	for _, row := range scopeRows {
		scope := model.DataScope{NodeId: int(row.NodeId), IncludeChild: row.IncludeChild != 0}
		switch row.ScopeType {
		case model.ScopeTypeArea:
			r.AreaScopes = append(r.AreaScopes, scope)
		case model.ScopeTypeOrg:
			r.OrgScopes = append(r.OrgScopes, scope)
		case model.ScopeTypeResourceArea:
			r.ResourceAreaScopes = append(r.ResourceAreaScopes, scope)
		}
	}
	return r, nil
}

func findArea(ctx context.Context, id int) (*model.Area, error) {
	var row entity.Area
	if err := dao.Area.Ctx(ctx).Where(dao.Area.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Area{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path, Sort: row.Sort}, nil
}

func findOrg(ctx context.Context, id int) (*model.Org, error) {
	var row entity.Org
	if err := dao.Org.Ctx(ctx).Where(dao.Org.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Org{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path}, nil
}

func findResource(ctx context.Context, id int) (*model.Resource, error) {
	var row entity.Resource
	if err := dao.Resource.Ctx(ctx).Where(dao.Resource.Columns().Id, id).Scan(&row); err != nil {
		return nil, err
	}
	if row.Id == 0 {
		return nil, nil
	}
	return &model.Resource{Id: int(row.Id), AreaId: int(row.AreaId), Type: row.Type, Name: row.Name}, nil
}

type menuRow struct {
	Id       int64
	ParentId int64
	Code     string
	Name     string
	Domain   string
	Sort     int
}

func menuFromRow(row *menuRow) *model.Menu {
	if row == nil || row.Id == 0 {
		return nil
	}
	return &model.Menu{Id: int(row.Id), ParentId: int(row.ParentId), Code: row.Code, Name: row.Name, Domain: row.Domain, Sort: row.Sort}
}

func findMenuByCode(ctx context.Context, code string) (*model.Menu, error) {
	var row menuRow
	if err := g.DB().Model("menu").Ctx(ctx).Fields("id,parent_id,code,name,domain,sort").
		Where("code", code).Where("enabled", 1).Scan(&row); err != nil {
		return nil, err
	}
	return menuFromRow(&row), nil
}

func listMenus(ctx context.Context) ([]*model.Menu, error) {
	var rows []*menuRow
	if err := g.DB().Model("menu").Ctx(ctx).Fields("id,parent_id,code,name,domain,sort").
		Where("enabled", 1).Order("sort,id").Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Menu, 0, len(rows))
	for _, row := range rows {
		out = append(out, menuFromRow(row))
	}
	return out, nil
}

func menuIDsByCodes(ctx context.Context, codes []string) ([]int, []string, error) {
	seenCode := map[string]bool{}
	clean := make([]string, 0, len(codes))
	for _, code := range codes {
		if code != "" && !seenCode[code] {
			seenCode[code] = true
			clean = append(clean, code)
		}
	}
	if len(clean) == 0 {
		return []int{}, []string{}, nil
	}
	var rows []struct {
		Id   int64
		Code string
	}
	if err := g.DB().Model("menu").Ctx(ctx).Fields("id,code").WhereIn("code", clean).
		Where("enabled", 1).Scan(&rows); err != nil {
		return nil, nil, err
	}
	byCode := map[string]int{}
	for _, row := range rows {
		byCode[row.Code] = int(row.Id)
	}
	ids, missing := []int{}, []string{}
	for _, code := range clean {
		if id := byCode[code]; id > 0 {
			ids = append(ids, id)
		} else {
			missing = append(missing, code)
		}
	}
	return ids, missing, nil
}

func roleNameExists(ctx context.Context, name string, excludeID int) (bool, error) {
	m := dao.Role.Ctx(ctx).Where(dao.Role.Columns().Name, name)
	if excludeID > 0 {
		m = m.WhereNot(dao.Role.Columns().Id, excludeID)
	}
	count, err := m.Count()
	return count > 0, err
}

func saveRole(ctx context.Context, role *model.Role) (*model.Role, error) {
	err := dao.Role.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.Role{Name: role.Name, Description: role.Description, CreatedBy: role.CreatedBy}
		if role.Id <= 0 {
			result, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).Insert()
			if err != nil {
				return err
			}
			id, err := result.LastInsertId()
			if err != nil {
				return err
			}
			role.Id = int(id)
		} else if _, err := tx.Model(dao.Role.Table()).Ctx(ctx).Data(data).
			Where(dao.Role.Columns().Id, role.Id).Update(); err != nil {
			return err
		}

		if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).Where(dao.RoleMenu.Columns().RoleId, role.Id).Delete(); err != nil {
			return err
		}
		for _, menuID := range role.MenuIds {
			if _, err := tx.Model(dao.RoleMenu.Table()).Ctx(ctx).Data(do.RoleMenu{RoleId: role.Id, MenuId: menuID}).Insert(); err != nil {
				return err
			}
		}
		if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Where(dao.RoleDataScope.Columns().RoleId, role.Id).Delete(); err != nil {
			return err
		}
		insertScopes := func(scopeType string, scopes []model.DataScope) error {
			for _, scope := range scopes {
				if _, err := tx.Model(dao.RoleDataScope.Table()).Ctx(ctx).Data(do.RoleDataScope{
					RoleId: role.Id, ScopeType: scopeType, NodeId: scope.NodeId, IncludeChild: scope.IncludeChild,
				}).Insert(); err != nil {
					return err
				}
			}
			return nil
		}
		if err := insertScopes(model.ScopeTypeArea, role.AreaScopes); err != nil {
			return err
		}
		if err := insertScopes(model.ScopeTypeOrg, role.OrgScopes); err != nil {
			return err
		}
		return insertScopes(model.ScopeTypeResourceArea, role.ResourceAreaScopes)
	})
	if err != nil {
		return nil, err
	}
	permissionHotCache.invalidateAll()
	return findRole(ctx, role.Id)
}

func saveUser(ctx context.Context, user *model.User, exists bool) (*model.User, error) {
	if user.Id == "" {
		user.Id = uuid.NewString()
	}
	err := dao.User.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		data := do.User{Id: user.Id, Name: user.Name, OrgId: user.OrgId, IsSuperuser: user.IsSuperuser}
		if !exists {
			if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).Insert(); err != nil {
				return err
			}
		} else if _, err := tx.Model(dao.User.Table()).Ctx(ctx).Data(data).
			Where(dao.User.Columns().Id, user.Id).Update(); err != nil {
			return err
		}
		if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Where(dao.UserRole.Columns().UserId, user.Id).Delete(); err != nil {
			return err
		}
		for _, roleID := range user.RoleIds {
			if _, err := tx.Model(dao.UserRole.Table()).Ctx(ctx).Data(do.UserRole{UserId: user.Id, RoleId: roleID}).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	permissionHotCache.invalidateAll()
	return findUser(ctx, user.Id)
}

func listAllAreas(ctx context.Context) ([]*model.Area, error) {
	var rows []entity.Area
	if err := dao.Area.Ctx(ctx).Order(dao.Area.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Area, 0, len(rows))
	for _, row := range rows {
		out = append(out, &model.Area{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path, Sort: row.Sort})
	}
	return out, nil
}

func listAllOrgs(ctx context.Context) ([]*model.Org, error) {
	var rows []entity.Org
	if err := dao.Org.Ctx(ctx).Order(dao.Org.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	out := make([]*model.Org, 0, len(rows))
	for _, row := range rows {
		out = append(out, &model.Org{Id: int(row.Id), ParentId: int(row.ParentId), Name: row.Name, Path: row.Path})
	}
	return out, nil
}

func listUsersByIDs(ctx context.Context, ids []string) ([]*model.User, error) {
	if len(ids) == 0 {
		return []*model.User{}, nil
	}
	var rows []entity.User
	if err := dao.User.Ctx(ctx).WhereIn(dao.User.Columns().Id, ids).
		Order(dao.User.Columns().Id).Scan(&rows); err != nil {
		return nil, err
	}
	byID := make(map[string]*model.User, len(rows))
	for _, row := range rows {
		byID[row.Id] = &model.User{
			Id: row.Id, Name: row.Name, OrgId: int(row.OrgId), IsSuperuser: row.IsSuperuser != 0,
			RoleIds: []int{},
		}
	}
	var bindings []struct {
		UserId string
		RoleId int
	}
	if err := dao.UserRole.Ctx(ctx).Fields(
		dao.UserRole.Columns().UserId, dao.UserRole.Columns().RoleId,
	).WhereIn(dao.UserRole.Columns().UserId, ids).
		Order(dao.UserRole.Columns().UserId + "," + dao.UserRole.Columns().RoleId).
		Scan(&bindings); err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if user := byID[binding.UserId]; user != nil {
			user.RoleIds = append(user.RoleIds, binding.RoleId)
		}
	}
	users := make([]*model.User, 0, len(rows))
	for _, user := range byID {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Id < users[j].Id })
	return users, nil
}

func userNameExists(ctx context.Context, name, excludeID string) (bool, error) {
	query := dao.User.Ctx(ctx).Where(dao.User.Columns().Name, name)
	if excludeID != "" {
		query = query.Where(dao.User.Columns().Id+" <> ?", excludeID)
	}
	count, err := query.Count()
	return count > 0, err
}
