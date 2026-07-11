// Package service defines business interfaces only. Concrete implementations are
// registered by internal/logic packages during application startup.
package service

import (
	"context"
	"sync"

	"security-permission/internal/model"
)

type Runtime interface {
	Reload(ctx context.Context) error
	Meta(actorID string, demoMode bool) *model.MetaData
	Areas() []*model.Area
	Orgs() []*model.Org
	Menus() []*model.Menu
	Resources() []*model.Resource
	Actions() []model.Action
	Users() []*model.User
	User(id string) *model.User
}

type Auth interface {
	CheckMenu(user *model.User, menuCode string) *model.Decision
	CheckArea(user *model.User, areaID int) *model.Decision
	CheckOrg(user *model.User, orgID int) *model.Decision
	CheckResource(user *model.User, resourceID int, actionCode string) *model.Decision
}

type Role interface {
	List(actorID string) []*model.Role
	Get(actorID string, roleID int) (*model.Role, error)
	SaveBasic(ctx context.Context, actorID string, role *model.Role) (*model.Role, int, error)
	Delete(ctx context.Context, actorID string, roleID int) error
}

type Delegation interface {
	GrantableSet(actorID string) *model.Grantable
	RoleAreaChildren(ctx context.Context, actorID string, parentID int, kind string) ([]model.RoleTreeNode, error)
}

type User interface {
	List(actorID string) []*model.User
	Get(actorID, userID string) (*model.User, error)
	SaveManaged(ctx context.Context, actorID string, user *model.User) (*model.User, error)
	Delete(ctx context.Context, actorID, userID string) error
}

type Area interface {
	Save(ctx context.Context, actorID string, input *model.AreaSaveInput) (*model.Area, error)
	Reorder(ctx context.Context, actorID string, input *model.AreaReorderInput) error
	Delete(ctx context.Context, actorID string, areaID int) error
}

type Org interface {
	Save(ctx context.Context, actorID string, input *model.OrgSaveInput) (*model.Org, error)
	Delete(ctx context.Context, actorID string, orgID int) error
}

type Resource interface {
	Save(ctx context.Context, actorID string, input *model.ResourceSaveInput) (*model.Resource, error)
	Delete(ctx context.Context, actorID string, resourceID int) error
}

type View interface {
	ManageOrgs(userID string) []model.VisibleArea
	ManageAreaDetail(ctx context.Context, userID string, areaID int) (*model.ManageDetail, error)
	ManageOrgDetail(userID string, orgID int) *model.ManageDetail
	SysMenus(userID string) []*model.Menu
	AppMenus(userID string) []*model.Menu
	AreaChildren(ctx context.Context, userID string, parentID, page, size int) (*model.PagedAreas, error)
	ManageAreaChildren(ctx context.Context, userID string, parentID, page, size int) (*model.PagedAreas, error)
	SearchAreas(ctx context.Context, userID, query, scope string, page, size int) (*model.PagedAreas, error)
	AreaResourcesPaged(ctx context.Context, userID string, areaID, page, size int) (*model.AreaResourcesPage, error)
}

type Provider struct {
	Runtime    Runtime
	Auth       Auth
	Role       Role
	Delegation Delegation
	User       User
	Area       Area
	Org        Org
	Resource   Resource
	View       View
}

var (
	providerMu sync.RWMutex
	provider   Provider
)

func Register(p Provider) {
	providerMu.Lock()
	provider = p
	providerMu.Unlock()
}

func current() Provider {
	providerMu.RLock()
	p := provider
	providerMu.RUnlock()
	if p.Runtime == nil {
		panic("permission service is not registered: import internal/logic/permission")
	}
	return p
}

func RuntimeService() Runtime       { return current().Runtime }
func AuthService() Auth             { return current().Auth }
func RoleService() Role             { return current().Role }
func DelegationService() Delegation { return current().Delegation }
func UserService() User             { return current().User }
func AreaService() Area             { return current().Area }
func OrgService() Org               { return current().Org }
func ResourceService() Resource     { return current().Resource }
func ViewService() View             { return current().View }
