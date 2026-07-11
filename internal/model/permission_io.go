package model

type MetaData struct {
	Areas     []*Area     `json:"areas"`
	Orgs      []*Org      `json:"orgs"`
	Menus     []*Menu     `json:"menus"`
	Resources []*Resource `json:"resources"`
	Actions   []Action    `json:"actions"`
	Users     []*User     `json:"users"`
}

// Decision is the reusable authorization result returned by the permission engine.
type Decision struct {
	Allow  bool     `json:"allow"`
	Reason string   `json:"reason"`
	Trace  []string `json:"trace"`
}

// Grantable describes the current actor's delegation ceiling.
type Grantable struct {
	Unlimited  bool     `json:"unlimited"`
	MenuIds    []int    `json:"-"`
	MenuCodes  []string `json:"menuCodes"`
	AreaIds    []int    `json:"areaIds"`
	OrgIds     []int    `json:"orgIds"`
	ResAreaIds []int    `json:"resAreaIds"`
}

type AreaSaveInput struct {
	Id       int
	ParentId int
	Name     string
}

type AreaReorderInput struct {
	AreaId   int
	ToAreaId int
}

type OrgSaveInput struct {
	Id       int
	ParentId int
	Name     string
}

type ResourceSaveInput struct {
	Id     int
	AreaId int
	Name   string
	Type   string
}

type VisibleArea struct {
	Id         int    `json:"id"`
	ParentId   int    `json:"parentId"`
	Name       string `json:"name"`
	Accessible bool   `json:"accessible"`
}

type ResourceBrief struct {
	Id     int    `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	AreaId int    `json:"areaId"`
}

type ManageDetail struct {
	Accessible    bool            `json:"accessible"`
	Name          string          `json:"name"`
	ParentId      int             `json:"parentId"`
	ChildCount    int             `json:"childCount"`
	Children      []string        `json:"children"`
	Resources     []string        `json:"resources"`
	ResourceItems []ResourceBrief `json:"resourceItems"`
}

type ActionAllow struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type ResourceView struct {
	Id      int           `json:"id"`
	Name    string        `json:"name"`
	Area    string        `json:"area"`
	Actions []ActionAllow `json:"actions"`
}

type AncestorRef struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type AreaNode struct {
	Id          int           `json:"id"`
	ParentId    int           `json:"parentId"`
	Name        string        `json:"name"`
	Accessible  bool          `json:"accessible"`
	HasChildren bool          `json:"hasChildren"`
	Ancestors   []AncestorRef `json:"ancestors,omitempty"`
}

type PagedAreas struct {
	Items []AreaNode `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
}

type RoleTreeNode struct {
	Id          int    `json:"id"`
	ParentId    int    `json:"parentId"`
	Name        string `json:"name"`
	HasChildren bool   `json:"hasChildren"`
	CanCheck    bool   `json:"canCheck"`
}

type AreaResourcesPage struct {
	Accessible bool           `json:"accessible"`
	AreaName   string         `json:"areaName"`
	Resources  []ResourceView `json:"resources"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Size       int            `json:"size"`
}
