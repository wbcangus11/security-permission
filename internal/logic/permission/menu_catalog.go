package permission

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/gogf/gf/v2/frame/g"

	"security-permission/internal/model"
)

// menuCatalog 是进程级只读菜单目录。
//
// 菜单属于随版本发布的稳定权限字典：应用启动时从数据库完整加载一次，
// 运行期间只读，不设置 TTL，也不会被角色、用户、区域等业务写操作清空。
type menuCatalog struct {
	all    []*model.Menu
	byCode map[string]*model.Menu
}

var (
	menuCatalogOnce sync.Once
	processMenus    *menuCatalog
	processMenusErr error
)

// InitializeMenuCatalog 在 HTTP 服务启动前加载并校验全部菜单。
// 第一次加载失败后不重试，由启动流程直接返回错误并终止进程，避免系统在
// 权限字典不完整的状态下提供服务。
func InitializeMenuCatalog(ctx context.Context) error {
	menuCatalogOnce.Do(func() {
		// 第 1 步：把代码内置的菜单基线幂等写入数据库，确保首次部署无需单独执行 menu.sql。
		if err := saveBuiltInMenus(ctx); err != nil {
			processMenusErr = fmt.Errorf("写入内置菜单失败: %w", err)
			return
		}
		// 第 2 步：一次性读取全部菜单。这是进程运行期间唯一一次菜单表查询。
		menus, err := loadMenus(ctx)
		if err != nil {
			processMenusErr = fmt.Errorf("读取菜单表失败: %w", err)
			return
		}
		// 第 3 步：校验菜单树，并建立按 code 查询的只读索引。
		processMenus, processMenusErr = buildMenuCatalog(menus)
	})
	return processMenusErr
}

type menuRow struct {
	Code       string
	ParentCode string
	Name       string
	Domain     string
}

// loadMenus 是运行期间唯一读取 menu 表的位置，只由启动初始化调用。
func loadMenus(ctx context.Context) ([]*model.Menu, error) {
	var rows []*menuRow
	if err := g.DB().Model("menu").Ctx(ctx).Fields("code,parent_code,name,domain").
		Order("code").Scan(&rows); err != nil {
		return nil, err
	}
	menus := make([]*model.Menu, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			menus = append(menus, nil)
			continue
		}
		menus = append(menus, &model.Menu{
			Code: row.Code, ParentCode: row.ParentCode, Name: row.Name, Domain: row.Domain,
		})
	}
	return menus, nil
}

func currentMenuCatalog() (*menuCatalog, error) {
	if processMenusErr != nil {
		return nil, processMenusErr
	}
	if processMenus == nil {
		return nil, fmt.Errorf("菜单目录尚未初始化")
	}
	return processMenus, nil
}

func buildMenuCatalog(menus []*model.Menu) (*menuCatalog, error) {
	if len(menus) == 0 {
		return nil, fmt.Errorf("菜单表中没有菜单")
	}
	catalog := &menuCatalog{
		all:    make([]*model.Menu, 0, len(menus)),
		byCode: make(map[string]*model.Menu, len(menus)),
	}
	// 先复制数据库结果并构造索引，确保目录不再受调用方对象修改影响。
	for index, source := range menus {
		if source == nil {
			return nil, fmt.Errorf("第 %d 个菜单为空", index+1)
		}
		menu := cloneMenu(source)
		if strings.TrimSpace(menu.Code) == "" {
			return nil, fmt.Errorf("第 %d 个菜单的 code 为空", index+1)
		}
		if _, exists := catalog.byCode[menu.Code]; exists {
			return nil, fmt.Errorf("菜单 code 重复: %s", menu.Code)
		}
		catalog.all = append(catalog.all, menu)
		catalog.byCode[menu.Code] = menu
	}

	// 子菜单必须拥有同域父节点，否则前端无法构造完整树。
	for _, menu := range catalog.all {
		if menu.ParentCode == "" {
			continue
		}
		parent := catalog.byCode[menu.ParentCode]
		if parent == nil {
			return nil, fmt.Errorf("菜单 %s 的父菜单 %s 不存在", menu.Code, menu.ParentCode)
		}
		if parent.Domain != menu.Domain {
			return nil, fmt.Errorf("菜单 %s 与父菜单 %s 不属于同一权限域", menu.Code, parent.Code)
		}
	}

	// 在启动阶段拒绝循环父子关系，防止菜单树遍历出现异常。
	for _, start := range catalog.all {
		seen := make(map[string]bool)
		for current := start; current != nil; current = catalog.byCode[current.ParentCode] {
			if seen[current.Code] {
				return nil, fmt.Errorf("菜单树存在循环关系，涉及菜单: %s", start.Code)
			}
			seen[current.Code] = true
			if current.ParentCode == "" {
				break
			}
		}
	}
	return catalog, nil
}

func cloneMenu(menu *model.Menu) *model.Menu {
	if menu == nil {
		return nil
	}
	clone := *menu
	return &clone
}

func (c *menuCatalog) menuByCode(code string) *model.Menu {
	return cloneMenu(c.byCode[code])
}

func (c *menuCatalog) menus() []*model.Menu {
	out := make([]*model.Menu, 0, len(c.all))
	for _, menu := range c.all {
		out = append(out, cloneMenu(menu))
	}
	return out
}

func (c *menuCatalog) knownCodes(codes []string) (known []string, missing []string) {
	// 保持接口提交顺序，同时去重；未知 code 单独返回，由角色保存入口统一拒绝。
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		if c.byCode[code] != nil {
			known = append(known, code)
		} else {
			missing = append(missing, code)
		}
	}
	return known, missing
}

func catalogMenuByCode(code string) (*model.Menu, error) {
	catalog, err := currentMenuCatalog()
	if err != nil {
		return nil, err
	}
	return catalog.menuByCode(code), nil
}

func catalogMenus() ([]*model.Menu, error) {
	catalog, err := currentMenuCatalog()
	if err != nil {
		return nil, err
	}
	return catalog.menus(), nil
}
