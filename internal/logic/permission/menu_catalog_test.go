package permission

import (
	"reflect"
	"strings"
	"testing"

	"security-permission/internal/consts"
	"security-permission/internal/model"
)

func TestMenuCatalogIndexesDeduplicatesAndReturnsCopies(t *testing.T) {
	source := []*model.Menu{
		{Code: consts.MenuCodeAppVideo, Name: "视频监控", Domain: model.MenuDomainApp},
		{Code: consts.MenuCodeAppVideoLive, ParentCode: consts.MenuCodeAppVideo, Name: "实时预览", Domain: model.MenuDomainApp},
	}
	catalog, err := buildMenuCatalog(source)
	if err != nil {
		t.Fatal(err)
	}

	// 构造完成后不再依赖调用方传入的对象。
	source[1].Name = "已被外部修改"
	menu := catalog.menuByCode(consts.MenuCodeAppVideoLive)
	if menu == nil || menu.Name != "实时预览" || menu.ParentCode != consts.MenuCodeAppVideo {
		t.Fatalf("unexpected menu lookup: %+v", menu)
	}
	// 查询结果也是副本，调用方不能修改进程级目录。
	menu.Name = "已被查询方修改"
	if current := catalog.menuByCode(consts.MenuCodeAppVideoLive); current.Name != "实时预览" {
		t.Fatalf("catalog was mutated through lookup result: %+v", current)
	}

	codes, missing := catalog.knownCodes([]string{consts.MenuCodeAppVideoLive, consts.MenuCodeAppVideoLive, "missing", ""})
	if !reflect.DeepEqual(codes, []string{consts.MenuCodeAppVideoLive}) || !reflect.DeepEqual(missing, []string{"missing"}) {
		t.Fatalf("unexpected code mapping: codes=%v missing=%v", codes, missing)
	}
}

func TestMenuCatalogRejectsInvalidTrees(t *testing.T) {
	tests := []struct {
		name    string
		menus   []*model.Menu
		message string
	}{
		{name: "empty", message: "没有菜单"},
		{
			name:    "missing parent",
			menus:   []*model.Menu{{Code: consts.MenuCodeAppVideoLive, ParentCode: consts.MenuCodeAppVideo, Domain: model.MenuDomainApp}},
			message: "父菜单 app.video 不存在",
		},
		{
			name: "cross domain",
			menus: []*model.Menu{
				{Code: "sys.root", Domain: model.MenuDomainSys},
				{Code: "app.child", ParentCode: "sys.root", Domain: model.MenuDomainApp},
			},
			message: "不属于同一权限域",
		},
		{
			name: "cycle",
			menus: []*model.Menu{
				{Code: "app.one", ParentCode: "app.two", Domain: model.MenuDomainApp},
				{Code: "app.two", ParentCode: "app.one", Domain: model.MenuDomainApp},
			},
			message: "循环关系",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildMenuCatalog(test.menus)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}
