package perm

import (
	"reflect"
	"strings"
	"testing"

	v1 "security-permission/api/perm/v1"
)

const apiV1PackagePath = "security-permission/api/perm/v1"

func TestControllerMethodsUseAPIV1RequestAndResponseTypes(t *testing.T) {
	controllerType := reflect.TypeOf(&ControllerV1{})
	errorType := reflect.TypeOf((*error)(nil)).Elem()

	for i := 0; i < controllerType.NumMethod(); i++ {
		method := controllerType.Method(i)
		methodType := method.Type
		if methodType.NumIn() != 3 || methodType.NumOut() != 2 {
			t.Fatalf("%s 必须使用 (ctx, *v1.XxxReq) (*v1.XxxRes, error) 签名", method.Name)
		}

		reqType := methodType.In(2)
		if reqType.Kind() != reflect.Pointer ||
			reqType.Elem().PkgPath() != apiV1PackagePath ||
			!strings.HasSuffix(reqType.Elem().Name(), "Req") {
			t.Fatalf("%s 的请求类型不在 api/perm/v1：%v", method.Name, reqType)
		}

		resType := methodType.Out(0)
		if resType.Kind() != reflect.Pointer ||
			resType.Elem().PkgPath() != apiV1PackagePath ||
			!strings.HasSuffix(resType.Elem().Name(), "Res") {
			t.Fatalf("%s 的响应类型不在 api/perm/v1：%v", method.Name, resType)
		}
		if methodType.Out(1) != errorType {
			t.Fatalf("%s 的第二个返回值必须是 error：%v", method.Name, methodType.Out(1))
		}
	}
}

func TestRoleRequestMappingPreservesOmittedAndEmptyMenuReplacement(t *testing.T) {
	if rolePermissionChangesInput(nil) != nil {
		t.Fatal("省略 permissions 时 service input 必须保持 nil")
	}

	input := rolePermissionChangesInput(&v1.RolePermissionChanges{
		MenuConfig: &v1.MenuReplacement{Replace: []string{}},
	})
	if input == nil || input.MenuConfig == nil || input.MenuConfig.Replace == nil {
		t.Fatal("显式空 replace 映射到 model 后必须仍是非 nil 空切片")
	}
	if input.MenuApp != nil {
		t.Fatal("省略的 menuApp 映射到 model 后必须保持 nil")
	}
}
