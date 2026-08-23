package permission

import (
	"strings"
	"testing"
)

func TestValidateAreaParentUnchanged(t *testing.T) {
	tests := []struct {
		name              string
		currentParentID   int
		requestedParentID int
		wantErr           bool
	}{
		{name: "重命名时省略父级", currentParentID: 10, requestedParentID: 0},
		{name: "重命名时传入当前父级", currentParentID: 10, requestedParentID: 10},
		{name: "拒绝更换父级", currentParentID: 10, requestedParentID: 20, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAreaParentUnchanged(test.currentParentID, test.requestedParentID)
			if test.wantErr {
				if err == nil {
					t.Fatal("期望拒绝更换父级，实际未返回错误")
				}
				if !strings.Contains(err.Error(), "不允许更换父级") {
					t.Fatalf("错误信息没有说明父级不可变：%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("合法的区域重命名被拒绝：%v", err)
			}
		})
	}
}
