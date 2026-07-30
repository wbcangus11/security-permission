package permission

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"security-permission/internal/model"
)

type rolePermissionPlan struct {
	MenuConfigCodes *[]string
	MenuAppCodes    *[]string
	Area            model.DataScopeChanges
	Org             model.DataScopeChanges
	ResourceArea    model.DataScopeChanges
}

// prepareMenuDomain 只替换操作人当前可编辑的菜单权限，并拒绝把 SYS、APP 权限码混在同一字段中。
// 旧角色中超出操作人当前权限的菜单不会出现在详情里，这里必须原样保留。
func prepareMenuDomain(
	snapshot *permissionSnapshot,
	old *model.Role,
	replacement *model.MenuReplacement,
	field string,
	domain string,
) (*[]string, error) {
	if replacement == nil {
		return nil, nil
	}
	if replacement.Replace == nil {
		return nil, fmt.Errorf("%s.replace 必须显式传递；清空该菜单域请传空数组", field)
	}
	catalog, err := currentMenuCatalog()
	if err != nil {
		return nil, err
	}
	menuCodes, missing := catalog.knownCodes(replacement.Replace)
	if len(missing) > 0 {
		return nil, fmt.Errorf("菜单权限码不存在：%s", strings.Join(missing, ","))
	}

	seen := make(map[string]bool, len(menuCodes))
	for _, menuCode := range menuCodes {
		menu := catalog.byCode[menuCode]
		if menu == nil {
			return nil, fmt.Errorf("菜单不存在：%s", menuCode)
		}
		if menu.Domain != domain {
			return nil, fmt.Errorf("%s 不能包含 %s 域菜单：%s", field, menu.Domain, menu.Code)
		}
		if !snapshot.hasMenu(menuCode) {
			return nil, fmt.Errorf("无权授予菜单：%s", menu.Code)
		}
		seen[menuCode] = true
	}

	oldDomainCodes := old.MenuConfigCodes
	if domain == model.MenuDomainApp {
		oldDomainCodes = old.MenuAppCodes
	}
	for _, menuCode := range oldDomainCodes {
		if !seen[menuCode] && !snapshot.hasMenu(menuCode) {
			menuCodes = append(menuCodes, menuCode)
			seen[menuCode] = true
		}
	}
	return &menuCodes, nil
}

// prepareRolePermissions 只处理请求中显式存在的权限变化，不根据缺失字段推测删除意图。
func prepareRolePermissions(
	ctx context.Context,
	snapshot *permissionSnapshot,
	old *model.Role,
	changes *model.RolePermissionChanges,
) (*rolePermissionPlan, error) {
	if changes == nil {
		return nil, nil
	}
	plan := &rolePermissionPlan{}

	// 第 1 步：系统配置菜单和应用菜单分别生成快照，未提交的菜单域保持不变。
	var err error
	plan.MenuConfigCodes, err = prepareMenuDomain(
		snapshot, old, changes.MenuConfig, "menuConfig", model.MenuDomainSys,
	)
	if err != nil {
		return nil, err
	}
	plan.MenuAppCodes, err = prepareMenuDomain(
		snapshot, old, changes.MenuApp, "menuApp", model.MenuDomainApp,
	)
	if err != nil {
		return nil, err
	}
	// 第 2 步：树权限始终按明确的 adds/dels 计算实际变化，空数组表示该树不变。
	areaPlan, err := planScopeChanges(old.AreaScopes, changes.Area)
	if err != nil {
		return nil, fmt.Errorf("安保区域权限：%w", err)
	}
	orgPlan, err := planScopeChanges(old.OrgScopes, changes.Org)
	if err != nil {
		return nil, fmt.Errorf("组织权限：%w", err)
	}
	resourceAreaPlan, err := planScopeChanges(old.ResourceAreaScopes, changes.ResourceArea)
	if err != nil {
		return nil, fmt.Errorf("业务资源区域权限：%w", err)
	}
	plan.Area, plan.Org, plan.ResourceArea = areaPlan, orgPlan, resourceAreaPlan

	// 第 3 步：增删都只能作用于操作人当前可编辑的范围。
	// 范围外旧记录不会出现在详情中，也不能通过手工构造请求绕过可见性边界。
	if err := validateScopeChanges(ctx, snapshot, treeKindArea, "安保区域", plan.Area); err != nil {
		return nil, err
	}
	if err := validateScopeChanges(ctx, snapshot, treeKindOrg, "组织", plan.Org); err != nil {
		return nil, err
	}
	if err := validateScopeChanges(ctx, snapshot, treeKindResArea, "业务资源区域", plan.ResourceArea); err != nil {
		return nil, err
	}
	return plan, nil
}

func validateScopeChanges(
	ctx context.Context,
	snapshot *permissionSnapshot,
	kind string,
	label string,
	changes model.DataScopeChanges,
) error {
	if err := validateScopes(ctx, snapshot, kind, label, "删除", changes.Dels); err != nil {
		return err
	}
	return validateScopes(ctx, snapshot, kind, label, "授予", changes.Adds)
}

func validateScopes(
	ctx context.Context,
	snapshot *permissionSnapshot,
	kind string,
	label string,
	action string,
	scopes []model.DataScope,
) error {
	for _, scope := range scopes {
		path, name, err := findTreeNode(ctx, kind, scope.NodeId)
		if err != nil {
			return err
		}
		if path == "" {
			return fmt.Errorf("%s节点不存在：%d", label, scope.NodeId)
		}
		if !snapshot.canGrantScope(kind, path, scope) {
			rangeName := "单节点"
			if scope.IncludeChild {
				rangeName = "整棵子树"
			}
			return fmt.Errorf("无权%s%s“%s”的%s权限", action, label, name, rangeName)
		}
	}
	return nil
}

// planScopeChanges 把客户端增删量转换成相对于当前数据库状态的实际变化。
// 它支持安全重试：已删除的记录再次删除、已增加的记录再次增加都视为无操作。
func planScopeChanges(old []model.DataScope, requested model.DataScopeChanges) (model.DataScopeChanges, error) {
	oldValues := make(map[int]bool, len(old))
	for _, scope := range old {
		if scope.NodeId > 0 {
			oldValues[scope.NodeId] = scope.IncludeChild
		}
	}
	adds, err := indexScopeChanges("adds", requested.Adds)
	if err != nil {
		return model.DataScopeChanges{}, err
	}
	dels, err := indexScopeChanges("dels", requested.Dels)
	if err != nil {
		return model.DataScopeChanges{}, err
	}

	desired := make(map[int]bool, len(oldValues)+len(adds))
	for nodeID, includeChild := range oldValues {
		desired[nodeID] = includeChild
	}
	for nodeID, deleteValue := range dels {
		currentValue, exists := oldValues[nodeID]
		if !exists {
			continue
		}
		if currentValue == deleteValue {
			delete(desired, nodeID)
			continue
		}
		// 修改 includeChild 的请求重试时，当前值可能已经等于本次 adds 的最终值。
		if addValue, hasAdd := adds[nodeID]; hasAdd && addValue == currentValue {
			continue
		}
		return model.DataScopeChanges{}, fmt.Errorf("节点 %d 的已保存权限状态已变化，请重新载入角色", nodeID)
	}
	for nodeID, addValue := range adds {
		if currentValue, exists := oldValues[nodeID]; exists && currentValue != addValue {
			deleteValue, hasDelete := dels[nodeID]
			if !hasDelete || deleteValue != currentValue {
				return model.DataScopeChanges{}, fmt.Errorf("节点 %d 修改 includeChild 时必须同时删除旧值", nodeID)
			}
		}
		desired[nodeID] = addValue
	}

	plan := model.DataScopeChanges{Adds: []model.DataScope{}, Dels: []model.DataScope{}}
	for nodeID, oldValue := range oldValues {
		newValue, exists := desired[nodeID]
		if !exists || newValue != oldValue {
			plan.Dels = append(plan.Dels, model.DataScope{NodeId: nodeID, IncludeChild: oldValue})
		}
	}
	for nodeID, newValue := range desired {
		oldValue, exists := oldValues[nodeID]
		if !exists || oldValue != newValue {
			plan.Adds = append(plan.Adds, model.DataScope{NodeId: nodeID, IncludeChild: newValue})
		}
	}
	sortScopes(plan.Adds)
	sortScopes(plan.Dels)
	return plan, nil
}

func indexScopeChanges(field string, scopes []model.DataScope) (map[int]bool, error) {
	out := make(map[int]bool, len(scopes))
	for _, scope := range scopes {
		if scope.NodeId <= 0 {
			return nil, fmt.Errorf("%s 包含无效节点 ID", field)
		}
		if _, exists := out[scope.NodeId]; exists {
			return nil, fmt.Errorf("%s 重复提交节点 %d", field, scope.NodeId)
		}
		out[scope.NodeId] = scope.IncludeChild
	}
	return out, nil
}

func sortScopes(scopes []model.DataScope) {
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].NodeId < scopes[j].NodeId
	})
}
