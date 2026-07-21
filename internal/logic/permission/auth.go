package permission

import (
	"strings"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"security-permission/internal/model"
)

func isSuper(user *model.User) bool { return user != nil && user.IsSuperuser }

type decision struct {
	Allow  bool
	Reason string
}

func superDecision(what string) *decision {
	reason := "超级管理员拥有全部" + what
	return &decision{Allow: true, Reason: reason}
}

func roleHasMenuID(role *model.Role, menuID int) bool {
	for _, id := range role.MenuIds {
		if id == menuID {
			return true
		}
	}
	return false
}

func (e *evaluator) userHasMenuID(user *model.User, menuID int) bool {
	if isSuper(user) {
		return true
	}
	for _, role := range e.effectiveRoles(user) {
		if roleHasMenuID(role, menuID) {
			return true
		}
	}
	return false
}

func (e *evaluator) roleAllowsTree(scopes []model.DataScope, kind string, nodeID int) bool {
	targetPath := e.nodePath(kind, nodeID)
	if targetPath == "" {
		return false
	}
	for _, scope := range scopes {
		if scope.NodeId == nodeID {
			return true
		}
		if scope.IncludeChild {
			if path := e.nodePath(kind, scope.NodeId); path != "" && strings.HasPrefix(targetPath, path) {
				return true
			}
		}
	}
	return false
}

func (e *evaluator) userResourceAreaCovers(user *model.User, areaID int) bool {
	if isSuper(user) {
		return true
	}
	for _, role := range e.effectiveRoles(user) {
		if e.roleAllowsTree(role.ResourceAreaScopes, treeKindArea, areaID) {
			return true
		}
	}
	return false
}

func (e *evaluator) checkMenu(user *model.User, menuCode string) *decision {
	if isSuper(user) {
		return superDecision("功能权限")
	}
	decision := &decision{}
	menu := e.menuByCode(menuCode)
	if menu == nil {
		decision.Reason = "菜单不存在：" + menuCode
		return decision
	}
	if e.userHasMenuID(user, menu.Id) {
		decision.Allow = true
		decision.Reason = "用户有效角色包含菜单“" + menu.Name + "”"
		return decision
	}
	decision.Reason = "没有有效角色授予菜单“" + menu.Name + "”"
	return decision
}

func (e *evaluator) hasAnyMenu(user *model.User, menuCodes ...string) bool {
	if user == nil || e.err != nil {
		return false
	}
	for _, menuCode := range menuCodes {
		if e.checkMenu(user, menuCode).Allow {
			return true
		}
		if e.err != nil {
			return false
		}
	}
	return false
}

// requireAnyMenu 是服务入口的功能权限门。数据范围决定“能看哪些数据”，
// 菜单权限决定“能否使用这个接口”；两者必须同时满足。
func (e *evaluator) requireAnyMenu(user *model.User, menuCodes ...string) error {
	if e.err != nil {
		return e.err
	}
	if user == nil {
		return gerror.NewCode(gcode.CodeNotAuthorized, "当前用户不存在或已失效")
	}
	if e.hasAnyMenu(user, menuCodes...) {
		return e.err
	}
	if e.err != nil {
		return e.err
	}
	return gerror.NewCode(gcode.CodeNotAuthorized, "功能权限不足")
}

// checkTree 判断用户是否拥有某棵业务树中指定节点的数据权限。
//
// 参数说明：
//   - user：当前被鉴权的用户；
//   - nodeID：目标区域或组织节点 ID；
//   - kind：树类型，area=后台区域、resarea=视频监控区域、org=组织；
//
// 角色权限在保存后独立生效，created_by 只记录创建人，不参与运行时鉴权。
// 判定结果采用“默认拒绝”：只有用户当前绑定角色的已保存范围覆盖目标节点时，才返回 Allow=true。
func (e *evaluator) checkTree(user *model.User, nodeID int, kind string) *decision {
	// 第 1 步：超级管理员不受树范围限制，直接放行。
	if isSuper(user) {
		return superDecision("数据权限")
	}

	// 第 2 步：先读取目标节点的物化路径。区域和组织的 path 都类似 /1/3/4/，
	// 后续用路径前缀即可判断目标是否位于某个已授权节点的子树中。
	decision := &decision{}
	targetPath := e.nodePath(kind, nodeID)
	if targetPath == "" {
		// 查不到路径表示目标节点不存在；不存在的目标按拒绝处理。
		decision.Reason = "目标节点不存在"
		return decision
	}

	// 第 3 步：遍历用户绑定的所有可读取角色。任意一个角色满足条件即可放行。
	for _, role := range e.effectiveRoles(user) {
		// 第 4 步：根据树类型选择角色中对应的数据范围，三个权限域不能混用。
		var scopes []model.DataScope
		switch kind {
		case treeKindOrg:
			// 组织管理使用 ORG 范围。
			scopes = role.OrgScopes
		case treeKindResArea:
			// 视频监控应用使用 RES_AREA 范围。
			scopes = role.ResourceAreaScopes
		default:
			// 后台区域管理使用 AREA 范围。
			scopes = role.AreaScopes
		}

		// 第 5 步：逐条判断该角色的数据范围是否覆盖目标节点。
		for _, scope := range scopes {
			// 精确授权：授权节点就是目标节点时，无论 includeChild 是否开启都覆盖目标自身。
			covered := scope.NodeId == nodeID
			if !covered && scope.IncludeChild {
				// 子树授权：includeChild=true 时，目标 path 以授权节点 path 开头即表示
				// 目标位于其子树中。path 的每一级都带“/”，可避免节点 1 和 10 误匹配。
				path := e.nodePath(kind, scope.NodeId)
				covered = path != "" && strings.HasPrefix(targetPath, path)
			}
			if !covered {
				// 当前范围不覆盖目标，继续检查该角色的下一条范围。
				continue
			}

			// 第 6 步：角色的已保存范围覆盖目标，鉴权成功并立即返回。
			// 创建人的权限变化或账号删除不会在这里反向修改该角色。
			decision.Allow = true
			decision.Reason = "角色“" + role.Name + "”的数据范围覆盖目标节点"
			return decision
		}
	}

	// 第 7 步：所有角色及其范围都检查完仍未命中，按默认拒绝返回。
	decision.Reason = "没有有效角色的数据范围覆盖目标节点"
	return decision
}

func (e *evaluator) checkResource(user *model.User, resourceID int, actionCode string) *decision {
	if isSuper(user) {
		return superDecision("业务资源操作权限")
	}
	decision := &decision{}
	action, ok := resourceAction(actionCode)
	if !ok {
		decision.Reason = "未知资源操作：" + actionCode
		return decision
	}
	menuDecision := e.checkMenu(user, action.MenuCode)
	if !menuDecision.Allow {
		decision.Reason = "功能权限不足：" + menuDecision.Reason
		return decision
	}
	resource := e.resource(resourceID)
	if resource == nil {
		decision.Reason = "资源不存在"
		return decision
	}
	if !e.userResourceAreaCovers(user, resource.AreaId) {
		decision.Reason = "资源不在任何有效视频监控区域范围内"
		return decision
	}
	decision.Allow = true
	decision.Reason = "视频监控区域范围覆盖资源“" + resource.Name + "”，允许“" + action.Name + "”"
	return decision
}
