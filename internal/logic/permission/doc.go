// Package permission 提供用户权限加载、缓存和判断方法。
//
// 当前用户统一由 middleware.GetUserId(ctx) 从上下文读取，调用方不用再传 userID。
//
// 其他业务通常只需要先调用 ForUser，再用 Access 上的方法判断菜单或树范围：
//
//	access, err := permission.ForUser(ctx)
//	if err != nil {
//		return err
//	}
//	if err := access.RequireAnyMenu("sys.person.role"); err != nil {
//		return err
//	}
//
// 用户、角色和树结构写入后，要调用对应的 InvalidateUser、InvalidateUsers
// 或 InvalidateAll。当前包自己的写入口已经处理好了这些失效动作。
package permission
