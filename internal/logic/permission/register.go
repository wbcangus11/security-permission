package permission

import (
	services "security-permission/internal/service"
)

func init() {
	services.Register(services.Provider{
		Runtime:    S.Runtime,
		Auth:       S.Permission,
		Role:       S.Roles,
		Delegation: S.Permission,
		User:       S.Users,
		Area:       S.Areas,
		Org:        S.Orgs,
		Resource:   S.Resources,
		View:       S.Views,
	})
}
