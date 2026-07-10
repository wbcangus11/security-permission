# Codex Project Context

This repository is a GoFrame v2 RBAC + data-permission demo that imitates Hikvision/iSecure Center permission behavior.

Before changing code, read these files in order:

1. `CLAUDE.md` - current project state, non-negotiable design decisions, known environment issues, and recent iteration notes.
2. `docs/权限设计说明.md` - plain-language design model.
3. `docs/设计导读.md` - recommended reading path through the codebase.
4. `docs/测试报告.md` - behavior dictionary and verified scenarios.
5. `docs/海康对照.md` - real iSecure Center comparison and why the current model is shaped this way.

Core model:

- Permissions are assigned to roles, not directly to users.
- Every access decision combines function permission(menu) and data permission(tree/resource scope).
- Superuser (`user.is_superuser`) bypasses all checks and owns current and future permissions.
- Tree permissions store `{node, include_child}` and use materialized `path` prefix matching instead of expanded descendants.
- Business resource permission currently uses resource-area scope only; resources in scope inherit all actions.
- Controlled delegation uses model A: write-time validation plus merge preservation, no cascading shrink.
- Explicit role scope (model B) is intentionally disabled; ordinary users work with self-created roles only.
- Editable/deletable roles are only self-created roles, except unrestricted actor or superuser.
- `created_by` is set only on role creation and must not be overwritten on edit.

Important implementation anchors:

- `internal/model/permission.go` - domain model.
- `internal/service/permission.go` - GoFrame-style business interfaces and implementation registry.
- `internal/logic/permission/auth.go` - read-only authorization checks.
- `internal/logic/permission/delegation.go` - grantable set and delegated merge.
- `internal/logic/permission/role.go` - edit/delete role guard and deletion cleanup.
- `internal/logic/permission/paging.go` - compact scope filtering, lazy tree loading, and search.
- `internal/middleware/identity.go` - request actor boundary; HTTP can never use maintenance actor `"0"`.
- `internal/controller/perm/perm.go` - HTTP API surface.
- `resource/public/index.html` - single-page frontend, no build step.

Run locally:

```bash
go run ./tools/dbinit
go run main.go
```

Then open `http://127.0.0.1:8000/`.

Operational notes:

- The user explicitly said not to commit automatically. Only run `git commit` after the user asks.
- The worktree may already be dirty; preserve user changes and do not revert unrelated edits.
- Windows console may display Chinese JSON as mojibake; source files are UTF-8.
- If port 8000 is occupied, kill the old process before trusting browser or curl results.
- Major changes should at least run targeted `go test`/`go build`; broad verification is only needed when the user asks.
