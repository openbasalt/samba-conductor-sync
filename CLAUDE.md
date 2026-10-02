# conductor-sync — Guidelines

Provisioning from Samba AD to other directories: Google Workspace first (Directory API), then Microsoft Entra ID, SCIM 2.0 and GitHub. Plan-then-apply, never deletes, safety limits.

- Read `../CLAUDE.md` (family rules) and `../planning/docs/architecture.md`.
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
