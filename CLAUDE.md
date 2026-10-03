# conductor-sync — Guidelines

Provisioning from Samba AD to other directories: Google Workspace first (Directory API), then Microsoft Entra ID, SCIM 2.0 and GitHub. Plan-then-apply, never deletes, safety limits.

- Read `../CLAUDE.md` (family rules) and `../planning/docs/architecture.md`.
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
- Tests never write to a real Google Workspace: use `internal/fakegoogle` (and `tools/fakegws` for the real binary).
- Lab: conductor-sync has its own (`scripts/synclab.sh`, prefix `conductor-synclab`, 10.95.0.0/24, state in `~/conductor-synclab` on server-home); never use the shared `conductor-lab-*` VMs. `make lab-test` resets it to `seeded` before and after.
- Safety rules (dry-run default, limits, never delete, ownership marker, journal/resume) are documented in `docs/decisions.md`; keep them when changing the engine.
