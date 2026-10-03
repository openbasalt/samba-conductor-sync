# conductor-sync

Provisioning from Samba AD to other directories. Google Workspace is the
first connector (Admin SDK Directory API); Microsoft Entra ID, SCIM 2.0 and
GitHub fit the same connector interface later.

Part of Samba Conductor v2. Design: `../planning/docs/architecture.md` §6,
phase spec: `../planning/docs/p5-spec.md`.

## What it does

- Reads users and groups from AD with a **read-only service account**
  (the `ad` library: LDAPS with the domain CA pinned, Kerberos or simple
  bind, paged searches, ranged retrieval of large groups), below the
  configured OUs, optionally only members of include groups and never
  members of exclude groups (nested membership, groups by DN or SID).
- Maps them to the target: address templates with fallbacks and an allowed
  domain list, names, optional attributes, Google org unit by AD group (with
  priorities) or by AD OU.
- Computes a **plan** against the target's current state and the recorded
  links (AD objectGUID to target ID): create, update, rename, suspend,
  unsuspend, group create/update, add/remove member. Shows it, records it,
  checks the **safety limits**, then applies it one journaled operation at
  a time.

## Safety rules

| Rule | How |
|---|---|
| Plan first | `plan` never writes (and uses read-only API scopes). `apply` re-plans, can be pinned to a reviewed plan (`--plan RUN`), and asks for confirmation |
| Dry-run by default | a new configuration has `mode = "dry-run"`: nothing is applied until the operator switches to `apply` |
| First apply is manual | scheduled runs stay blocked until an operator applied once by hand |
| Safety limits | scheduled runs apply only plans inside `[limits]` (creates, suspends, renames, updates, memberships, % of accounts touched, source shrinkage, empty source); otherwise the run stops, records the plan as blocked, alerts and exits 3 |
| Never delete | an account that leaves the scope (or the AD) is suspended; a group that leaves the scope is kept. Deletion is `delete-user`: one account, suspended by the sync for at least `min_suspended_days`, out of the AD scope, confirmed by typing its address |
| Only what it owns | accounts carry an ownership marker (`externalIds`, customType `conductor-sync`); an existing account with the same address is reported and left alone unless `adopt = "email"`; administrators are never suspended or renamed; a suspension made by someone else is never undone; members the sync does not manage stay in synced groups |
| Idempotent, resumable | every operation is journaled before and after it is sent; a crashed run is detected by the next one, and the fresh plan resolves the unknown outcomes (marker, in-flight creates). Re-running is always safe |
| Audit | every run, operation, blocked plan and deletion goes to a hash-chained audit log (`audit verify`) |
| Secrets | the AD password is a systemd credential (or 0600 file); the Google key is stored encrypted (AES-256-GCM, key from the `state-key` credential) or kept as a credential file; never logged, never returned by the API. Initial Google passwords are random, never stored, and must be changed at first sign-in (or SSO, below) |
| Management API | `conductor-sync serve` on a Unix socket for conductor only (SO_PEERCRED), typed operations, every change audited with the acting AD user; applies bound to a reviewed plan's digest |

Passwords are **not** synchronized: Samba keeps only hashes that Google
cannot accept. The intended sign-in is SSO through `conductor-idp`'s SAML
provider (phase P4); until then users get a password from a Google admin
reset.

## Commands

```
conductor-sync plan [--all] [--json]
conductor-sync apply [--plan RUN | --digest SHA256] [--yes] [--override-limits] [--scheduled]
conductor-sync status
conductor-sync history [--limit N] [--run RUN]
conductor-sync map [--kind user|group] [KEY]
conductor-sync delete-user KEY [--confirm ADDRESS]
conductor-sync audit verify|export
conductor-sync check-config
conductor-sync serve
conductor-sync config export | import [FILE] | history
conductor-sync key set FILE | show
```

Operator guide: [`docs/usage-p5.md`](docs/usage-p5.md) (§13: the
management API and conductor's sync section). Mapping reference:
[`docs/mapping.md`](docs/mapping.md). Decisions:
[`docs/decisions.md`](docs/decisions.md). Configuration example:
[`conductor-sync.toml.example`](conductor-sync.toml.example). systemd:
[`deploy/systemd/`](deploy/systemd/).

## Layout

| Package | What |
|---|---|
| `cmd/conductor-sync` | CLI, `serve` |
| `syncapi` | the management API protocol and client (the only package conductor imports) |
| `internal/api` | the management API server: socket, peer check, operations, background jobs, in-process scheduler |
| `internal/app` | wiring shared by the CLI and the API: effective configuration, stored key, engines |
| `internal/secretbox` | AES-256-GCM for secrets at rest (the Google key) |
| `internal/engine` | plan and apply runs: limits, confirmation, journal, resume, delete |
| `internal/plan` | the diff: operations, warnings, digest, safety limits |
| `internal/model` | connector-agnostic users, groups, members |
| `internal/source/adsource` | AD reader (scope, mapping, members) |
| `internal/mapping` | templates, address validation, OU mapping |
| `internal/connector` | connector interface; `google`: Directory API client (JWT bearer with domain-wide delegation, backoff, merges) |
| `internal/store` | SQLite state: links, runs, plans, journal, audit chain, run lock, settings versions, encrypted secrets |
| `internal/fakegoogle` | fake Directory API used by every test (no real Workspace is ever written) |
| `internal/alert`, `internal/metrics` | webhook and log alerts; Prometheus textfile |
| `tools/fakegws` | the fake as a loopback server, for lab runs of the real binary |

## Development

```sh
make test        # unit and integration tests against the fake API (race detector)
make check       # gofmt, vet, staticcheck, govulncheck, tests
make fuzz        # template fuzzer
make lab-test    # Samba AD lab on the lab host + fake API (scripts/lab-test.sh)
make package     # dist/: .deb for amd64 and arm64, SBOMs
make lintian     # Debian 13's lintian on dist/*.deb
```

The lab is conductor-sync's own (`scripts/synclab.sh`: the family lab
scripts under the prefix `conductor-synclab`, network `10.95.0.0/24`, domain
`sync.conductor.test`, one DC), so it never touches the shared
`conductor-lab-*` VMs.

## Status

P5 (2026-10-02): engine, Google connector, CLI, systemd units, tests (unit,
fake API, Samba AD lab end to end). P5b (2026-10-03): scope and org unit
placement by AD group, the management API, and the "Google Workspace sync"
section of conductor (<https://github.com/openbasalt/samba-conductor/blob/main/docs/usage-p5b.md>). Not yet tested
against a real Google Workspace (read-only check pending a test tenant).

License: Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
