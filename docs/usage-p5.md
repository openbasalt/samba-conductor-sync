# conductor-sync: operator guide (P5, P5b, P5c)

From an empty host to scheduled provisioning AD -> Google Workspace. No
secret appears in this document; replace `example.com` with your domains.

## 1. Google side (once)

1. In the Google Cloud console, create a project and a service account
   (no roles needed on the project). Create a JSON key for it and keep
   the file for step 3. Note the service account's client ID (numeric).
2. In the Admin console: Security > Access and data control > API controls
   > Domain-wide delegation > Add new: the client ID and these scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.user
   https://www.googleapis.com/auth/admin.directory.group
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/admin.directory.group.readonly
   ```
   `plan` uses only the read-only scopes; `apply` and `delete-user` use the
   two write scopes. Nothing else is requested.
3. Choose the administrator the service account acts as
   (`google.admin_subject`). A dedicated super admin account for the sync
   is recommended; the sync never suspends or renames administrators.
4. Create the org units you map AD OUs to (the sync does not create org
   units).

## 2. AD side (once)

Create an unprivileged account for the sync, e.g. `svc.sync` in a service
OU, with a long random password that does not expire. Plain Domain Users
rights are enough to read users, groups and members; never use an
administrator. (`conductor setup` will create it in a later phase.)

## 3. Install

Basalt OS and Fedora (RPM packages, SELinux): `install-fedora.md`.

(Samba 4.19 DCs, Ubuntu 24.04: see the `ldap server require strong auth`
note in conductor's install doc; Kerberos binds need it.)

From the Debian package (recommended; Debian 13, Ubuntu 26.04, Ubuntu 24.04
best effort). The project's APT repository is not published yet; until it
is, install the `.deb` of a release directly (`apt install
./conductor-sync_<version>_amd64.deb`, after checking it against the
release's signed `SHA256SUMS`). Once it is published, add it as conductor's
install doc shows (`/etc/apt/sources.list.d/samba-conductor.sources` with
`Signed-By:`), then:

```sh
apt install conductor-sync
install -m 0644 domain-ca.pem /etc/conductor-sync/domain-ca.pem
```

The package installs `/usr/bin/conductor-sync`, the four units in
`/usr/lib/systemd/system`, the man page and the conffile
`/etc/conductor-sync/conductor-sync.toml` (the example, `mode = "dry-run"`;
upgrades keep your edits); it creates the `conductor-sync` user,
`/etc/conductor-sync` (root:conductor-sync 0750) with `credentials/`
(conductor-sync 0700) and `/var/lib/conductor-sync`. It does not enable or
start anything. Continue with the credentials below and skip the unit
installation line. Upgrades restart the management API when it is running;
`apt purge conductor-sync` deletes `/etc/conductor-sync` (with the state
key) and `/var/lib/conductor-sync`.

From source:

```sh
useradd --system --user-group --home-dir /var/lib/conductor-sync --no-create-home --shell /usr/sbin/nologin conductor-sync
install -m 0755 conductor-sync /usr/local/bin/
install -d -m 0750 -o root -g conductor-sync /etc/conductor-sync
install -d -m 0700 -o conductor-sync -g conductor-sync /etc/conductor-sync/credentials
install -m 0644 domain-ca.pem /etc/conductor-sync/domain-ca.pem
install -m 0640 -o root -g conductor-sync conductor-sync.toml.example /etc/conductor-sync/conductor-sync.toml
```

Credentials (files 0600, owned by `conductor-sync`; the services get them
through `LoadCredential=`, manual runs read them from `credentials_dir`):

```sh
install -m 0600 -o conductor-sync -g conductor-sync /dev/null /etc/conductor-sync/credentials/ad-bind
# write the svc.sync password into it with an editor (not on a command line)
(umask 077; openssl rand -hex 32 >/etc/conductor-sync/credentials/state-key)
chown conductor-sync:conductor-sync /etc/conductor-sync/credentials/state-key
```

The state key encrypts the Google service account key, which is set once,
either in conductor (Google Workspace sync > Setup, §13) or here, then
stored encrypted in the state database and never shown again:

```sh
sudo -u conductor-sync conductor-sync key set service-account-key.json
shred -u service-account-key.json
```

(A key kept as a credential file still works: `google.key_credential =
"google-sa"` and `LoadCredential=google-sa:...` in the units; a stored key
wins over it.)

Edit `/etc/conductor-sync/conductor-sync.toml` (see the comments and
[`mapping.md`](mapping.md)). Keep `mode = "dry-run"`.

```sh
# source install only:
install -m 0644 deploy/systemd/conductor-sync.service deploy/systemd/conductor-sync.timer \
  deploy/systemd/conductor-sync-api.service deploy/systemd/conductor-sync-api.socket /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now conductor-sync-api.socket    # only with conductor's sync section (§13)
```

Manual commands run as the service user:

```sh
alias cs='sudo -u conductor-sync conductor-sync'
cs check-config     # credentials readable, key valid, AD scope counted
```

## 4. First plan (dry-run)

```sh
cs plan             # first 200 operations; --all for every one, --json for tooling
```

Read it: creates (with the address, names and org unit of each account),
warnings (duplicate addresses, existing accounts not managed by the sync,
skipped AD objects with the reason), and whether the plan is within the
safety limits. A first sync is normally far beyond `max_creates`; that is
expected, it is applied by hand once.

Iterate on the mapping until the plan is right. Plans are recorded:
`cs history` lists them.

## 5. First apply (manual)

Switch `mode = "apply"` in the configuration, then:

```sh
cs plan                                       # note the run number it prints
cs apply --plan RUN --override-limits         # applies only if the fresh plan is identical
```

`apply` shows the plan and asks you to type `override` (or `apply` when the
plan is within the limits). `--plan RUN` refuses if anything changed since
you reviewed run RUN. New accounts get a random password nobody knows and
must change it at first sign-in: use SSO (P4 SAML) or an admin reset to
give users access.

Existing Google accounts with the same address are not touched (warning
`unmanaged-exists`). To take them over, set `policy.adopt = "email"`: either
for one reviewed run, or for as long as AD users are being added to an
existing Workspace. Adopted accounts keep their org unit, address, password
and any name AD has no value for; see "Adopting an existing Google
Workspace" in [mapping.md](mapping.md#adopting-an-existing-google-workspace)
for every rule and its switch.

## 6. Schedule

```sh
systemctl enable --now conductor-sync.timer
```

Every 15 minutes the timer runs `apply --scheduled`: a fresh plan, applied
only when it is within `[limits]`. Otherwise the run stops, nothing is
written, the plan is recorded as `blocked`, an alert is sent and the unit
fails (exit 3). Review it with `cs plan`; if it is intended (a
reorganization), apply it by hand with `--override-limits`.

## 7. Day to day

| Command | Shows |
|---|---|
| `cs status` | mode, first manual apply, links, last runs, unfinished operations, audit chain |
| `cs history [--run RUN]` | runs; one run's journal (each operation's status and error) or its plan |
| `cs map [KEY]` | the link of an account or group: address, Google ID, AD objectGUID and DN, suspended by the sync |
| `cs audit verify` / `export` | chain check; JSON lines for archiving |

What AD changes do on Google:

| In AD | On Google |
|---|---|
| user created in scope | account created (random password, change at next sign-in) |
| name, title, department changed | mapped fields updated (only mapped fields) |
| logon name / mail changed (address template) | account renamed; Google keeps the old address as an alias |
| moved to another OU | org unit changed per `[[mapping.org_units]]` |
| moved out of the scope, filtered out, deleted | account suspended (never deleted) and removed from synced groups |
| disabled (or expired, by default) | account suspended; enabled again: unsuspended (only if the sync suspended it) |
| group membership changed | member added/removed in the synced group (nested groups mirrored as group members) |
| group renamed / out of scope | group address/name updated / group kept unchanged |

## 8. Deleting an account

Never automatic. Only an account the sync suspended, out of the AD scope,
suspended for at least `delete.min_suspended_days` (default 30):

```sh
cs delete-user former.employee@example.com     # shows the account, asks to type its address
```

Every attempt (refused or done) is in the audit log and sends an alert
when done. Google keeps deleted users restorable for about 20 days.

## 9. Recovery

- A run was interrupted (crash, reboot, kill): nothing to do. The next
  run marks it `interrupted`, re-plans from the real state and completes
  the work; accounts created just before the crash are recognized by their
  ownership marker (`user.relink`), groups by the journal (`group.relink`).
- Rate limits: requests are paced (`requests_per_second`) and retried
  with exponential backoff honouring `Retry-After`; if Google still
  throttles after `max_retries`, the run stops (partial) and the next one
  continues.
- Partial failures are reported per object (`cs history --run RUN`);
  memberships that depend on a failed create are skipped, not failed.
- State database lost: the next plan relinks every account through the
  marker (an adopted account also carries its adoption mark, so it keeps
  the adopted rules). Groups have no marker: run once with `adopt =
  "email"` after reviewing the plan; they are then treated as adopted
  (add-only members, see mapping.md).

## 10. Exit codes

| Code | Meaning |
|---|---|
| 0 | done (or nothing to do; or a scheduled run in dry-run mode) |
| 1 | error (configuration, credentials, AD or API unreachable, lock held) |
| 2 | usage |
| 3 | blocked: safety limits, or a scheduled run before the first manual apply |
| 4 | partial: some operations failed |
| 5 | not applied: confirmation declined, the reviewed plan changed, delete refused |
| 6 | manual apply in dry-run mode |

## 11. Alerts and metrics

- Alerts go to the journal always, and to `alert.webhook_url` as JSON
  (`kind`, `subject`, `text`, `run_id`, `host`), signed with HMAC-SHA256 in
  `X-Conductor-Signature` when `webhook_secret_credential` is set. Kinds:
  `blocked`, `partial`, `failed`, `interrupted`, `deleted`. The unit's
  `OnFailure=` can chain any other notifier.
- `metrics_file` (node_exporter textfile collector):
  `conductor_sync_last_run_timestamp_seconds{action,status}`,
  `conductor_sync_last_success_timestamp_seconds`, `conductor_sync_blocked`,
  `conductor_sync_source_users`, `conductor_sync_managed_users`,
  `conductor_sync_planned_ops{kind}`, `conductor_sync_ops_failed`,
  `conductor_sync_api_retries` and more. Alert on a stale last success.

## 12. Lab (development)

`scripts/synclab.sh` builds conductor-sync's own Samba lab on the lab host
(one DC, `sync.conductor.test`, 10.95.0.0/24, prefix `conductor-synclab`,
state in `~/conductor-synclab/state`), `scripts/lab-test.sh` runs the Go
lab tests and `scripts/lab-cli-e2e.sh` (the real binary against the lab AD
and `tools/fakegws`). Measured 2026-10-02 against 2,512 AD users and 12
groups (4,142 memberships, a 1,600-member group): source read 5.9 s,
initial apply of 6,664 operations against the fake API 16 s.

## 13. Managing the sync from conductor (P5b)

conductor's "Google Workspace sync" section (administrators only) drives
conductor-sync through its local management API, `conductor-sync serve`:

- `conductor-sync-api.socket` creates `/run/conductor-sync/api.sock`
  (owner conductor-sync, group conductor, 0660) and starts
  `conductor-sync-api.service` on the first connection. Every connection's
  peer is checked with SO_PEERCRED: only `api.allowed_users` (default
  `conductor`) is served. No network listener exists.
- In `/etc/conductor/conductor.toml`: `[sync] enabled = true` (socket
  `/run/conductor-sync/api.sock`), then restart conductor.
- What the API does: read and update the sync settings (validated, stored as
  versions with who changed what), set the service account key (write only,
  stored encrypted, only its e-mail and key ID are shown), test the AD and
  Google connections, preview the e-mail templates and org unit rules
  against real AD users, generate a plan, apply a reviewed plan by run ID and
  digest, "run now" with the scheduled rules, status, history, blocked runs,
  audit chain verification. Every change is in the audit log with the AD
  user conductor acted for (`conductor:<user>@<ip>`).
- conductor asks for a fresh second factor before every change, and for a
  typed confirmation bound to the plan's digest before an apply
  (`apply 1a2b3c4d`, or `override 1a2b3c4d` beyond the limits).
- The timer keeps working without the API; the API is only the way the web
  interface acts. Plans and applies started from the web run as background
  jobs inside `serve`; the run lock keeps them and the timer apart.

Settings edited in conductor are stored in the state database and override
the configuration file's sync settings (mode, `[source]` scope keys,
`[mapping]`, `[policy]`, `[limits]`, `google.customer`, `admin_subject`,
`member_role`, `schedule.interval`) and, since P5c, the connection settings
(§14). Host settings (state directory, credential names, `[api]`, the
Google API endpoints) stay in the file. From the command line:

| Command | Does |
|---|---|
| `cs config export` | the effective configuration as TOML (no secret) |
| `cs config history` | the stored versions: who, when, how many changes |
| `cs config import [FILE]` | make the sync settings of FILE (default: the configuration file) the newest version |
| `cs key set FILE` / `cs key show` | store the service account key encrypted / show its e-mail and key ID |
| `cs secret status` | each secret: configured or not, from the database or a credential file, when and by whom (never a value) |
| `cs secret set ad-bind-password` / `alert-webhook-secret` | store the value read from stdin, encrypted |
| `cs secret remove NAME` | drop a stored secret (the credential file, if any, is used again); `google-key` for the key |
| `cs serve` | the management API (normally started by the socket unit) |
| `cs check-config` | also says whether the sync settings come from the file or from a stored version |

Hosts without systemd timers (containers) set `schedule.in_process = true`:
`serve` then runs the scheduled applies itself every `schedule.interval`.

Group scope and placement (`include_groups`, `exclude_groups`, group rules
with priorities): see [`mapping.md`](mapping.md). Measured in the main lab
(2026-10-03, conductor-sync on dc1, 2 vCPU): a plan with 2,499 users in
scope through one include group and one group placement rule takes about
11 s; the first apply of 2,499 accounts to the fake API about 52 s.

Upgrading from P5: the service unit now loads `state-key` instead of
`google-sa`. Either create the state key and `key set` the existing key file
(then remove `google-sa` and its `LoadCredential=` line), or keep
`google.key_credential = "google-sa"` and add its `LoadCredential=` line
back to the units.


## 14. Connection settings and secrets from conductor (P5c)

conductor's Google Workspace sync > Settings > Connection page edits how
conductor-sync reaches AD and Google, the ownership marker and the alert
webhook, and replaces or removes the secrets. Decisions 38-43 in
[`decisions.md`](decisions.md).

- Editable: `[source]` realm, dcs, preferred, dns_servers, the CA content
  (`ca_pem`, pasted or uploaded; it wins over `ca_file`, and "use the host's
  CA file" goes back to the file), bind_user, auth; `[google]` customer,
  admin_subject, requests_per_second, max_retries, timeout, marker;
  `alert.webhook_url`. They are stored as settings versions like the sync
  settings. A version stored before P5c keeps the file's connection values
  until a new version is saved; `check-config` prints where they come from.
- Every change is a draft, tested (a sign-in to AD with the pinned CA and a
  read of the admin subject on Google with the stored key) before conductor
  offers to save it, previewed (every changed setting; the CA as a count and
  a short SHA-256), confirmed with the password and a fresh second factor,
  and audited in both audit logs. conductor-sync signs in to AD again with
  the new values before it stores an AD change.
- The ownership marker has its own form: a strong warning and the typed
  confirmation `change marker to <new marker>`, which conductor-sync checks
  too. Accounts carrying the previous marker are no longer recognized as the
  sync's own.
- Secrets are write only: the AD bind password, the Google service account
  key and the webhook HMAC secret. Pages and the API show whether each one
  is configured, from where (stored encrypted, or the credential file named
  in the configuration), when and by whom; never a value. A new bind
  password is stored only after a sign-in to AD with it. A stored secret wins
  over the credential file; removing it falls back to the file. The audit
  records the secret's name and `set`, `replaced` or `removed`.
- Rollback: Settings > history > "Roll back to this version" stores the
  settings of that version as a new version, after a preview and
  re-authentication (and the typed confirmation if the marker changes).
  Secrets are not versioned.
- The configuration file stays the bootstrap; `config export` renders the
  effective settings (the CA inline included, never a secret) and `config
  import` makes the file's settings the newest version.

Upgrading from P5b: the protocol version is 2; upgrade conductor and
conductor-sync together. Nothing else changes until a connection setting is
saved from conductor.
