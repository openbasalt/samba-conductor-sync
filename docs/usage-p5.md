# conductor-sync: operator guide (P5)

From an empty host to scheduled provisioning AD -> Google Workspace. No
secret appears in this document; replace `example.com` with your domains.

## 1. Google side (once)

1. In the Google Cloud console, create a project and a **service account**
   (no roles needed on the project). Create a **JSON key** for it and keep
   the file for step 3. Note the service account's **client ID** (numeric).
2. In the Admin console: Security > Access and data control > API controls
   > **Domain-wide delegation** > Add new: the client ID and these scopes:
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

```sh
useradd --system --user-group --home-dir /var/lib/conductor-sync --no-create-home --shell /usr/sbin/nologin conductor-sync
install -m 0755 conductor-sync /usr/local/bin/
install -d -m 0750 -o root -g conductor-sync /etc/conductor-sync
install -d -m 0700 -o conductor-sync -g conductor-sync /etc/conductor-sync/credentials
install -m 0644 domain-ca.pem /etc/conductor-sync/domain-ca.pem
install -m 0640 -o root -g conductor-sync conductor-sync.toml.example /etc/conductor-sync/conductor-sync.toml
```

Credentials (files 0600, owned by `conductor-sync`; the service gets them
through `LoadCredential=`, manual runs read them from `credentials_dir`):

```sh
install -m 0600 -o conductor-sync -g conductor-sync /dev/null /etc/conductor-sync/credentials/ad-bind
# write the svc.sync password into it with an editor (not on a command line)
install -m 0600 -o conductor-sync -g conductor-sync service-account-key.json /etc/conductor-sync/credentials/google-sa
shred -u service-account-key.json
```

Edit `/etc/conductor-sync/conductor-sync.toml` (see the comments and
[`mapping.md`](mapping.md)). Keep `mode = "dry-run"`.

```sh
install -m 0644 deploy/systemd/conductor-sync.service deploy/systemd/conductor-sync.timer /etc/systemd/system/
systemctl daemon-reload
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

Existing Google accounts with the same address are **not** touched (warning
`unmanaged-exists`). To take them over, set `policy.adopt = "email"` for one
reviewed run and set it back afterwards.

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
| moved out of the scope, filtered out, deleted | account **suspended** (never deleted) and removed from synced groups |
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

- **A run was interrupted** (crash, reboot, kill): nothing to do. The next
  run marks it `interrupted`, re-plans from the real state and completes
  the work; accounts created just before the crash are recognized by their
  ownership marker (`user.relink`), groups by the journal (`group.relink`).
- **Rate limits**: requests are paced (`requests_per_second`) and retried
  with exponential backoff honouring `Retry-After`; if Google still
  throttles after `max_retries`, the run stops (partial) and the next one
  continues.
- **Partial failures** are reported per object (`cs history --run RUN`);
  memberships that depend on a failed create are skipped, not failed.
- **State database lost**: the next plan relinks every account through the
  marker. Groups have no marker: run once with `adopt = "email"` after
  reviewing the plan.

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

`scripts/synclab.sh` builds conductor-sync's own Samba lab on server-home
(one DC, `sync.conductor.test`, 10.95.0.0/24, prefix `conductor-synclab`,
state in `~/conductor-synclab/state`), `scripts/lab-test.sh` runs the Go
lab tests and `scripts/lab-cli-e2e.sh` (the real binary against the lab AD
and `tools/fakegws`). Measured 2026-10-02 against 2,512 AD users and 12
groups (4,142 memberships, a 1,600-member group): source read 5.9 s,
initial apply of 6,664 operations against the fake API 16 s.
