# conductor-sync: design

`conductor-sync` provisions users and groups from Samba Active Directory
into another directory. Google Workspace (Admin SDK Directory API) is the
connector implemented. Sync is one way, AD to the target: AD is the source
of truth, every run computes a plan against the target's current state,
and the plan is applied only within safety limits. Accounts are never
deleted by a run; an account that leaves the scope is suspended. The
cross-cutting design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md#integration-components)
and packaging in
[packaging.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md).
Numbered choices and their reasons are in [decisions.md](decisions.md);
how AD attributes become Google fields is in [mapping.md](mapping.md).

## Pieces

| Part | Role |
|---|---|
| source (`adsource`) | reads AD with a read-only service account through the [ad library](https://github.com/openbasalt/samba-conductor-ad/blob/main/docs/design.md): LDAPS with the domain CA pinned, paged searches, ranged retrieval of large groups |
| model | connector-agnostic users, groups and memberships |
| mapping | templates, address rules, org unit placement ([mapping.md](mapping.md)) |
| plan | the diff between source and target: typed operations, warnings, a digest, the limit checks |
| engine | plan and apply runs: confirmation, journal, resume, manual deletion |
| connector | the target; `google` calls the Directory API directly (JWT bearer grant with domain-wide delegation, backoff) |
| store | SQLite: links, runs, plans, journal, settings versions, encrypted secrets, audit chain, run lock |
| management API | `conductor-sync serve` on a Unix socket for conductor (package `syncapi`) |

A connector implements a snapshot plus typed verbs (create, update,
suspend, group create and update, add and remove member, and a delete used
only by the manual command), so the plan and the engine do not depend on
the target.

## Scope

- Users below the configured OUs, optionally only members of include
  groups (any of them, nested) and never members of exclude groups
  (exclusion wins). Groups are referenced by DN or SID; SIDs survive
  renames and moves, and the web UI stores SIDs.
- Every referenced group must resolve. A renamed or deleted include group
  stops the read rather than looking like "everybody left" (a mass
  suspension); a missing exclude group would look like "everybody joined".
- Disabled AD accounts, and accounts past `accountExpires`, are suspended
  and never created. Critical system objects are excluded.
- Each run reads the whole scope and the whole target (full
  reconciliation): simpler than incremental reads and self-healing, since
  drift on the target is corrected. Incremental change tracking is not
  implemented.

## Identity and ownership

- Identity is the AD objectGUID, stored as a link in SQLite and as an
  ownership marker on the Google account (an `externalIds` custom entry).
  DNs, logon names and addresses are display data, so renames and moves
  never break a link.
- The sync changes only accounts it links or that carry its marker. An
  existing account with the same address is reported and left alone,
  unless adoption by e-mail is configured. An adopted account is marked
  as adopted (in the link and with a second `externalIds` entry, so a
  lost state database does not forget it) and keeps, by default, its org
  unit, its address, and every name or field AD has no value of its own
  for; adopted groups are add-only. A disabled AD user never adopts an
  account. The rules and their switches are in
  [mapping.md](mapping.md#adopting-an-existing-google-workspace). A marker with another
  objectGUID (an AD account deleted and recreated) is a conflict, never a
  takeover.
- Google administrators and the impersonated subject are never suspended
  or renamed. A suspension made by someone else is never undone (the link
  records who suspended). Members of synced groups that the sync does not
  manage are kept by default.

## Plan, then apply

- `plan` never writes and uses only the read-only API scopes, so a review
  cannot write even through a bug. `apply` re-plans with the write
  scopes.
- Plans are deterministic: operations sorted by phase and key and hashed
  (SHA-256 over canonical JSON). `apply --plan RUN` or `--digest` refuses
  unless the fresh plan is identical to the reviewed one. Display data
  (resolved groups, users left out, placement reasons) is stored with the
  plan but outside the digest; the rule that chose an org unit is part of
  the operation and therefore of the digest.
- Operation order: relinks, renames, updates, unsuspends, creates, groups,
  member additions, member removals, suspensions last, so an interrupted
  run leaves the fewest surprise suspensions.
- Org unit placement: group rules by explicit priority, then the most
  specific container rule, then the default org unit. Two matching group
  rules of the same best priority with different targets are a plan error
  for that user, who is then left untouched.

## Safety limits

- A new configuration is in `dry-run` mode: nothing is applied until an
  operator switches to `apply`. Scheduled runs stay blocked until one
  manual apply has succeeded.
- Scheduled runs apply only plans within `[limits]`: creates, suspends,
  unsuspends, renames, updates, group changes, membership changes, the
  share of managed accounts touched, a minimum source size, and the
  shrinkage of the source since the last applied run. A run beyond a limit
  stops, records the plan as blocked, alerts and exits with status 3. A
  limit of 0 means none allowed; -1 means no limit, so a zero never
  silently means unlimited.
- A manual apply may override the limits only with an explicit flag and a
  typed confirmation; the override is audited.

## Never delete

- An account that leaves the scope or AD is suspended; a group that
  leaves the scope is kept.
- Deletion is a separate command, `delete-user`, for one account only: it
  must be linked, carry the marker for that link, have been suspended by
  the sync for at least `min_suspended_days` (30 by default), be out of
  the AD scope at that moment, and be confirmed by typing its address.
  Adopted accounts (they existed before the sync) are never deleted by
  it. Groups are never deleted.

## Passwords

Passwords are not synchronized: Samba keeps only hashes that Google cannot
accept. New Google accounts get a random 32-character password generated
in the connector, sent once, never logged or stored, with a change
required at next sign-in. That create is the only request of a run that
carries a password: updates, adoptions, suspensions and renames never send
`password` or `changePasswordAtNextLogin`, so an existing or adopted
account keeps its password. Outside the runs, a user can activate their
account or set a new password from conductor's self-service (below); that
password is the user's own, sent once and never stored. The optional request log
(`CONDUCTOR_SYNC_REQUEST_LOG=<file>`: method, path, status and the names
of the body's top-level fields, never values) lets an operator verify it. The intended sign-in is SSO through the SAML
provider of
[conductor-idp](https://github.com/openbasalt/samba-conductor-idp/blob/main/docs/design.md),
or a Google administrator reset.

## Resilience

- Every operation is journaled before it is sent and after it returns. A
  run left running is marked interrupted by the next run, which resolves
  unknown outcomes from the fresh plan (users by the marker, groups by the
  journal's in-flight create). Re-running is always safe.
- A create retried after a timeout that answers "conflict" is accepted
  only when the existing object is provably the sync's own.
- Rate limits and server errors are retried with exponential backoff and
  jitter, honouring `Retry-After`; requests are paced. Authentication
  errors and exhausted rate limits stop the run; other failures are per
  object, up to a maximum.
- One run at a time: a file lock covers plan, apply and delete, for the
  timer, the CLI and the API alike.

## Management API (with conductor)

- `conductor-sync serve` listens on `/run/conductor-sync/api.sock`
  (systemd socket activation: owner conductor-sync, group conductor,
  0660) and checks the peer of every connection with `SO_PEERCRED`
  (default: the conductor user only).
- One request and one response per connection, each one JSON line (at
  most 4 MiB), a protocol version, typed allowlisted operations decoded
  strictly in both directions: status; configuration get, validate,
  update, history, export, version and rollback; key and secret set or
  remove; connection test; mapping preview against real AD users; plan
  and apply start; job, run and runs lookups; audit verify; the import
  plan and the self-service account operations (below).
- Every request carries the acting AD user from conductor. Mutations are
  written to conductor-sync's hash-chained audit log with that actor;
  conductor audits the same actions in its own log.
- Plans and applies are background jobs, one at a time. An apply through
  the API names the reviewed run and its digest; conductor-sync re-plans
  and applies only on the same digest. conductor additionally requires a
  typed confirmation with the first 8 characters of the digest and a
  fresh second factor.
- Settings versus host settings: what an administrator edits (mode,
  scope, mapping, policy, limits, Google customer and subject, schedule,
  and the AD and Google connection settings) is stored as versions in
  SQLite (who, when, what changed) and overrides the TOML file, which is
  the bootstrap and export format. Updates carry the base version
  (optimistic concurrency); a rollback is a new version. State and
  credential locations, the API socket and the Google endpoints stay in
  the file only, so a web session cannot redirect where data or
  credentials go.
- An AD connection change is saved only after a successful sign-in with
  it. Changing the ownership marker requires a typed confirmation.
- Timer-driven runs do not need the API.

## Import from Google Workspace

For a company whose AD starts empty while its people are in Google,
`import.plan` (and `conductor-sync import-plan`) reads the Google directory
with the read-only scopes and returns the accounts and groups that
conductor may create in AD, with filters (org units, group membership,
suspended accounts and administrators left out by default) and limits.
conductor-sync writes nothing anywhere for it; conductor creates the AD
objects (mail = the Google address) with the administrator's credentials,
after a preview, and the sync then adopts the Google accounts by address.
See [import-from-google.md](import-from-google.md).

## Google-first mode

The opposite direction, opt-in per installation: Google Workspace is the
source of truth for the people of each scope and AD follows. `g2a.plan`
(and `conductor-sync g2a-plan`) reads Google with the read-only scopes and
AD with the read-only account (privilege index included) and records a
plan of typed AD operations as a run of action `g2a`; conductor applies it
through conductor-provisioner and reports back with `g2a.confirm`.
conductor-sync never writes to Google or AD. Privileged AD accounts are
never touched, Google wins on the fields it owns, nothing is deleted, and
the two directions never share an OU tree or an org unit. See
[google-first.md](google-first.md).

## Self-service: connected accounts

conductor's self-service shows a signed-in user their own account on each
target and, when the target's connector supports it and the policy allows
it, lets them activate it (on-demand provisioning) or set a new password,
generated and shown once or typed by them. The management API operations
`account.status`, `account.activate` and `account.set_password` always act
on the request's actor, found in AD by SID. With `self_service.activation
= "self-service"` the runs create accounts only for users who activated
theirs; an activation applies, as a journaled run of its own, the create
that a run's plan computes for that user. Resets apply only to the user's
own linked account carrying the marker, never to target administrators,
and to adopted accounts only when the policy says so. Actions are rate
limited per user and per target, and audited in conductor and here without
any password. See [self-service.md](self-service.md).

## Secrets

- The AD bind password, the Google service account key and the webhook
  HMAC secret are write-only. Stored ones are sealed with AES-256-GCM
  under a `state-key` systemd credential (additional data: the secret's
  name); credential files remain an alternative. Results, logs and the
  audit carry only whether a secret is configured and where it comes
  from, never a value or fingerprint (for the Google key, its client
  e-mail and key ID).

## Operation

- systemd units: a oneshot service with a timer (every 15 minutes,
  randomized), and the API service with its socket.
- Alerts go to the journal and optionally to a signed webhook (https, or
  http to a loopback relay). Blocked and partial runs exit non-zero, so
  the unit's `OnFailure=` can chain any notifier.
- Metrics: a Prometheus textfile written atomically; no listener.
- Tests use a fake Directory API that models users, groups, members, org
  units, pagination, the JWT grant and injected faults. No real Workspace
  is written by tests; the connector is also exercised by hand against a
  real Google tenant.
