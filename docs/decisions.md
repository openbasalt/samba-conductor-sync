# conductor-sync: decisions

Design decisions of conductor-sync, with their reasons. The design overview
is [design.md](design.md); family-wide design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).

## Architecture

1. No Google client library. The connector calls the half-dozen Admin
   SDK Directory endpoints (users list/get/insert/patch/delete, groups
   list/get/insert/patch, members list/insert/delete) and the OAuth token
   endpoint directly with `net/http`. The JWT bearer grant (RFC 7523) with
   domain-wide delegation is about 60 lines (RS256 with `crypto/rsa`).
   `google.golang.org/api` and `golang.org/x/oauth2` would add a large
   dependency tree for a handful of calls; the fake API also stays simple.
2. Connector interface = snapshot + typed operations. `Snapshot`,
   `CreateUser`, `UpdateUser`, `SetSuspended`, `CreateGroup`, `UpdateGroup`,
   `AddMember`, `RemoveMember`, `GetUser`, and `DeleteUser` (manual delete
   only). Entra ID (Graph), SCIM 2.0 and GitHub map onto the same verbs;
   the plan and the engine do not know which connector they drive.
3. Full reconciliation every run, no incremental AD reads. Each run
   reads the whole scope (2,512 users and 12 groups with 4,142 memberships:
   5.9 s in the lab) and the whole target. It is simpler and self-healing
   (drift on the target is corrected); uSNChanged/DirSync incremental reads
   can come later if large directories need them.
4. Identity is the AD objectGUID, stored as a link (SQLite) and as an
   ownership marker on the Google account (`externalIds` custom entry). DN,
   logon name and address are display data: renames and moves never break
   a link.
5. Deterministic plans with a digest. The plan is sorted (phase, key)
   and its operations hashed (SHA-256 over canonical JSON). `apply --plan
   RUN` / `--digest` refuses unless the fresh plan is identical to the
   reviewed one (Terraform-style "what you saw is what is applied").
6. Operation order: local relinks, renames (free addresses first),
   updates, unsuspends, creates, groups, member adds, member removes,
   suspensions last (an interrupted run leaves the fewest surprise
   suspensions).

## Safety

7. Dry-run is the default mode, and a scheduled run never applies
   before one successful manual apply (`first_manual_apply` in state).
8. Limits: 0 means "none allowed", -1 means "no limit" (a zero must
   never silently mean unlimited). Defaults: 50 creates, 10 suspends, 50
   unsuspends, 10 renames, 500 updates, 20 group changes, 1,000 membership
   changes, 10% of managed accounts touched, at least 1 source user, at
   most 10% source shrinkage since the last applied run. Small directories
   need a higher `max_touched_percent`. Manual applies may override with
   an explicit flag and a typed confirmation (`override`); the override is
   audited.
9. Ownership: the sync changes only accounts it links or that carry its
   marker. An existing account with the same address is reported, not
   taken over, unless `adopt = "email"`. A marker with a different
   objectGUID (an AD account deleted and recreated) is a conflict, not a
   takeover. Two instances on one tenant need different markers.
10. Suspension provenance: `suspended_by_sync` (and `suspended_at`) on
    the link. Google reports any API suspension as `ADMIN`, so the link is
    the only way to know who suspended; the sync never unsuspends what it
    did not suspend.
11. Protected accounts: Google administrators (`isAdmin`,
    `isDelegatedAdmin`) and the impersonated subject are never suspended or
    renamed by the sync (warning instead), so it cannot lock the tenant out.
12. Deletion exists only as `delete-user`: one account, linked, carrying
    the marker for that link, suspended by the sync for at least
    `min_suspended_days` (30), not in the AD scope at the time of the
    command, and confirmed by typing its exact address. Groups are never
    deleted.
13. Disabled and expired AD accounts are suspended and not created
    (`create_disabled = false`); accounts past `accountExpires` count as
    disabled (`expired_as_disabled = true`).
14. Unmanaged members of synced groups (external addresses, manual
    additions) are kept by default (`remove_unmanaged_members = false`).
15. Scopes: `plan` uses only the `.readonly` scopes, so a review can
    never write even through a bug; `apply` requests the write scopes.
16. Passwords: Google accounts get a 32-character random password,
    generated inside the connector, sent once, never logged or stored, with
    `changePasswordAtNextLogin`. Nobody knows it: access is SSO
    (conductor-idp SAML, P4) or an admin reset. Samba hashes are never
    synchronized.

## Resilience

17. Journal before and after every operation. `started` is committed
    before the request, `done`/`failed` after. A run left `running` is
    marked `interrupted` by the next run (which holds the lock, so it
    cannot be really running). Unknown outcomes are resolved by the next
    plan: users by the ownership marker (`user.relink`), groups (no marker
    on Google groups) by the journal's in-flight `group.create` with the
    same address (`group.relink`).
18. Ambiguous writes: a create retried after a timeout or 5xx that
    answers 409 is accepted only when the existing object is provably
    ours (users: marker with this objectGUID; groups: same address and
    name, and an earlier attempt of the same call may have reached Google).
19. Retries: 429, 5xx and 403 `rateLimitExceeded`/`userRateLimitExceeded`/
    `quotaExceeded` are retried with exponential backoff and full jitter
    (1 s doubling to 64 s, 6 retries), at least `Retry-After`; a 401
    refreshes the token once. Requests are paced (5/s default). Auth errors
    and exhausted rate limits stop the run (systemic); other failures are
    per object, up to `max_failures` (25).
20. One run at a time: `flock` on `state_dir/run.lock` for plan, apply
    and delete.

## Operations

21. Credentials: systemd `LoadCredential=` in the unit; manual runs
    (`sudo -u conductor-sync conductor-sync ...`) read the same names from
    `credentials_dir`, where files must be 0600. The configuration file
    holds no secret.
22. Alerts: always to the journal; optional JSON webhook signed with
    HMAC-SHA256 (https, or http to a loopback relay only). No SMTP client
    in conductor-sync: blocked/partial runs exit non-zero, so the unit's
    `OnFailure=` can chain any notifier (and conductor-backup already owns
    an SMTP sender if the family wants a shared one later).
23. Metrics: Prometheus textfile written atomically; no listener.
24. Timer: every 15 minutes (`OnUnitInactiveSec`), randomized 60 s.

## Testing

25. No real Workspace is written. `internal/fakegoogle` models users
    (aliases after rename, externalIds/organizations/phones, isAdmin),
    groups (aliases), members (USER/GROUP/EXTERNAL), org units, pagination,
    the JWT bearer grant with delegated-scope checks, and injected faults
    (status, reason, Retry-After, count, and "after commit" for ambiguous
    writes). `tools/fakegws` serves it on loopback for runs of the real
    binary.
26. Own lab: `scripts/synclab.sh` runs the family lab scripts patched
    to the prefix `conductor-synclab`, bridge `cndsync0`, `10.95.0.0/24`,
    domain `sync.conductor.test`, one DC, state in `~/conductor-synclab`
    on the lab host. The patches are verified (the script fails if a
    second-DC step survives). The shared `conductor-lab-*` VMs are never
    used.
27. govulncheck reports GO-2026-5932 (`golang.org/x/crypto/openpgp`,
    unmaintained, no fix) in a required module; conductor-sync does not
    import or call it.

## `ad` library: helpers implemented here, to upstream

The P5 rule was not to edit `ad`. These were done inside conductor-sync
(or only in its lab test) and belong in `ad`:

| Need | Where now | Proposed `ad` API |
|---|---|---|
| ~~Normalized DN key for map lookups~~ | upstreamed in P5b: `escape.NormalizeDN` (`adsource.DNKey` wraps it) | done |
| Typed user plus extra attributes in one search | `adsource` (Search + `UserFromEntry` + raw entry) | `Conn.UsersWithAttributes(ctx, base, filter, extra []string) iter.Seq2[UserEntry, error]` |
| Bulk member read of many groups (one ranged read per group today) | `adsource` loop over `GroupMembers` | `Conn.GroupMembersMany` or a member DN -> GUID resolver |
| Logon rename (sAMAccountName + userPrincipalName); `UpdateUser` covers profile attributes only | raw go-ldap modify in `internal/labtest` | `ad.RenameLogon(dn, sam, upn)` with preview and the old-value assertion |
| Incremental change tracking (uSNChanged high-water mark or DirSync control) | not implemented (full reads) | `Conn.ChangesSince(ctx, base, usn)` |
| Exclusion of critical system objects | filter in `adsource` | a reusable `escape` constant / `Users` option |

## Group-based scope and the management API (2026-10-03)

28. Groups decide the scope. `source.include_groups` (any of them,
    nested membership) and `source.exclude_groups` (exclusion wins);
    `require_group` stays as a one-item alias. Membership is read per
    referenced group with one `LDAP_MATCHING_RULE_IN_CHAIN` search below the
    user bases (objectGUID only), then decided in Go, so the same sets serve
    scope and placement. Primary-group membership (Domain Users) is not a
    `member` value and does not count.
29. Every referenced group must resolve. A group referenced by DN that
    was renamed or deleted, or a SID that no longer exists, stops the read
    ("referenced groups not found"): a missing include group must never look
    like "everybody left" (mass suspension), nor a missing exclude group
    like "everybody joined". The scheduled run fails and alerts instead. The
    web UI stores groups by SID, which survives renames and moves.
30. Placement order: group rules by explicit priority (1 first; a group
    rule without a priority is a configuration error), then the most specific
    container rule, then `default_org_unit`. Two matching group rules of the
    same best priority with different targets are a plan error for that
    user (`org-unit-ambiguous`): the user is left untouched (no create,
    update, suspension or membership removal) until fixed. Two rules of the
    same priority with the same target are not ambiguous and are accepted
    (the spec said "a plan error, never a silent pick"; no pick happens when
    both answers agree). One group may have only one rule.
31. Plan display fields (resolved groups with names and member counts,
    users left out by include/exclude groups, skipped objects, placement
    reasons) are stored with the plan but are not part of the digest; the
    digest still covers exactly the operations. An org unit change carries
    the rule that chose it in the operation's reason, which is part of the
    digest (a plan reviewed under one rule is not applied under another).
32. Management API = `conductor-sync serve` on a Unix socket, JSON lines,
    one request per connection, typed and allowlisted operations (package
    `syncapi`, the only package conductor imports). Peers are checked with
    SO_PEERCRED (default: the conductor user only); under systemd the socket
    comes from `conductor-sync-api.socket` (owner conductor-sync, group
    conductor, 0660) and the service runs with `PrivateUsers=no` (a private
    user namespace would show every peer as "nobody"). Plans and applies are
    background jobs, one at a time; the run lock still excludes the timer and
    the CLI. Timer-driven runs do not need the API.
33. Sync settings versus host settings. Settings an administrator edits
    in the UI (mode, scope, mapping, policy, limits, `google.customer`,
    `admin_subject`, `member_role`, `schedule.interval`) are stored as
    versions in SQLite (who, when, comment, changed paths) and the newest one
    overrides the file; the file is the bootstrap and `config export` renders
    the effective configuration in the same format (`config import` makes the
    file's settings the newest version again). Host settings (state and
    credentials, how AD and Google are reached, `api_base_url`/`token_url`,
    the ownership marker, alerts, `[api]`) stay file-only: they decide where
    data and credentials go, and a web session must not be able to redirect
    them. Updates carry the base version (optimistic concurrency).
34. The Google key at rest. `key.set` (API) and `key set FILE` (CLI)
    store the service account JSON key in SQLite encrypted with AES-256-GCM
    (key from the `state-key` systemd credential, 32 bytes; the secret's name
    is the additional data). It is never returned: only its client e-mail
    and key ID are shown and audited. `google.key_credential` (a file) still
    works and is used when no key is stored. The units load `state-key`
    instead of `google-sa`.
35. Manual applies through the API are bound to a reviewed plan: run ID
    and digest; conductor-sync re-plans and applies only if the fresh plan
    has that digest. conductor additionally asks for a typed confirmation
    that contains the first 8 characters of the digest (`apply 1a2b3c4d`, or
    `override 1a2b3c4d` beyond the limits) and a fresh second factor. "Run
    now" is a scheduled-style run (binding limits, first apply must have been
    manual).
36. In-process scheduler (`schedule.in_process`) for hosts without
    systemd timers (the Docker test environment); with the timer the status
    estimates the next run as the last scheduled run plus the interval.
37. Upstreamed to `ad`: `escape.NormalizeDN` (was `adsource.DNKey`).

The remaining helpers listed above are still local; the group-scope work
needed none of them.

## Connection settings and write-only secrets in the web UI (2026-10-03)

Decided 2026-10-03: the connection settings that decision 33 kept
file-only become editable through the management API (and conductor's
Settings > Connection page), with more safeguards than the sync settings.

38. Connection settings join the versioned settings. `Settings.connection`
    holds the AD realm, DCs, preferred DCs, DNS servers, the CA content
    (`source.ca_pem`, which wins over `ca_file`), the bind user and the
    authentication; the Google client tuning (`requests_per_second`,
    `max_retries`, `timeout`); the ownership marker; the alert webhook URL.
    `google.customer` and `admin_subject` were already editable. A version
    stored before P5c has no `connection` and keeps the file's values; from
    the first P5c version on, the stored values are in force (`config
    import` makes the file's the newest version again, `check-config` says
    where they come from). Still file-only: the state directory, the
    credential names, `[api]`, `google.api_base_url`/`token_url`/`ca_file`
    and the CA file path: they decide where state and credentials live and
    which Google endpoint gets the key, and only exist for tests and proxies.
    Supersedes the "host settings stay file-only" part of decision 33 for
    these keys.
39. An AD connection change is saved only after a sign-in with it.
    `config.update` and `config.rollback` that change how AD is reached (or
    carry a new bind password) run a sign-in (TLS with the pinned CA, then
    the bind) with the new values first and store nothing if it fails.
    conductor additionally requires a successful connection test of exactly
    the draft it saves (AD and/or Google, whichever part changed). Google
    changes are not re-tested by conductor-sync itself: the setup wizard
    sets the admin subject before the key may exist.
40. The ownership marker needs a typed confirmation,
    `change marker to <new marker>`, checked by conductor-sync on update and
    rollback (and by conductor, which shows a strong warning): accounts
    marked with the previous value are no longer recognized as owned.
41. Secrets are write only. The AD bind password and the webhook HMAC
    secret join the Google key in the encrypted `secrets` table
    (AES-256-GCM, state key, the secret's name as additional data):
    `secret.set` (the bind password only after a sign-in with it),
    `secret.remove`, and `ad_password` on `config.update` for a new bind
    account (stored in the same transaction as the version). Results and
    `config.get` carry only the state (configured, source database or
    credential file, the credential name, when and by whom); never a value
    or a fingerprint. The audit records `secret <name>: set|replaced|removed`.
    A stored secret wins over the credential file; removing it falls back to
    the file. `connection.test` accepts a bind password that is used for the
    test only.
42. Rollback = a new version with an earlier version's settings
    (`config.rollback`, origin `rollback`, the source version in the audit),
    with the same checks as an update. Secrets are not versioned and are not
    touched by a rollback.
43. Protocol version 2. Results are decoded strictly (unknown fields
    rejected), so the new fields make P5b clients incompatible; the version
    bump turns that into a clear `version` error. conductor and
    conductor-sync are upgraded together (the lab snapshot conductor-p2b now
    reinstalls both).

## Eventual consistency of the Google Directory API (2026-10-05)

Found in the first run against a real tenant; the fake answered every read
with the latest write, so the suites never saw it.

44. A member insert right after the group's create can answer 404
    (`Resource Not Found: groupKey`), and so can one for a user created
    seconds earlier. `AddMember` retries a 404 with the client's backoff
    (up to `max_retries`) before reporting the operation as failed.
45. `users.list` and `groups.list` lag behind writes: a user created by the
    previous run was missing from the list while `users.get` found it, and
    the plan proposed `user.unlink` plus a second `user.create`. Before
    planning, every linked object absent from the list is read directly by
    its ID (`users.get`, `groups.get` with members); only a 404 there means
    it was removed outside the sync. The cost is one read per missing link,
    normally zero. `internal/fakegoogle` can hide an object from lists
    (`HideFromList`) to test it.

## Adopting an existing Google Workspace (2026-10-05)

For a company that already has its users in Google and connects AD
gradually: an adopted account must keep working exactly as before, and
the sync only starts to follow it.

46. Adoption is recorded: `links.adopted` (migration 003) and an
    `externalIds` entry `<marker>-adopted` on the account, so the rules
    below survive a lost state database (a relink by marker carries the
    flag). Links made before this change count as created.
47. Safe defaults, each with a switch in `[policy]`: the org unit is kept
    (`adopted_org_unit = "keep"`), the primary address is never renamed
    and a differing AD address is a warning (`adopted_email = "keep"`),
    names and mapped fields are written only when AD has a value of its
    own (`adopted_names`, `adopted_attributes` = `if-set`; a value from a
    fallback template such as `{sAMAccountName}` does not count, and an
    empty AD value never clears), adopted groups are add-only
    (`adopted_group_members = "add-only"`, which also overrides
    `remove_unmanaged_members`). `manage` treats the object like a created
    one.
48. A disabled AD user never adopts an account (`disabled-not-adopted`):
    otherwise adoption would suspend a working account in the same run
    only because AD has it disabled. After adoption, disabling the AD user
    or leaving the scope suspends as for any managed account, and a
    suspension by someone else is never undone.
49. `delete-user` refuses adopted accounts.
50. Only `CreateUser` sends a password. The fake records the field names of
    every write and the tests assert that no other request carries
    `password` or `changePasswordAtNextLogin`; the connector can write the
    same field names (never values) to a request log
    (`CONDUCTOR_SYNC_REQUEST_LOG`) for audits against a real tenant.
51. The adopted rules travel in the management API as optional fields;
    defaults are sent as empty strings and an empty value in an update
    keeps the configuration file's value, so a conductor built before
    these fields keeps working (decision 43's strict decoding never sees
    them unless set).

## Import from Google Workspace (2026-10-05)

For a company that starts AD from scratch while it already lives in Google:
create the AD users and groups once from the Google directory, then let
the sync adopt the Google accounts by address. Details:
[import-from-google.md](import-from-google.md).

52. Privilege separation. conductor-sync only reads: `import.plan` (and
    `conductor-sync import-plan`) uses the read-only Directory API scopes,
    sends no write request to Google, records no run and needs no AD
    write right. conductor, which already holds AD write rights (the
    administrator's own credentials), enforces the password policy and
    audits every change, creates the AD objects as a bulk job with a full
    preview and re-authentication. No component gains a right for this
    feature.
53. No passwords. Google never returns them; the plan carries none. Each
    imported user gets a random 32-character password generated by
    conductor, sent once in the create request, never shown, logged or
    stored, with `pwdLastSet = 0`; the administrator sets an initial
    password when onboarding the person. Nothing is sent to Google, and
    the adoption that follows never sends a password (decision 50).
54. Filters fail closed: a Google group named by a filter that does not
    exist stops the read, like a missing scope group (decision 29).
55. Safe defaults: suspended accounts and Google administrators (the
    admin subject included) are left out unless asked for; accounts that
    already carry the sync's marker are always left out (they come from AD).
    Suspended accounts that are included are created disabled.
56. New accounts are enabled by default. With an unknown password and a
    forced change, an enabled account cannot be used by anyone, and only an
    enabled AD user adopts its Google account (decision 48); creating them
    disabled is the documented alternative, chosen per import.
57. Additive and idempotent. An AD object that already has the address
    (`mail`, `userPrincipalName` or an SMTP `proxyAddresses` entry) is never
    changed; an existing group only receives the plan's missing members, and
    a privileged group is never touched; logon names are never invented
    beyond the address's local part and one fallback template; a per-run
    limit bounds each job and running it again creates only what is
    missing. Nothing is deleted.
58. The operation was added without a protocol version change: it changes
    no existing request or result, an older conductor never sends it, and
    an older conductor-sync answers that it is not allowlisted. The answer
    is bounded (`max_users` 5,000, `max_groups` 1,000) and refused when it
    would exceed the 4 MiB message limit.

## Self-service: connected accounts (2026-10-05)

A signed-in user activates their own account on a target, or sets a new
password on it, from conductor's self-service. Details:
[self-service.md](self-service.md).

59. Generic capabilities. A connector that supports self-service implements
    an optional interface (`connector.SelfService`: capabilities, password
    rules, create with the user's password, set a password) and declares
    what it supports; the management API carries the capabilities and the
    rules, and conductor shows only what a target declares. Nothing in the
    protocol or in conductor names a Google type or field.
60. The actor is the user. The account operations take no user: they act on
    the request's actor, looked up in AD by SID with the scope rules of a
    full read (a one-user lookup that walks the user's groups upwards, about
    40 ms in the lab instead of seconds for the member lists of the scope
    groups). conductor cannot, even by mistake, act on someone else.
61. No stored password. Storing an initial password in an AD attribute was
    rejected (readable by authenticated users by default, in plain text in
    backups and replication). A generated password is returned once in the
    API result and shown once by conductor; a typed one crosses the socket
    once. Neither reaches the state database, the journal, the audit or a
    log; the request log records field names only. Tests search the state
    files and logs for the password.
62. `changePasswordAtNextLogin` is false for a self-service password: the
    user saw it (or chose it) and nobody else did, so a forced change only
    makes them pick another one right away. A run's create keeps true (its
    random password is never shown). Resets send only `password` and
    `changePasswordAtNextLogin`.
63. An activation is a run's plan, applied for one user. The plan is
    computed as for a sync run, with the user counted as activated, so the
    mapping, the scope and every address and ownership check are the same;
    only that user's create (and memberships in existing groups) is applied,
    journaled as a run of its own (action `activate`) under the run lock.
    It never adopts: an existing account with the address is left to the
    next run. The batch limits do not apply (one account); the rate limits
    do.
64. `activation = "self-service"` makes the runs skip the creation of users
    who did not activate theirs, reported as `pending-activation` warnings
    (not operations: the digest and the limits do not depend on them).
    Activations are recorded in the state database, so an activated user's
    account deleted outside the sync is created again by the runs.
65. Password resets are conservative by default: only accounts the sync
    created (`password_reset = "created"`); adopted accounts only with
    `created-and-adopted`; never target administrators or the sync's own
    subject, never a suspended account or one without the user's marker,
    never in dry-run mode. Rate limits per user and per target are kept in
    the state database, and conductor asks for a fresh second factor when
    the last one is older than a few minutes.
66. No protocol version change: three new operations and optional settings
    (`self_service` absent while every value is the default, as decision 51
    does for the adopted rules). An activation run does not supersede a plan
    under review and is never applicable from the runs page.
