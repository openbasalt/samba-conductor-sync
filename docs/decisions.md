# conductor-sync: decisions

Decisions taken while building P5 (2026-10-02, implementation agent; to be
reviewed by the owner). Family-wide decisions live in
`../planning/docs/decisions.md`; this file is conductor-sync's own while P3
and P4 edit the planning repository in parallel.

## Architecture

1. **No Google client library.** The connector calls the half-dozen Admin
   SDK Directory endpoints (users list/get/insert/patch/delete, groups
   list/get/insert/patch, members list/insert/delete) and the OAuth token
   endpoint directly with `net/http`. The JWT bearer grant (RFC 7523) with
   domain-wide delegation is about 60 lines (RS256 with `crypto/rsa`).
   `google.golang.org/api` and `golang.org/x/oauth2` would add a large
   dependency tree for a handful of calls; the fake API also stays simple.
2. **Connector interface = snapshot + typed operations.** `Snapshot`,
   `CreateUser`, `UpdateUser`, `SetSuspended`, `CreateGroup`, `UpdateGroup`,
   `AddMember`, `RemoveMember`, `GetUser`, and `DeleteUser` (manual delete
   only). Entra ID (Graph), SCIM 2.0 and GitHub map onto the same verbs;
   the plan and the engine do not know which connector they drive.
3. **Full reconciliation every run, no incremental AD reads.** Each run
   reads the whole scope (2,512 users and 12 groups with 4,142 memberships:
   5.9 s in the lab) and the whole target. It is simpler and self-healing
   (drift on the target is corrected); uSNChanged/DirSync incremental reads
   can come later if large directories need them.
4. **Identity is the AD objectGUID**, stored as a link (SQLite) and as an
   ownership marker on the Google account (`externalIds` custom entry). DN,
   logon name and address are display data: renames and moves never break
   a link.
5. **Deterministic plans with a digest.** The plan is sorted (phase, key)
   and its operations hashed (SHA-256 over canonical JSON). `apply --plan
   RUN` / `--digest` refuses unless the fresh plan is identical to the
   reviewed one (Terraform-style "what you saw is what is applied").
6. **Operation order**: local relinks, renames (free addresses first),
   updates, unsuspends, creates, groups, member adds, member removes,
   suspensions last (an interrupted run leaves the fewest surprise
   suspensions).

## Safety

7. **Dry-run is the default mode**, and a scheduled run never applies
   before one successful manual apply (`first_manual_apply` in state).
8. **Limits**: 0 means "none allowed", -1 means "no limit" (a zero must
   never silently mean unlimited). Defaults: 50 creates, 10 suspends, 50
   unsuspends, 10 renames, 500 updates, 20 group changes, 1,000 membership
   changes, 10% of managed accounts touched, at least 1 source user, at
   most 10% source shrinkage since the last applied run. Small directories
   need a higher `max_touched_percent`. Manual applies may override with
   an explicit flag and a typed confirmation (`override`); the override is
   audited.
9. **Ownership**: the sync changes only accounts it links or that carry its
   marker. An existing account with the same address is reported, not
   taken over, unless `adopt = "email"`. A marker with a different
   objectGUID (an AD account deleted and recreated) is a conflict, not a
   takeover. Two instances on one tenant need different markers.
10. **Suspension provenance**: `suspended_by_sync` (and `suspended_at`) on
    the link. Google reports any API suspension as `ADMIN`, so the link is
    the only way to know who suspended; the sync never unsuspends what it
    did not suspend.
11. **Protected accounts**: Google administrators (`isAdmin`,
    `isDelegatedAdmin`) and the impersonated subject are never suspended or
    renamed by the sync (warning instead), so it cannot lock the tenant out.
12. **Deletion** exists only as `delete-user`: one account, linked, carrying
    the marker for that link, suspended by the sync for at least
    `min_suspended_days` (30), not in the AD scope at the time of the
    command, and confirmed by typing its exact address. Groups are never
    deleted.
13. **Disabled and expired AD accounts** are suspended and not created
    (`create_disabled = false`); accounts past `accountExpires` count as
    disabled (`expired_as_disabled = true`).
14. **Unmanaged members** of synced groups (external addresses, manual
    additions) are kept by default (`remove_unmanaged_members = false`).
15. **Scopes**: `plan` uses only the `.readonly` scopes, so a review can
    never write even through a bug; `apply` requests the write scopes.
16. **Passwords**: Google accounts get a 32-character random password,
    generated inside the connector, sent once, never logged or stored, with
    `changePasswordAtNextLogin`. Nobody knows it: access is SSO
    (conductor-idp SAML, P4) or an admin reset. Samba hashes are never
    synchronized.

## Resilience

17. **Journal before and after every operation.** `started` is committed
    before the request, `done`/`failed` after. A run left `running` is
    marked `interrupted` by the next run (which holds the lock, so it
    cannot be really running). Unknown outcomes are resolved by the next
    plan: users by the ownership marker (`user.relink`), groups (no marker
    on Google groups) by the journal's in-flight `group.create` with the
    same address (`group.relink`).
18. **Ambiguous writes**: a create retried after a timeout or 5xx that
    answers 409 is accepted only when the existing object is provably
    ours (users: marker with this objectGUID; groups: same address and
    name, and an earlier attempt of the same call may have reached Google).
19. **Retries**: 429, 5xx and 403 `rateLimitExceeded`/`userRateLimitExceeded`/
    `quotaExceeded` are retried with exponential backoff and full jitter
    (1 s doubling to 64 s, 6 retries), at least `Retry-After`; a 401
    refreshes the token once. Requests are paced (5/s default). Auth errors
    and exhausted rate limits stop the run (systemic); other failures are
    per object, up to `max_failures` (25).
20. **One run at a time**: `flock` on `state_dir/run.lock` for plan, apply
    and delete.

## Operations

21. **Credentials**: systemd `LoadCredential=` in the unit; manual runs
    (`sudo -u conductor-sync conductor-sync ...`) read the same names from
    `credentials_dir`, where files must be 0600. The configuration file
    holds no secret.
22. **Alerts**: always to the journal; optional JSON webhook signed with
    HMAC-SHA256 (https, or http to a loopback relay only). No SMTP client
    in conductor-sync: blocked/partial runs exit non-zero, so the unit's
    `OnFailure=` can chain any notifier (and conductor-backup already owns
    an SMTP sender if the family wants a shared one later).
23. **Metrics**: Prometheus textfile written atomically; no listener.
24. **Timer**: every 15 minutes (`OnUnitInactiveSec`), randomized 60 s.

## Testing

25. **No real Workspace is written.** `internal/fakegoogle` models users
    (aliases after rename, externalIds/organizations/phones, isAdmin),
    groups (aliases), members (USER/GROUP/EXTERNAL), org units, pagination,
    the JWT bearer grant with delegated-scope checks, and injected faults
    (status, reason, Retry-After, count, and "after commit" for ambiguous
    writes). `tools/fakegws` serves it on loopback for runs of the real
    binary.
26. **Own lab**: `scripts/synclab.sh` runs the family lab scripts patched
    to the prefix `conductor-synclab`, bridge `cndsync0`, `10.95.0.0/24`,
    domain `sync.conductor.test`, one DC, state in `~/conductor-synclab`
    on the lab host. The patches are verified (the script fails if a
    second-DC step survives). The shared `conductor-lab-*` VMs are never
    used.
27. **govulncheck** reports GO-2026-5932 (`golang.org/x/crypto/openpgp`,
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

## P5b: group-based scope and the management API (2026-10-03)

Implementation agent; to be reviewed by the owner.

28. **Groups decide the scope.** `source.include_groups` (any of them,
    nested membership) and `source.exclude_groups` (exclusion wins);
    `require_group` stays as a one-item alias. Membership is read per
    referenced group with one `LDAP_MATCHING_RULE_IN_CHAIN` search below the
    user bases (objectGUID only), then decided in Go, so the same sets serve
    scope and placement. Primary-group membership (Domain Users) is not a
    `member` value and does not count.
29. **Every referenced group must resolve.** A group referenced by DN that
    was renamed or deleted, or a SID that no longer exists, stops the read
    ("referenced groups not found"): a missing include group must never look
    like "everybody left" (mass suspension), nor a missing exclude group
    like "everybody joined". The scheduled run fails and alerts instead. The
    web UI stores groups by SID, which survives renames and moves.
30. **Placement order**: group rules by explicit priority (1 first; a group
    rule without a priority is a configuration error), then the most specific
    container rule, then `default_org_unit`. Two matching group rules of the
    same best priority with **different** targets are a plan error for that
    user (`org-unit-ambiguous`): the user is left untouched (no create,
    update, suspension or membership removal) until fixed. Two rules of the
    same priority with the same target are not ambiguous and are accepted
    (the spec said "a plan error, never a silent pick"; no pick happens when
    both answers agree). One group may have only one rule.
31. **Plan display fields** (resolved groups with names and member counts,
    users left out by include/exclude groups, skipped objects, placement
    reasons) are stored with the plan but are not part of the digest; the
    digest still covers exactly the operations. An org unit change carries
    the rule that chose it in the operation's reason, which is part of the
    digest (a plan reviewed under one rule is not applied under another).
32. **Management API = `conductor-sync serve`** on a Unix socket, JSON lines,
    one request per connection, typed and allowlisted operations (package
    `syncapi`, the only package conductor imports). Peers are checked with
    SO_PEERCRED (default: the conductor user only); under systemd the socket
    comes from `conductor-sync-api.socket` (owner conductor-sync, group
    conductor, 0660) and the service runs with `PrivateUsers=no` (a private
    user namespace would show every peer as "nobody"). Plans and applies are
    background jobs, one at a time; the run lock still excludes the timer and
    the CLI. Timer-driven runs do not need the API.
33. **Sync settings versus host settings.** Settings an administrator edits
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
34. **The Google key at rest.** `key.set` (API) and `key set FILE` (CLI)
    store the service account JSON key in SQLite encrypted with AES-256-GCM
    (key from the `state-key` systemd credential, 32 bytes; the secret's name
    is the additional data). It is never returned: only its client e-mail
    and key ID are shown and audited. `google.key_credential` (a file) still
    works and is used when no key is stored. The units load `state-key`
    instead of `google-sa`.
35. **Manual applies through the API are bound to a reviewed plan**: run ID
    and digest; conductor-sync re-plans and applies only if the fresh plan
    has that digest. conductor additionally asks for a typed confirmation
    that contains the first 8 characters of the digest (`apply 1a2b3c4d`, or
    `override 1a2b3c4d` beyond the limits) and a fresh second factor. "Run
    now" is a scheduled-style run (binding limits, first apply must have been
    manual).
36. **In-process scheduler** (`schedule.in_process`) for hosts without
    systemd timers (the Docker test environment); with the timer the status
    estimates the next run as the last scheduled run plus the interval.
37. **Upstreamed to `ad`**: `escape.NormalizeDN` (was `adsource.DNKey`).

The remaining helpers listed above are still local; the group-scope work
needed none of them.

## P5c: connection settings and write-only secrets in the web UI (2026-10-03)

Owner decision (2026-10-03): the connection settings that decision 33 kept
file-only become editable through the management API (and conductor's
Settings > Connection page), with more safeguards than the sync settings.

38. **Connection settings join the versioned settings.** `Settings.connection`
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
39. **An AD connection change is saved only after a sign-in with it.**
    `config.update` and `config.rollback` that change how AD is reached (or
    carry a new bind password) run a sign-in (TLS with the pinned CA, then
    the bind) with the new values first and store nothing if it fails.
    conductor additionally requires a successful connection test of exactly
    the draft it saves (AD and/or Google, whichever part changed). Google
    changes are not re-tested by conductor-sync itself: the setup wizard
    sets the admin subject before the key may exist.
40. **The ownership marker needs a typed confirmation**,
    `change marker to <new marker>`, checked by conductor-sync on update and
    rollback (and by conductor, which shows a strong warning): accounts
    marked with the previous value are no longer recognized as owned.
41. **Secrets are write only.** The AD bind password and the webhook HMAC
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
42. **Rollback = a new version with an earlier version's settings**
    (`config.rollback`, origin `rollback`, the source version in the audit),
    with the same checks as an update. Secrets are not versioned and are not
    touched by a rollback.
43. **Protocol version 2.** Results are decoded strictly (unknown fields
    rejected), so the new fields make P5b clients incompatible; the version
    bump turns that into a clear `version` error. conductor and
    conductor-sync are upgraded together (the lab snapshot conductor-p2b now
    reinstalls both).
