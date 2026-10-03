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
    on server-home. The patches are verified (the script fails if a
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
| Normalized DN key for map lookups (case, escaping, multi-valued RDN order) | `adsource.DNKey` | `escape.NormalizeDN(dn) string` (EqualDN exists, but maps need a key) |
| Typed user plus extra attributes in one search | `adsource` (Search + `UserFromEntry` + raw entry) | `Conn.UsersWithAttributes(ctx, base, filter, extra []string) iter.Seq2[UserEntry, error]` |
| Bulk member read of many groups (one ranged read per group today) | `adsource` loop over `GroupMembers` | `Conn.GroupMembersMany` or a member DN -> GUID resolver |
| Logon rename (sAMAccountName + userPrincipalName); `UpdateUser` covers profile attributes only | raw go-ldap modify in `internal/labtest` | `ad.RenameLogon(dn, sam, upn)` with preview and the old-value assertion |
| Incremental change tracking (uSNChanged high-water mark or DirSync control) | not implemented (full reads) | `Conn.ChangesSince(ctx, base, usn)` |
| Exclusion of critical system objects | filter in `adsource` | a reusable `escape` constant / `Users` option |
