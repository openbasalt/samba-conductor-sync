# Google-first mode (Google Workspace to AD)

By default AD is the source of truth and conductor-sync provisions AD to
Google Workspace. The Google-first mode is the other direction, for an
organization whose people are created, renamed and suspended in Google
Workspace and that wants a Samba AD (file servers, Wi-Fi, VPN, Linux and
Windows sign-in) to follow.

The mode is off by default and opt-in per installation. Within it, each
scope pairs one AD OU tree with a Google selection (org units, optionally
restricted to members of Google groups). conductor-sync reads both sides
and computes a plan; it never writes to Google or to AD. conductor applies
the plan through conductor-provisioner, which holds the only AD write
right, delegated on the managed OUs.

This version plans user accounts. Groups and group memberships are not
part of the plan, and plans are requested and applied by hand from
conductor (or listed with `conductor-sync g2a-plan`).

## Product rules

These rules hold whatever Google says and are enforced by every component
of the mode.

1. Privileged access is granted only directly in AD. Nothing that comes
   from Google creates, grants, restores or widens a privileged
   membership or right in AD. Google administrator flags and roles never
   map to anything in AD: super administrators and the sync's admin
   subject are never created in AD, and the flag changes nothing for an
   account that is already managed. An AD account that is privileged
   (nested member of an administrative group or of one of conductor's role
   groups, `adminCount` set, or holding more than read on the domain head,
   an OU, AdminSDHolder or a Group Policy object) is out of scope: the plan
   never modifies, disables, moves or re-enables it, and lists it as
   skipped (`privileged-object`) with the reasons, so a person acts in AD.
   A person who also administers AD gets a separate AD-only account.
2. Google is the source of truth for every field it owns. After an apply,
   each Google-owned field in AD equals Google's value. A change made in
   AD to such a field is overwritten by the next plan (`ad.user.update`
   with reason `ad-drift`): no merge, no "AD wins". Fields Google does not
   own stay AD-managed and are never written.
3. Google keeps its own sign-in. There is no single sign-on from AD to
   Google in this mode: conductor refuses to enable it while a
   conductor-idp application serves the Google domain, and the reverse.
   The Google password is never written to AD or read from it; people set
   their first AD password through an invitation sent to their Google
   address.

## Who does what

| Component | Does | Never does |
|---|---|---|
| conductor-sync | reads Google with the read-only Directory API scopes and AD with its read-only account, computes a deterministic plan (typed operations, digest, limits), records it as a run and audits the read; records what conductor applied (links) | any write to Google or to AD |
| conductor | requests and shows the plan, applies it after review through conductor-provisioner, sends invitations, reports the results | talking to Google; acting outside the managed OUs |
| conductor-provisioner | executes typed operations with a delegated AD account limited to the managed OUs, re-checking every operation (scope, privilege, ceilings) | free-form LDAP, deletions, security descriptors, privileged objects |

## Configuration

```toml
[google_first]
enabled = false
google_domain = "example.com"

[[google_first.scopes]]
name = "people"
mode = "dry-run"                     # dry-run | apply
managed_ou = "OU=People,OU=Google,DC=example,DC=com"
groups_ou = "OU=Groups,OU=People,OU=Google,DC=example,DC=com"
quarantine_ou = "OU=Quarantine,OU=People,OU=Google,DC=example,DC=com"
org_units = ["/Staff"]
sub_org_units = true
member_of = []                       # Google group addresses; empty: no restriction
fields = ["title", "department", "employee_id", "phone_work", "phone_mobile"]
logon_template = "{given}.{family}"
[google_first.scopes.limits]
max_creates = 20
max_disables = 5
max_reenables = 20
max_updates = 50
max_renames = 5
max_touched_percent = 20
min_source_size = 1
max_source_drop_percent = 20
```

The section can be edited in the file or through the management API
(`config.update`, settings `google_first`), like the other sync settings.
Every scope starts in `dry-run`; conductor switches a scope to `apply` only
after its plan was reviewed, with a typed confirmation and a fresh second
factor.

A configuration version is refused when:

- `groups_ou` or `quarantine_ou` is not below `managed_ou`, or they are
  the same OU (or one contains the other);
- `managed_ou` is inside, equal to, or contains any `source.user_bases` or
  `source.group_bases` entry of the AD to Google direction, or overlaps the
  managed OU of another scope (the two directions never share an OU tree);
- an org unit of `org_units` (with `sub_org_units`, also the org units
  below it) is a target org unit of the AD to Google mapping
  (`mapping.default_org_unit` or an `org_units` rule);
- a scope name is used twice or is not 1 to 32 lower-case letters, digits,
  `-` or `_`; `org_units` is empty; a field is not one of `title`,
  `department`, `employee_id`, `phone_work`, `phone_mobile`;
  `logon_template` uses an unknown placeholder;
- a limit is below -1, or a percentage is outside 0 to 100 (-1 means no
  limit, 0 means none allowed);
- the mode is enabled, or has scopes, without `google_domain`.

Without a `limits` table a scope uses the values above. A `limits` table
replaces them: a key left out is 0 (none allowed).

## What is read

Google, with the read-only scopes only: every account of the customer
(and the groups with their members when a scope has `member_of`). A scope
selects the accounts of its org units (and below them with
`sub_org_units`) that are members, directly or through nested groups, of at
least one `member_of` group when the list is set. It never selects:

- accounts outside `google_domain`;
- super administrators and the sync's admin subject (never created);
- accounts that carry the AD to Google ownership marker (skipped as
  `managed-by-ad-first`).

AD, with the read-only account:

- whether the schema has `msDS-cloudExtensionAttribute1` (checked once per
  read);
- every user below each `managed_ou`, with the marker attribute, `mail`,
  `proxyAddresses`, names, the mapped fields, `userAccountControl`,
  `pwdLastSet`, `objectGUID`, `objectSid` and `adminCount`;
- every object anywhere with a candidate address (`mail`,
  `userPrincipalName` or an SMTP `proxyAddresses` entry) or a candidate
  marker, and the logon names, principal names and common names already
  used;
- the privilege index: nested membership of the administrative groups and
  of the role groups conductor passes with the request, `adminCount`, and
  the explicit allow entries on the domain head, every OU, AdminSDHolder
  and every Group Policy object.

### What stops a read

A read that cannot be trusted stops with an error and records a failed run
without a plan. It must never look like everybody left.

| Case | Error |
|---|---|
| a scope selects no account (for example only administrators) | `empty-selection` |
| an org unit of `org_units` has no account at all (missing or empty: the read-only scopes do not list org units) | `missing-org-unit` |
| a `member_of` group does not exist in Google | `missing-group` |
| the AD schema has no `msDS-cloudExtensionAttribute1` | refused, no other attribute is used |
| a managed OU does not exist in AD | refused |

## Identity

The link between a Google account and its AD account is the immutable
Google user ID. It is written on the AD object as the marker
`google-first:<google user id>` in `msDS-cloudExtensionAttribute1` (set at
creation, never edited by hand) and in conductor-sync's state, table
`g2a_links` (scope, Google ID, `objectGUID`, SID, logon name, whether the
sync disabled the account, and the Google values last applied). The marker
means a lost state database does not orphan accounts; the stored Google
values tell a change made in Google (`google-change`) from a change made in
AD (`ad-drift`).

A Google account deleted and recreated has a new ID: it is a new person,
never a takeover of the old AD account, which is disabled.

## Field ownership

| AD attribute or property | Owner | Notes |
|---|---|---|
| existence | Google | created when a selected Google account appears |
| suspension, deletion | Google | AD disable and move to `quarantine_ou`; never deleted |
| `givenName`, `sn`, `displayName` | Google | `displayName` is the given and family name |
| `mail` | Google | the primary address; a former address stays as an `smtp:` entry of `proxyAddresses` |
| `title`, `department`, `employeeID`, `telephoneNumber`, `mobile` | Google | only the scope's `fields`; the others stay AD-managed |
| marker (`msDS-cloudExtensionAttribute1`) | the sync | never edited by hand |
| `sAMAccountName`, `userPrincipalName`, `cn` | AD, set once | generated at creation, never changed by the sync |
| password, `pwdLastSet`, lockout | AD and the person | set through the invitation; never from Google |
| every privileged membership or right | AD only | never from Google |
| every other attribute and group | AD administrators | untouched |

## Operations

| Kind | When | Effect |
|---|---|---|
| `ad.user.create` | a selected, active Google account without an AD account carrying its marker, and no conflict | a user in `managed_ou`: logon name, `userPrincipalName` = `<logon name>@<realm>`, `cn` from the names, the Google-owned fields, the marker; created disabled with `pwdLastSet` 0 and a random password generated by the provisioner; `invite` asks conductor to send an invitation |
| `ad.user.update` | a Google-owned field differs | the field set to Google's value; reason `google-change` when the stored Google value equals the AD value, else `ad-drift` |
| `ad.user.rename` | Google's primary address changed | new `mail`, the old address added to `proxyAddresses` as `smtp:`; the logon name is kept |
| `ad.user.disable` | the Google account is suspended, deleted, or no longer selected | disabled (when enabled) and moved to `quarantine_ou` (when not there) |
| `ad.user.reenable` | the Google account is active and selected again, and the sync was the one that disabled the AD account | enabled and moved back to `managed_ou` |

Operations are listed in apply order (updates, renames, re-enables,
creates, disables), then by Google ID, and numbered (`seq`) across the
plan. An account created by the sync that is still disabled with
`pwdLastSet` 0 waits for its invitation: the plan leaves its state alone.

Logon names follow the import rules unchanged
([import-from-google.md](import-from-google.md#logon-names)): the local part
of the address when it is a valid logon name and free, else the scope's
`logon_template`, accents folded, at most 20 characters, never an invented
numbered name.

## Skips

| Reason | Case |
|---|---|
| `privileged-object` | the AD account is privileged (rule 1); the reasons are listed |
| `ad-unmanaged-exists` | an AD object already has the address, or carries the account's marker outside the managed OU |
| `duplicate-logon-name` | two Google accounts resolve to the same logon name: neither is created |
| `marker-mismatch` | an AD account with the address carries another Google ID's marker, two AD accounts carry the same marker, or the marker is on another account than the linked one |
| `managed-by-ad-first` | the Google account carries the AD to Google ownership marker |
| `no-free-logon-name` | neither the local part nor the template is free (or the common name and its `(logon name)` variant are both taken) |
| `disabled-outside-sync` | the AD account was disabled by someone else: never re-enabled |
| `in-two-scopes` | the Google account is selected by two scopes: left alone by both |

## Limits

Each scope has its own limits, checked like the AD to Google limits:
`max_creates`, `max_disables`, `max_reenables`, `max_updates` (drift
corrections included), `max_renames`, `max_touched_percent` (existing
accounts changed, as a share of the accounts carrying the marker in the
scope), `min_source_size` (selected Google accounts) and
`max_source_drop_percent` (compared with the scope's size at the last
applied plan). A scope whose plan exceeds a limit is blocked: conductor
shows the violation and does not apply that scope.

## Management API

`g2a.plan` (`syncapi.G2APlanParams`: `scope`, empty for every scope, and
`role_group_sids`, conductor's role groups) returns `syncapi.G2APlan`:
`run_id`, `digest`, `read_at`, `google_domain` and, per scope, `name`,
`mode`, `ops`, `skipped`, `warnings`, `limits`, `blocked`, `source_size`
and `managed`. The plan is recorded as a run of action `g2a`, listed by
`runs.list` and readable page by page with `run.get` (field `g2a`). The
digest is the SHA-256 of the canonical JSON of the operations of every
scope.

`g2a.confirm` (`syncapi.G2AConfirmParams`: `run_id`, `digest`, `results`
with each operation's `seq`, `status` done, failed or skipped, `error`,
and for a done create the new account's `sid` and `object_guid`, and
`actor`, who approved the apply) records what conductor applied: the links
are written and the run is closed as `applied`, `partial`, `blocked` or
`dry-run`. A result for an operation that is not in the plan, or that
belongs to a scope in `dry-run` or blocked by its limits, refuses the whole
confirmation. A run is confirmed once.

## Command line

```
conductor-sync g2a-plan [--scope NAME] [--role-group SID]... [--json]
```

It prints (or returns as JSON) the same plan and records the same run. It
writes nothing to Google or AD.

## Audit

conductor-sync audits `g2a.plan` (the scope requested, the number of role
groups, the run and digest, and per scope the mode, sizes, counts of
operations by kind and of skips by reason) and `g2a.confirm` (run, digest,
approver, counts and the run's status). Neither carries personal data: no
address, name or logon name. conductor audits every applied operation and
conductor-provisioner keeps its own chain.
