# conductor-sync: mapping guide

How AD objects become Google accounts and groups: the `[mapping]` and
`[source]` sections of `conductor-sync.toml`, or the same settings in
conductor's "Google Workspace sync > Setup" (stored as versions by
conductor-sync, see `usage-p5.md` §13). Test every change with a plan before
applying; the plan lists every field that would change and the rule behind
each org unit change.

## Templates

A template is text with `{attribute}` placeholders, optionally filtered:
`{attribute|filter|filter}`. Attribute names are LDAP names and are not
case-sensitive: `sAMAccountName`, `userPrincipalName`, `mail`, `givenName`,
`sn`, `displayName`, `cn`, `title`, `department`, `employeeID`,
`telephoneNumber`, `mobile`, `description`, and any other single-valued
attribute (it is read automatically when a template names it).

| Filter | Effect | Example |
|---|---|---|
| `lower`, `upper`, `trim` | case, spaces | `{mail|lower}` |
| `localpart` | text before `@` | `{userPrincipalName|localpart}` -> `jsilva` |
| `domain` | text after `@` | |
| `ascii` | folds accents, drops other non-ASCII | `José` -> `Jose` |
| `slug` | lowercase ASCII letters, digits, `.`, `_`, `-`; other runs become `-` | `Sales Team (BR)` -> `sales-team-br` |

A placeholder whose value is empty makes the whole template fail, so list
fields take several templates and use the first that works:

```toml
primary_email = ["{mail|lower}", "{sAMAccountName|ascii|lower}@example.com"]
```

## Users

| Key | Default | Notes |
|---|---|---|
| `primary_email` | (required) | First template that renders an address whose domain is in `allowed_domains`. A user with none is skipped and listed under "Skipped source objects" |
| `allowed_domains` | (required) | Domains the sync may create addresses in. An AD `mail` in another domain falls through to the next template |
| `given_name` | `{givenName}`, `{displayName}`, `{sAMAccountName}` | Google requires both names (at most 60 characters; longer values are cut) |
| `family_name` | `{sn}`, `{sAMAccountName}` | |
| `default_org_unit` | `/` | For users no rule places |
| `[[mapping.org_units]]` | none | Placement rules, by group or by container (next section). The org units must exist in Google |
| `[mapping.attributes]` | none | Optional fields, one template each: `title`, `department`, `employee_id`, `phone_work`, `phone_mobile`. Only listed fields are managed; an empty AD value clears the Google value |

How optional fields are written: `title` and `department` go to the
primary entry of `organizations` (other entries are kept); `employee_id`
is the `externalIds` entry of type `organization`; `phone_work` and
`phone_mobile` replace the `work` and `mobile` entries of `phones` (other
phone types are kept). The ownership marker is another `externalIds` entry
(`type: custom`, `customType: <google.marker>`, value: the AD objectGUID);
do not remove it by hand, or the account stops being recognized after a
state loss.

### Org unit placement

Two kinds of `[[mapping.org_units]]` rules:

- group rules: `group = "<DN or SID>"`, `target`, and an explicit
  `priority` (an integer from 1; 1 is evaluated first). Members of the
  group, nested membership included, go to `target`;
- container rules: `ad = "<container DN>"`, `target`; no priority, the
  most specific container holding the user wins.

Resolution, for each user:

1. group rules, from priority 1 upwards: the first priority at which the
   user matches any group rule decides;
   - one matching rule, or several pointing at the same org unit: that org
     unit;
   - several pointing at different org units: a plan error for that
     user (`org-unit-ambiguous`). The plan lists it and the user is left
     untouched (not created, changed, suspended or removed from groups) until
     the configuration or the memberships are fixed. The sync never picks one
     silently;
2. otherwise the most specific matching container rule;
3. otherwise `default_org_unit`.

A group may have one rule only. Groups referenced by SID survive renames and
moves (conductor stores SIDs); a group referenced by DN that is renamed,
moved or deleted stops the read with "referenced groups not found", so the
run fails and alerts instead of moving everybody to another org unit. The
plan shows the groups with their current names, and every org unit change
says which rule caused it (`org unit from group Finance (priority 10)`).

```toml
[[mapping.org_units]]                   # managers first, wherever they are
group = "S-1-5-21-1004336348-1177238915-682003330-1601"   # Managers
target = "/Managers"
priority = 1

[[mapping.org_units]]
group = "CN=Finance,OU=Groups,DC=corp,DC=example"
target = "/Finance"
priority = 10

[[mapping.org_units]]                   # everybody else by OU
ad = "OU=People,DC=corp,DC=example"
target = "/Staff"
```

Address changes: when the rendered address of a user changes (logon name or
`mail` changed in AD), the plan shows `user.rename`; Google keeps the old
address as an alias, so mail keeps arriving. Renames have their own limit
(`max_renames`). Administrators are never renamed or suspended by the sync.

Two AD users that render the same address are both left alone (warning
`duplicate-address`) until one is fixed. An address that already belongs to
a Google account the sync does not own is reported (`unmanaged-exists`)
and left alone unless `policy.adopt = "email"` (see "Adopting an existing
Google Workspace" below).

## Scope

`[source]` decides who is in scope:

- `user_bases`: containers searched (subtree) for users;
- `exclude_bases`: containers below them to leave out (service accounts);
- `include_groups`: optional groups (DN or SID); only users that are members
  of at least one of them, nested membership included, are in scope (a
  "Google users" group is a convenient switch). `require_group` (one DN) is
  the P5 form and still accepted;
- `exclude_groups`: optional groups whose members are out of scope even
  when included (exclusion wins), e.g. "Leavers" or "No Google";
- primary-group membership (Domain Users) is not an AD `member` value and
  does not count for these groups: use a regular group;
- every referenced group must exist (see above);
- critical system objects (Administrator, krbtgt, built-in groups) are
  never in scope;
- disabled accounts are in scope but suspended (`policy.suspend_disabled`),
  and not created (`policy.create_disabled = false`); accounts past
  `accountExpires` count as disabled (`expired_as_disabled`).

Leaving the scope, by any route (moved out of the bases, removed from the
include groups, added to an exclude group), suspends the account. Narrowing
the scope by mistake suspends many accounts at once: that is what
`max_suspends`, `max_touched_percent` and `max_source_drop_percent` stop in
scheduled runs. The plan shows how many users the include and exclude
groups left out.

## Groups

Groups are synced when both `group_email` and `source.group_bases` are set.

| Key | Default | Notes |
|---|---|---|
| `group_email` | none (groups off) | Templates; the address must be in `group_allowed_domains` |
| `group_allowed_domains` | `allowed_domains` | |
| `group_name` | `{cn}` | |
| `group_description` | `{description}` | |

Members: direct members that are in scope. A user member becomes a USER
member; a group member that is itself synced becomes a GROUP member
(nesting is mirrored, not flattened). AD primary-group membership (Domain
Users) is not a `member` value and is not synced. Members in Google that
the sync does not manage (external addresses, people added by hand) are
kept unless `policy.remove_unmanaged_members = true` (for adopted groups,
only with `adopted_group_members = "manage"`). Added members get the
role `google.member_role` (MEMBER).

A group that leaves the scope is kept as it is, with its members (warning
`group-out-of-scope`); delete it by hand if intended.

## Adopting an existing Google Workspace

A company that already uses Google Workspace has accounts, org units,
groups and aliases that people rely on. To connect AD to it, start with
`policy.adopt = "email"` and add users to the AD scope gradually: each AD
user whose rendered address equals an existing account's primary address
is adopted. Adoption takes the account over; it does not recreate, reset,
move, rename or delete it.

What adoption does, on the adoption run:

- writes the ownership marker (`externalIds`, `customType` =
  `google.marker`, value = the AD objectGUID) and an adoption mark
  (`customType` = `<marker>-adopted`), keeping every other `externalIds`
  entry. The link in the state database records that the account was
  adopted, not created; the mark on the account keeps that fact if the
  state database is lost;
- writes the names and mapped fields allowed by the rules below, and
  nothing else.

What adoption never does:

- send a password or `changePasswordAtNextLogin`. Only an account the sync
  creates gets a password (random, sent once, never stored). An adopted
  account keeps its password, its sign-in method and its 2-Step
  Verification;
- change aliases, recovery e-mail or phone, photos, licenses, admin roles,
  or any field that is not mapped;
- suspend the account. An AD user that is disabled (or past
  `accountExpires`) never adopts an account: the plan shows
  `disabled-not-adopted` and leaves it alone until the AD user is enabled;
- unsuspend an account that someone else suspended (`suspended-outside-sync`);
- delete anything. `conductor-sync delete-user` refuses adopted accounts:
  they existed before the sync, so only an administrator deletes them, in
  the Admin console.

The adopted rules apply on the adoption run and on every later run of an
adopted account or group. Accounts the sync creates follow the mapping as
usual.

| Key (`[policy]`) | Default | Values |
|---|---|---|
| `adopted_org_unit` | `keep` | `keep`: the account stays in its org unit forever; `manage`: placed by the org unit rules like a created account |
| `adopted_email` | `keep` | `keep`: the primary address of an adopted account or group is never changed; when AD renders another address the plan warns `adopted-address-kept`; `manage`: renamed (`user.rename`, the old address stays as an alias) |
| `adopted_names` | `if-set` | given and family name, and an adopted group's name and description. `if-set`: written only when AD has a value of its own (not empty, and not rendered by a fallback template such as `{sAMAccountName}` when `givenName` is empty); `keep`: never written; `manage`: always written |
| `adopted_attributes` | `if-set` | the optional fields of `[mapping.attributes]`. `if-set`: an empty AD value never clears the Google value; `keep`: never written; `manage`: as for created accounts (an empty AD value clears) |
| `adopted_group_members` | `add-only` | adopted groups. `add-only`: members are added, never removed, managed or not (`adopted-member-kept`, `unmanaged-member-kept`); `manage`: AD decides the managed members, and `remove_unmanaged_members` applies |

Later effects, which are the normal sync rules:

- disabling the AD user, or taking it out of the scope (moving it out of
  the bases, out of the include groups, into an exclude group, or deleting
  it), suspends the adopted account. Enabling it, or putting it back,
  unsuspends it, because the sync did the suspension. The safety limits
  stop a scheduled run that would suspend or change too many accounts;
- an account suspended by an administrator stays suspended whatever AD
  says.

A plan shows every adoption as `user.adopt` or `group.adopt` with the
fields it changes; the reason lists the fields whose AD value differs but
is kept on the account (`adopt existing account by address; kept on the
account: org_unit`).

Rollout:

1. Keep `mode = "dry-run"` and set `adopt = "email"` with the defaults
   above. Use small limits (`max_updates`, `max_creates`, `max_suspends`,
   `max_touched_percent`).
2. Put a few AD users in the scope (an include group is a convenient
   switch), plan, and read every `user.adopt`: the changes must be only
   the names you expect. Check the warnings (`unmanaged-exists` for
   addresses that differ in case or domain, `alias-collision` when the AD
   address is an alias of another account, `disabled-not-adopted`).
3. Apply manually, check the accounts in the Admin console, then grow the
   scope in batches.
4. Accounts that are not in the AD scope are never touched.

## Worked example

AD:

```
OU=People,DC=corp,DC=example
  OU=Engineering   ->  /Staff/Engineering
  OU=Sales         ->  /Staff/Sales
  OU=Contractors   ->  /Contractors
  OU=Service       (excluded)
OU=Google Groups,DC=corp,DC=example
```

```toml
[source]
user_bases = ["OU=People,DC=corp,DC=example"]
exclude_bases = ["OU=Service,OU=People,DC=corp,DC=example"]
group_bases = ["OU=Google Groups,DC=corp,DC=example"]

[mapping]
primary_email = ["{mail|lower}", "{sAMAccountName|ascii|lower}@example.com"]
allowed_domains = ["example.com"]
default_org_unit = "/Staff"
group_email = ["{mail|lower}", "{cn|slug}@example.com"]

[mapping.attributes]
title = "{title}"
department = "{department}"

[[mapping.org_units]]
ad = "OU=Engineering,OU=People,DC=corp,DC=example"
target = "/Staff/Engineering"
[[mapping.org_units]]
ad = "OU=Sales,OU=People,DC=corp,DC=example"
target = "/Staff/Sales"
[[mapping.org_units]]
ad = "OU=Contractors,OU=People,DC=corp,DC=example"
target = "/Contractors"
```

`João Souza` (`sAMAccountName` `jsouza`, no `mail`) in OU=Sales becomes
`jsouza@example.com` in `/Staff/Sales` with his title and department; the
group `CN=Sales Team (BR)` without `mail` becomes `sales-team-br@example.com`.
