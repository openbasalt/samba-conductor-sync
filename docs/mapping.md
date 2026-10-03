# conductor-sync: mapping guide

How AD objects become Google accounts and groups: the `[mapping]` section
of `conductor-sync.toml`. Test every change with `conductor-sync plan`
before applying; the plan lists every field that would change.

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
| `default_org_unit` | `/` | For users outside every mapped OU |
| `[[mapping.org_units]]` | none | `ad` (a container DN) -> `target` (org unit path). The most specific container holding the user wins. The org unit must exist in Google |
| `[mapping.attributes]` | none | Optional fields, one template each: `title`, `department`, `employee_id`, `phone_work`, `phone_mobile`. **Only listed fields are managed**; an empty AD value clears the Google value |

How optional fields are written: `title` and `department` go to the
primary entry of `organizations` (other entries are kept); `employee_id`
is the `externalIds` entry of type `organization`; `phone_work` and
`phone_mobile` replace the `work` and `mobile` entries of `phones` (other
phone types are kept). The ownership marker is another `externalIds` entry
(`type: custom`, `customType: <google.marker>`, value: the AD objectGUID);
do not remove it by hand, or the account stops being recognized after a
state loss.

Address changes: when the rendered address of a user changes (logon name or
`mail` changed in AD), the plan shows `user.rename`; Google keeps the old
address as an alias, so mail keeps arriving. Renames have their own limit
(`max_renames`). Administrators are never renamed or suspended by the sync.

Two AD users that render the same address are both left alone (warning
`duplicate-address`) until one is fixed. An address that already belongs to
a Google account the sync does not own is reported (`unmanaged-exists`)
and left alone unless `policy.adopt = "email"`.

## Scope

`[source]` decides who is in scope:

- `user_bases`: containers searched (subtree) for users;
- `exclude_bases`: containers below them to leave out (service accounts);
- `require_group`: optional group DN; only its members, including nested
  membership, are in scope (a "Google users" group is a convenient switch);
- critical system objects (Administrator, krbtgt, built-in groups) are
  never in scope;
- disabled accounts are in scope but suspended (`policy.suspend_disabled`),
  and not created (`policy.create_disabled = false`); accounts past
  `accountExpires` count as disabled (`expired_as_disabled`).

Leaving the scope, by any route, suspends the account. Narrowing the scope
by mistake suspends many accounts at once: that is what `max_suspends`,
`max_touched_percent` and `max_source_drop_percent` stop in scheduled runs.

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
kept unless `policy.remove_unmanaged_members = true`. Added members get the
role `google.member_role` (MEMBER).

A group that leaves the scope is kept as it is, with its members (warning
`group-out-of-scope`); delete it by hand if intended.

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
