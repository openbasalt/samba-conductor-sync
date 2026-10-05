# Self-service: connected accounts

conductor's self-service has a "Connected accounts" page: for each target
directory conductor-sync provisions to, a signed-in user sees their own
account there and, when the target and its policy allow it, can activate
it or set a new password. conductor-sync does the work on the user's
explicit request, never from a schedule; conductor shows what
conductor-sync reports and knows nothing specific to a target.

Google Workspace is the connector implemented. The protocol and the page
are generic: a connector declares what it supports and conductor renders
only that.

## What a user can do

| Action | Effect |
|---|---|
| See the status | not activated, active, suspended, waiting for the next sync run, or not available (with the reason), the account's address, and whether the sync created it or adopted it |
| Activate | creates the account now (on-demand provisioning), with a password shown once or typed by the user |
| New password | sets a new password on the user's own linked account: generated and shown once, or typed by the user |

No password is stored anywhere: not in AD, not in conductor, not in
conductor-sync's state, logs, journal or audit. Storing an initial password
in an AD attribute was rejected: such attributes are readable by
authenticated users by default and end up in plain text in backups and
replication.

## Capabilities of a connector

A connector that supports self-service implements an optional interface
and declares its capabilities:

| Capability | Meaning |
|---|---|
| `on_demand_create` | one account can be created on request, with the user's password |
| `set_password` | a password can be set on an existing account |
| `password_rules` | the target publishes its password rules (length, characters) |
| `status` | one account can be read |

conductor-sync raises the rules with the policy (`password_min_length`) and
returns them with the status, so conductor can tell the user what a typed
password must look like. The Google connector declares all four; its rules
are 8 to 100 characters, printable ASCII, no leading or trailing space (a
tenant's own password policy may require more: the Directory API then
refuses the password and the user is told so).

## Policy

`[self_service]` in the configuration file, or `self_service` in the
settings edited through the management API (defaults travel as empty, and
an empty value keeps the file's):

| Key | Default | Values and effect |
|---|---|---|
| `activation` | `auto` | `auto`: the sync runs create accounts as before and activation is not offered. `self-service`: the sync runs create an account only for users who activated theirs; the others are shown in every plan as `pending-activation` warnings. Adoptions, updates and suspensions are not affected |
| `password_reset` | `created` | `created`: only accounts the sync created. `created-and-adopted`: also accounts that existed before the sync and were adopted. `off`: no password changes |
| `chosen_password` | `off` | `allow`: the user may type a password instead of a generated one |
| `password_min_length` | 12 | raises the connector's minimum (8 to 100) |
| `max_per_user_hour` | 3 | activations and password changes per user in any hour |
| `max_per_target_hour` | 30 | the same for all users of the target |

## Safety rules

- The user is always the request's actor. conductor sends the signed-in
  user's SID; conductor-sync looks that user up in AD and never accepts a
  user named in the request.
- Nothing is written in dry-run mode.
- Eligibility is the sync scope: the user must be below the user bases, in
  an include group when there are any, in no exclude group, enabled (and not
  expired) and have a valid mapped address. The lookup of one user uses the
  same rules as a full read.
- An activation runs the plan of a sync run with that user counted as
  activated, so the mapping, the address checks (duplicates, aliases,
  accounts owned by another source, existing unmanaged accounts) and the
  ownership marker are those of a run. Of that plan only the user's create
  is applied, with the user's memberships in groups that already exist; it
  is journaled as a run of its own (action `activate`, trigger
  `self-service`) and holds the run lock. An existing account with the
  address is never taken over by an activation: with `adopt = "email"` the
  next sync run adopts it.
- A password is set only on the user's linked account that carries the
  sync's ownership marker for that user. Target administrators and the
  sync's own admin subject are always refused, whatever the policy; so are
  suspended accounts, users out of the scope or disabled, and adopted
  accounts unless `password_reset = "created-and-adopted"`.
- The rate limits are kept in the state database, so they hold across
  restarts. Refusals do not count; every request that reaches the target
  does, successful or not.
- conductor requires a session that passed a second factor, and asks for
  the password and a second factor again when the last one is older than a
  few minutes.

## Passwords on the wire

| Step | What happens |
|---|---|
| Generated | conductor-sync generates it (groups of four unambiguous letters and digits joined by hyphens, about 92 bits), sends it to the target once and returns it once in the API result; conductor keeps it in the session's memory until the user opens the page that shows it (once, not cached), then drops it |
| Typed | conductor checks the confirmation and the length, holds it in the session's memory until the confirmation page is submitted (at most ten minutes), sends it to conductor-sync once; conductor-sync checks the rules and sends it to the target once |
| Google | an activation is the same `users.insert` as a run's create; a reset is a `users.patch` whose body has only `password` and `changePasswordAtNextLogin` |

`changePasswordAtNextLogin` is false for both. A run's create sets it to
true because the random password is never shown to anyone; a self-service
password is the user's own: only the user saw it (or chose it), so a forced
change would only make them pick another one right away, and with
single sign-on through conductor-idp it would interrupt the sign-in for
nothing. The rest of the sync still never sends a password: updates,
adoptions, suspensions and renames do not carry `password` or
`changePasswordAtNextLogin`. The optional request log
(`CONDUCTOR_SYNC_REQUEST_LOG`) records the field names of each request, so
an operator can verify that only the activations and the resets carried a
password.

## Audit

- conductor-sync's hash-chained audit log: `api.account.activate` and
  `api.account.set_password` (with the conductor actor), `activate.start`,
  `activate.end` and the create's own entry, `self.set_password` (address,
  target ID, whether the account was created or adopted, generated or
  typed), refusals and rate limits. Never a password.
- The table `selfservice_actions` (state database) keeps who acted, when,
  on which account and with what result, for the rate limits.
- conductor's audit log: `self.account_activate` and
  `self.account_password` with the previewed text (no password), and
  `self.account_password_shown` when the user opened the page with the
  generated password.

## Management API

| Operation | Params | Result |
|---|---|---|
| `account.status` | `AccountStatusParams` (optional target) | `AccountStatus`: one `TargetAccount` per target |
| `account.activate` | `AccountActivateParams`: target, password mode (`generate` or `chosen`) and the typed password | `AccountActionResult`: the account, the generated password (once), warnings |
| `account.set_password` | `AccountSetPasswordParams`: the same | `AccountActionResult` |

A refusal is an error with code `forbidden` whose only detail is a reason
code (`out-of-scope`, `disabled`, `dry-run`, `adopted`, `admin`,
`address-taken`, `existing-account`, `password-rules`, `target-refused`,
and others listed in `syncapi`), which conductor translates. The rate
limits answer the code `rate_limited`. The operations were added without a
protocol version change, like `import.plan`: they change no existing
message, an older conductor never sends them and an older conductor-sync
answers that they are not allowlisted. The new `self_service` settings are
optional and absent while every value is the default.

## Status from a run's point of view

- With `activation = "self-service"`, a plan lists every user waiting for
  activation as a `pending-activation` warning, not as an operation, so
  the plan's digest and limits do not depend on them.
- An activation run is shown in the runs list with its single create; it
  is never applicable from there, and it does not supersede a plan under
  review (that plan has no operation for a user waiting for activation, so
  its digest is the same after the activation).
- When an activated user's account is deleted outside the sync, the next
  run creates it again (with a random password and a change required, as
  any run's create); the user sets a new password in conductor.
