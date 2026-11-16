# Google credentials: least privilege

conductor-sync calls the Admin SDK Directory API with a Google Cloud
service account and its JSON key. How that service account is authorized
decides what a stolen key can do. This page describes the recommended
setup, the legacy one, the migration between them, and how to keep the key.

Status: the service-account mode below follows Google's documented model
for administrator roles assigned to service accounts. It is covered by the
test suite against a fake Directory API; it has not yet been validated
against a live Google Workspace tenant. Run a `plan` and a `check-config`
before the first apply, and report any privilege that turns out to be
missing.

## The two modes

`google.auth_mode` in the configuration file (a host setting: the
management API and conductor's web UI can not change it).

| Mode | How the key is used | What a stolen key can do |
|---|---|---|
| `service-account` (default) | the service account acts as itself; it holds a custom administrator role with only the privileges below. The token request carries no subject | what the role allows: create, read and update users (and groups, when they are synced). Google does not let a role without super administrator rights change a super administrator |
| `domain-wide-delegation` (legacy, explicit opt-in) | the service account impersonates `google.admin_subject` | impersonate any user of the tenant, super administrators included: the key holder chooses the subject, Google only checks that the scopes are delegated. That is a full takeover of the Workspace |

With `domain-wide-delegation`, every command and every start of the service
prints a warning to standard error (the journal under systemd), and
conductor's connection test says so.

## Setting up the service-account mode

1. Google Cloud console: create a project and a service account. It needs
   no IAM role on the project. Create a JSON key (see "The key" below for
   how to keep it). Do not enable domain-wide delegation for it.
2. Admin console > Account > Admin roles > Create new role, for example
   `conductor-sync`. Under Admin API privileges grant only:
   - Users: Read, Create, Update;
   - Groups: Read, Create, Update (only when groups are synced, that is
     when `mapping.group_email` and `source.group_bases` are set);
   - Organization Units: Read;
   - Roles: Read (only if group adoption is used, see below).
   Do not grant Delete: conductor-sync never deletes in its runs.
   `conductor-sync delete-user` (manual) then fails with a permission
   error; an administrator deletes in the Admin console instead, or the
   privilege is added only for that moment.
3. On the role, Assign service accounts: enter the service account's
   e-mail address. Where the Admin console offers it, limit the assignment
   to the org units the sync manages.
4. Configuration: `[google] auth_mode = "service-account"` (or leave it
   out, it is the default). `admin_subject` is not needed; when it is set it
   only names an account the sync never touches.
5. Store the key (`conductor-sync key set FILE`, or conductor's Google
   Workspace sync > Setup) and run `conductor-sync check-config` and a
   `plan`.

Scopes the sync requests (a token can never do more than its scopes, and
the role decides what the service account may do within them):

| When | Scopes |
|---|---|
| `plan`, `import-plan`, `g2a-plan`, connection test, self-service status | `admin.directory.user.readonly`, `admin.directory.group.readonly` |
| `apply`, self-service writes, `delete-user` | `admin.directory.user`; `admin.directory.group` only when groups are synced |
| an approved group adoption (once per plan) | `admin.directory.rolemanagement.readonly`, with its own token |

If the role assignments can not be read (the Roles: Read privilege, or in
the delegated mode the scope, is missing), no group is adopted: the plan
reports the candidate as refused with `group-roles-unknown`.

## Migrating from domain-wide delegation

1. Create the custom role and assign it to the same service account (steps
   2 and 3 above). The key does not change.
2. Set `auth_mode = "service-account"` in the configuration file and run
   `conductor-sync check-config` and `conductor-sync plan`. The plan must
   show no change caused by the switch.
3. Admin console > Security > Access and data control > API controls >
   Domain-wide delegation: delete the service account's client ID. From
   then on the key can no longer impersonate anyone.
4. Rotate the key (below): the old one was able to impersonate any user.
5. The dedicated `admin_subject` account is no longer used by the sync;
   remove its super administrator role or delete it, unless you keep it for
   other reasons.

To stay on the delegated mode for now, set
`auth_mode = "domain-wide-delegation"` explicitly (a configuration without
the key is in the service-account mode from this version on), keep
`admin_subject` a dedicated account that is used for nothing else, and
delegate only the scopes in the table above.

## The key

- Prefer the encrypted store (`conductor-sync key set FILE`): the key is
  kept in the state database with AES-256-GCM under the `state-key`
  credential, and is never returned by the API. Delete the downloaded file
  afterwards.
- A key kept as a file (`google.key_credential` naming an absolute path, or
  a name in `credentials_dir`) must be a regular file, not a symbolic link,
  owned by the conductor-sync user (or root), with mode 0600 or 0400.
  conductor-sync checks this on the opened file and refuses anything else.
  Under systemd, prefer `LoadCredential=`, which makes a private copy for
  the service.
- Rotation, at least yearly and after any suspicion (or anyone who had
  access leaving):
  1. Google Cloud console > the service account > Keys > Add key (JSON).
  2. `conductor-sync key set NEWFILE` (or conductor's Setup page), then
     `conductor-sync check-config` and a `plan`.
  3. Delete the old key in the Google Cloud console (its key ID is shown by
     `conductor-sync key show`), and the downloaded file.
- Recommended Google Cloud organization policies: an expiry for service
  account keys (`iam.serviceAccountKeyExpiryHours`) and key creation
  disabled except for this project (`iam.disableServiceAccountKeyCreation`).
- Alerting: watch the Admin console audit logs for actions by the service
  account outside its expected pattern (password changes, role changes,
  sign-ins), and the Google Cloud audit logs for new keys on the service
  account.
- Where the host offers it, a key held by an HSM or a cloud KMS, or
  Workload Identity Federation instead of a key file, removes the key
  from the host altogether; conductor-sync does not support these yet.
