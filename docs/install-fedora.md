# Installing conductor-sync on Basalt OS / Fedora

conductor-sync on Basalt OS (Fedora 44 based, SELinux enforcing) or
Fedora 44, from the RPM packages, next to conductor. The configuration
is the one `docs/usage-p5.md` describes; this page lists what differs. The
Basalt OS package lab (see
[testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)) runs it with SELinux enforcing: dry-run by default, the
management API socket used by conductor.

## Package

```sh
sudo dnf install conductor-sync           # Basalt OS: from basalt-tools
sudo dnf install ./conductor-sync-<version>-1.x86_64.rpm ./conductor-sync-selinux-<version>-1.noarch.rpm
                                          # Fedora, or a release's assets (check SHA256SUMS)
```

`conductor-sync-selinux` comes with it wherever the targeted policy is
installed. The package creates the `conductor-sync` user (sysusers.d) and
owns `/etc/conductor-sync` (root:conductor-sync 0750) with `credentials/`
(conductor-sync 0700), `conductor-sync.toml` (0640, `%config(noreplace)`,
`mode = "dry-run"`) and `/var/lib/conductor-sync`. Nothing is enabled or
started. Install conductor first: the API socket's group is `conductor`.

Then, as in `docs/usage-p5.md`: the AD password in `credentials/ad-bind`, a
state key in `credentials/state-key` (both 0600, owned by conductor-sync),
the domain CA, `conductor-sync.toml`, `sudo systemctl enable --now
conductor-sync-api.socket`, `[sync] enabled = true` in conductor.toml.

## SELinux

The services run in `conductor_sync_t` (scheduled runs and the management
API): configuration (`conductor_sync_conf_t`), state
(`conductor_sync_var_lib_t`), the API socket in `/run/conductor-sync`
(`conductor_sync_var_run_t`, which `conductor_t` may use), LDAP(S) and
Kerberos to the DCs, HTTPS to Google's APIs and an optional webhook.
Commands run by hand (`sudo -u conductor-sync conductor-sync plan`) are not
confined. A `metrics_file` outside `/var/lib/conductor-sync` needs a path
labeled for it (for example `semanage fcontext -a -t
conductor_sync_var_lib_t '/var/lib/node_exporter/textfile(/.*)?'`).

## Upgrade and removal

`dnf upgrade` restarts the API service when it runs and keeps an edited
`conductor-sync.toml` (`.rpmnew` beside it). `dnf remove` stops and disables
the units, removes the packaged files and the policy module and keeps the
credentials, `/var/lib/conductor-sync` and the user.
