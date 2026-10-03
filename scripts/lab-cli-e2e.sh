#!/usr/bin/env bash
# End-to-end run of the real conductor-sync binary on server-home: the sync
# lab's Samba AD as source, fakegws (the fake Directory API) as target.
# Covers dry-run, the first-manual-apply rule, the limits, a plan pinned by
# run ID, the run lock, a kill -9 in the middle of the initial apply and the
# resume, idempotency, status/history/map/audit/metrics and a refused
# delete. Run by scripts/lab-test.sh (lab reset before and after).
#
# Credentials are copied into a private work directory (0700/0600) that is
# removed at the end; nothing secret is printed.
set -euo pipefail

ROOT="${SYNCLAB_ROOT:-$HOME/conductor-synclab}"
BIN="$ROOT/bin"
STATE="$ROOT/state"
W="$ROOT/cli-e2e"
PORT=18443
FAKE="https://127.0.0.1:$PORT"

say() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

rm -rf "$W"
install -d -m 0700 "$W" "$W/creds" "$W/fake" "$W/state"
(umask 077; sed -n 's/^SYNC_BIND_PASSWORD=//p' "$STATE/sync-secrets.env" >"$W/creds/ad-bind")

FAKE_PID=""
cleanup() {
  [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

"$BIN/fakegws" -dir "$W/fake" -addr "127.0.0.1:$PORT" -domains sync.example.com,groups.sync.example.com \
  -org-units /Staff/Engineering,/Staff/Sales,/Special -page-size 200 2>"$W/fake.log" &
FAKE_PID=$!
for _ in $(seq 1 50); do [ -s "$W/fake/admin.txt" ] && curl -sk -o /dev/null "$FAKE/_fake/state" && break; sleep 0.2; done
install -m 0600 "$W/fake/sa-key.json" "$W/creds/google-sa"

BASE="DC=sync,DC=conductor,DC=test"
cat >"$W/sync.toml" <<EOF
mode = "dry-run"
state_dir = "$W/state"
credentials_dir = "$W/creds"
metrics_file = "$W/metrics.prom"

[source]
realm = "SYNC.CONDUCTOR.TEST"
dcs = ["dc1.sync.conductor.test"]
dns_servers = ["10.95.0.10"]
ca_file = "$STATE/ca.pem"
bind_user = "svc.sync"
password_credential = "ad-bind"
user_bases = ["OU=Lab,$BASE"]
group_bases = ["OU=Groups,OU=Lab,$BASE"]

[mapping]
primary_email = ["{sAMAccountName|ascii|lower}@sync.example.com"]
allowed_domains = ["sync.example.com"]
group_email = ["{sAMAccountName|slug}@groups.sync.example.com"]
group_allowed_domains = ["groups.sync.example.com"]
[mapping.attributes]
title = "{title}"
department = "{department}"
[[mapping.org_units]]
ad = "OU=People,OU=Lab,$BASE"
target = "/Staff"
[[mapping.org_units]]
ad = "OU=Engineering,OU=People,OU=Lab,$BASE"
target = "/Staff/Engineering"
[[mapping.org_units]]
ad = "OU=Sales,OU=People,OU=Lab,$BASE"
target = "/Staff/Sales"
[[mapping.org_units]]
ad = "OU=Special,OU=Lab,$BASE"
target = "/Special"

[google]
admin_subject = "$(cat "$W/fake/admin.txt")"
key_credential = "google-sa"
api_base_url = "$FAKE"
token_url = "$FAKE/token"
ca_file = "$W/fake/cert.pem"
requests_per_second = 2000
EOF

cs() { "$BIN/conductor-sync" "$@" --config "$W/sync.toml"; }
expect() {
  local want="$1"; shift
  local rc=0
  "$@" >"$W/out.txt" 2>&1 || rc=$?
  if [ "$rc" != "$want" ]; then
    cat "$W/out.txt" >&2
    fail "'$*' exited $rc, want $want"
  fi
}
fake_json() { curl -sk "$FAKE/_fake/$1"; }
fake_users() { fake_json state | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["users"] or []))'; }
fake_unique() { fake_json state | python3 -c 'import json,sys; d=json.load(sys.stdin); u=d["users"] or []; print(len({x["primaryEmail"] for x in u}), len(u))'; }
fake_writes() { fake_json writes | python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))'; }

say "check-config"
expect 0 cs check-config
grep -E '^AD:' "$W/out.txt"
SRC_USERS="$(sed -n 's/^AD: \([0-9]*\) users.*/\1/p' "$W/out.txt")"
[ "${SRC_USERS:-0}" -ge 2500 ] || fail "source users: $SRC_USERS"

say "plan in dry-run mode"
expect 0 cs plan
grep -q 'SAFETY LIMITS EXCEEDED' "$W/out.txt" || fail "limits not reported"
grep -q 'Mode is dry-run' "$W/out.txt" || fail "dry-run not reported"
grep -E '^Changes:' "$W/out.txt"
# Disabled AD accounts are not created (policy.create_disabled = false).
CREATES="$(sed -n 's/^Changes:.*user.create=\([0-9]*\).*/\1/p' "$W/out.txt")"
PLAN_RUN="$(sed -n 's/.*conductor-sync apply --plan \([0-9]*\).*/\1/p' "$W/out.txt")"

say "apply refused in dry-run mode"
expect 6 cs apply --yes
[ "$(fake_writes)" = 0 ] || fail "dry-run wrote"

sed -i 's/^mode = "dry-run"/mode = "apply"/' "$W/sync.toml"
say "scheduled run before the first manual apply"
expect 3 cs apply --scheduled
grep -q 'first apply must be manual' "$W/out.txt" || fail "first-manual rule"
say "manual apply beyond the limits without the override"
expect 3 cs apply --yes
say "declined confirmation"
printf 'nope\n' | expect 5 cs apply --override-limits
[ "$(fake_writes)" = 0 ] || fail "wrote without confirmation"

say "initial apply pinned to plan run $PLAN_RUN, killed with SIGKILL mid-way"
curl -sk -X POST "$FAKE/_fake/latency?ms=3" >/dev/null
"$BIN/conductor-sync" apply --plan "$PLAN_RUN" --yes --override-limits --config "$W/sync.toml" >"$W/apply1.txt" 2>&1 &
APPLY_PID=$!
for _ in $(seq 1 300); do
  n="$(fake_users)"
  [ "$n" -ge 400 ] && break
  sleep 0.2
done
say "concurrent run refused by the lock"
expect 1 cs plan
grep -q 'another conductor-sync run is in progress' "$W/out.txt" || fail "lock"
kill -9 "$APPLY_PID"
wait "$APPLY_PID" 2>/dev/null || true
echo "killed after $(fake_users) accounts"
curl -sk -X POST "$FAKE/_fake/latency?ms=0" >/dev/null

say "the old plan no longer matches"
expect 5 cs apply --plan "$PLAN_RUN" --yes --override-limits
grep -q 'plan changed' "$W/out.txt" || fail "pin"

say "resume"
expect 0 cs apply --yes --override-limits
grep -E '^Run' "$W/out.txt"
read -r uniq total < <(fake_unique)
[ "$uniq" = "$total" ] || fail "duplicate accounts: $uniq unique of $total"
[ "$total" = "$CREATES" ] || fail "accounts $total, planned creates $CREATES"
echo "accounts on the target: $total (no duplicates)"

say "idempotent"
expect 0 cs plan
grep -q '^No changes.' "$W/out.txt" || { cat "$W/out.txt"; fail "plan not empty"; }
expect 0 cs apply --scheduled
grep -q 'nothing-to-do' "$W/out.txt" || fail "scheduled not nothing-to-do"

say "status, history, map, audit, metrics"
expect 0 cs status
cat "$W/out.txt"
grep -q 'interrupted' "$W/out.txt" || fail "interrupted run not shown"
expect 0 cs history --limit 5
expect 0 cs map user0001@sync.example.com
grep -q 'CN=User 0001' "$W/out.txt" || fail "map"
expect 0 cs audit verify
cat "$W/out.txt"
grep -q 'conductor_sync_last_run_timestamp_seconds' "$W/metrics.prom" || fail "metrics"

say "delete refused for an active, in-scope account"
expect 5 cs delete-user user0001@sync.example.com --confirm user0001@sync.example.com
cat "$W/out.txt"
fake_json writes | python3 -c 'import json,sys
w=json.load(sys.stdin) or []
bad=[x for x in w if x["method"]=="DELETE" and "/members/" not in x["path"]]
assert not bad, bad
print("no deletions among", len(w), "writes")'

say "CLI end to end: OK"
