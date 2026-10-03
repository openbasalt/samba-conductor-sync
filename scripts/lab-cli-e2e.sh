#!/usr/bin/env bash
# End-to-end run of the real conductor-sync binary on the lab host: the sync
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
SERVE_PID=""
cleanup() {
  [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null || true
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

"$BIN/fakegws" -dir "$W/fake" -addr "127.0.0.1:$PORT" -domains sync.example.com,groups.sync.example.com \
  -org-units /Staff/Engineering,/Staff/Sales,/Special -page-size 200 -seed-admin 2>"$W/fake.log" &
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
# The fake's own administrator (the admin subject, -seed-admin) is not counted.
fake_unique() { fake_json state | python3 -c 'import json,sys; d=json.load(sys.stdin); u=[x for x in d["users"] or [] if not x.get("isAdmin")]; print(len({x["primaryEmail"] for x in u}), len(u))'; }
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

say "management API (serve): key, settings, connection test, preview, plan, run now"
openssl rand -hex 32 >"$W/creds/state-key"; chmod 0600 "$W/creds/state-key"
cat >>"$W/sync.toml" <<EOF2

[api]
socket = "$W/api.sock"
allowed_uids = [$(id -u)]
EOF2
expect 0 cs key set "$W/creds/google-sa"
grep -q 'stored (encrypted)' "$W/out.txt" || fail "key set"
expect 0 cs config history
grep -q 'no stored version' "$W/out.txt" || fail "config history before any edit"
"$BIN/conductor-sync" serve --config "$W/sync.toml" 2>"$W/serve.log" &
SERVE_PID=$!
for _ in $(seq 1 50); do [ -S "$W/api.sock" ] && break; sleep 0.1; done
[ "$(stat -c %a "$W/api.sock")" = 660 ] || fail "socket mode"
api() { python3 - "$W/api.sock" "$@" <<'PY'
import json, socket, sys, uuid
sock, op = sys.argv[1], sys.argv[2]
params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
req = {"version": 2, "id": uuid.uuid4().hex[:16], "op": op, "params": params, "sent_at": "2026-10-03T00:00:00Z",
       "actor": {"user": "lab.admin", "sid": "S-1-5-21-1-2-3-1104", "session": "cli-e2e", "ip": "127.0.0.1"}}
s = socket.socket(socket.AF_UNIX); s.connect(sock)
s.sendall((json.dumps(req) + "\n").encode())
data = b""
while not data.endswith(b"\n"):
    chunk = s.recv(1 << 20)
    if not chunk: break
    data += chunk
resp = json.loads(data)
if not resp["ok"]:
    print(json.dumps(resp["error"])); sys.exit(1)
print(json.dumps(resp["result"]))
PY
}
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
api status | jq_ 'd["ready"] and d["key"]["source"] == "database"' | grep -q True || fail "status"
SID="$(api mapping.preview '{"query":"user0001","limit":3}' | jq_ 'd["users"][0]["email"]')"
[ "$SID" = "user0001@sync.example.com" ] || fail "preview: $SID"
CFG="$(api config.get)"
SETTINGS="$(echo "$CFG" | python3 -c 'import json,sys; s=json.load(sys.stdin)["settings"]; s["scope"]["include_groups"]=["CN=All Staff,OU=Groups,OU=Lab,DC=sync,DC=conductor,DC=test"]; print(json.dumps(s))')"
api connection.test "{\"settings\": $SETTINGS}" >"$W/test.json"
jq_ 'd["ad"]["ok"] and d["google"]["ok"] and d["groups"][0]["name"] == "All Staff"' <"$W/test.json" | grep -q True || { cat "$W/test.json"; fail "connection test"; }
api config.update "{\"base_version\": 0, \"settings\": $SETTINGS, \"comment\": \"cli e2e\"}" | jq_ 'd["version"]' | grep -q '^1$' || fail "config.update"
JOB="$(api plan.start | jq_ 'd["job"]["id"]')"
for _ in $(seq 1 120); do
  STATE="$(api job.get "{\"id\": \"$JOB\"}" | jq_ 'd["state"]+" "+str(d.get("run_id",0))')"
  case "$STATE" in running*) sleep 0.5 ;; *) break ;; esac
done
case "$STATE" in done*) ;; *) fail "plan job: $STATE" ;; esac
RUN="${STATE#done }"
api run.get "{\"id\": $RUN, \"section\": \"create\", \"limit\": 5}" >"$W/run.json"
jq_ 'd["groups"][0]["name"] == "All Staff" and d["groups"][0]["members"] >= 2400' <"$W/run.json" | grep -q True || fail "plan scope"
api apply.start '{"scheduled": true}' | jq_ 'd["job"]["kind"]' | grep -q scheduled || fail "run now"
expect 0 cs config history
grep -q 'conductor:lab.admin@127.0.0.1' "$W/out.txt" || fail "config history actor"

say "P5c: connection settings and write-only secrets through the API"
# Wait for the scheduled-style run to release the run lock.
for _ in $(seq 1 240); do
  api status | jq_ 'd.get("job") is None or d["job"]["state"] != "running"' | grep -q True && break; sleep 0.5
done
BINDPW="$(cat "$W/creds/ad-bind")"
pyjson() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
# A wrong bind password is refused (AD sign-in), the right one stored.
api secret.set "{\"name\": \"ad_bind_password\", \"value\": $(pyjson "${BINDPW}-wrong")}" >"$W/secret.json" && fail "wrong bind password stored"
grep -q 'could not sign in' "$W/secret.json" || { cat "$W/secret.json"; fail "wrong password reason"; }
api secret.set "{\"name\": \"ad_bind_password\", \"value\": $(pyjson "$BINDPW")}" | jq_ 'd["configured"] and d["source"] == "database"' | grep -q True || fail "bind password stored"
api secret.set '{"name": "alert_webhook_secret", "value": "lab-webhook-hmac-0123456789"}' | jq_ 'd["configured"]' | grep -q True || fail "webhook secret"
# The credential file is no longer needed.
rm -f "$W/creds/ad-bind"
expect 0 cs check-config
grep -q 'secret ad_bind_password: configured (database)' "$W/out.txt" || fail "check-config secret source"
# The CA inline and the DC list, saved after a real sign-in; an unknown DC is refused.
CFG="$(api config.get)"
echo "$CFG" | jq_ 'd["secrets"][0]["configured"] and d["secrets"][0]["source"] == "database" and d["host"]["connection_stored"]' | grep -q True || fail "config.get secrets"
# (STATE was reused for the job state above: the lab state is $ROOT/state.)
CA="$(cat "$ROOT/state/ca.pem")"
SETTINGS="$(echo "$CFG" | python3 -c 'import json,sys; s=json.load(sys.stdin)["settings"]; s["connection"]["ad"]["dcs"]=["dc9.sync.conductor.test"]; print(json.dumps(s))')"
api config.update "{\"base_version\": 1, \"settings\": $SETTINGS}" >"$W/bad.json" && fail "unknown DC saved"
grep -q 'could not sign in' "$W/bad.json" || { cat "$W/bad.json"; fail "unknown DC reason"; }
SETTINGS="$(echo "$CFG" | CA="$CA" python3 -c 'import json,os,sys; s=json.load(sys.stdin)["settings"]; s["connection"]["ad"]["ca_pem"]=os.environ["CA"]; s["connection"]["ad"]["auth"]="kerberos"; print(json.dumps(s))')"
api config.update "{\"base_version\": 1, \"settings\": $SETTINGS, \"comment\": \"inline CA\"}" | jq_ 'd["version"]' | grep -q '^2$' || fail "connection update"
# The marker needs its typed confirmation.
SETTINGS="$(api config.get | python3 -c 'import json,sys; s=json.load(sys.stdin)["settings"]; s["connection"]["marker"]="conductor-sync-lab2"; print(json.dumps(s))')"
api config.update "{\"base_version\": 2, \"settings\": $SETTINGS}" >"$W/marker.json" && fail "marker changed without confirmation"
api config.update "{\"base_version\": 2, \"settings\": $SETTINGS, \"marker_confirmation\": \"change marker to conductor-sync-lab2\"}" | jq_ 'd["version"]' | grep -q '^3$' || fail "marker change"
# Rollback to version 2 (marker back, confirmed).
api config.rollback '{"base_version": 3, "version": 2, "comment": "undo marker", "marker_confirmation": "change marker to conductor-sync"}' | jq_ 'd["version"]' | grep -q '^4$' || fail "rollback"
api config.get | jq_ 'd["settings"]["connection"]["marker"] == "conductor-sync" and d["host"]["connection_stored"]' | grep -q True || fail "after rollback"
# The new settings work end to end: a plan reads AD with the stored password and the inline CA.
JOB="$(api plan.start | jq_ 'd["job"]["id"]')"
for _ in $(seq 1 120); do
  STATE2="$(api job.get "{\"id\": \"$JOB\"}" | jq_ 'd["state"]')"
  [ "$STATE2" = running ] || break; sleep 0.5
done
[ "$STATE2" = done ] || fail "plan with the stored connection: $STATE2"
# No secret value anywhere.
expect 0 cs config export
grep -q 'BEGIN CERTIFICATE' "$W/out.txt" || fail "export lacks the inline CA"
for f in "$W/out.txt" "$W/serve.log"; do grep -qF -- "$BINDPW" "$f" && fail "bind password in $f"; done
cs audit export >"$W/audit.jsonl"
grep -qF -- "$BINDPW" "$W/audit.jsonl" && fail "bind password in the audit"
grep -q 'lab-webhook-hmac' "$W/audit.jsonl" && fail "webhook secret in the audit"
grep -q 'secret ad_bind_password: set' "$W/audit.jsonl" || fail "audit of the secret"
expect 0 cs audit verify
kill "$SERVE_PID"; wait "$SERVE_PID" 2>/dev/null || true
grep -q 'management API listening' "$W/serve.log" || fail "serve log"

say "CLI end to end: OK"
