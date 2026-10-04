#!/usr/bin/env bash
# Maintainer lab tooling: it needs the family checkout with the lab
# scripts (planning/lab), which are not published; the lab is described in
# https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md
# conductor-sync's own AD lab on the lab host: the family lab scripts
# (planning/lab) run under a different prefix, network and domain, so the
# shared conductor-lab-* VMs are never touched.
#
#   one VM          conductor-synclab-dc1, 10.95.0.10, domain sync.conductor.test
#   network         conductor-synclab (NAT, bridge cndsync0, 10.95.0.0/24)
#   state           ~/conductor-synclab/state (secrets 0600, SSH key, CA)
#
# Run ON the lab host from a copy of the family tree that holds planning/lab:
#
#   scripts/synclab.sh up        # create + provision + seed + snapshot
#   scripts/synclab.sh reset     # back to the "seeded" snapshot
#   scripts/synclab.sh status
#   scripts/synclab.sh svc       # create the read-only service account svc.sync
#   scripts/synclab.sh down      # remove VM, network, volumes and secrets
#   scripts/synclab.sh purge     # down + remove ~/conductor-synclab/state
#
# The copy of the lab scripts is regenerated on every call from
# ../planning/lab (relative to this repository) and patched with sed; the
# patches are checked so an upstream change that breaks them fails loudly.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_LAB="${SYNCLAB_SRC:-$HERE/../../planning/lab}"
ROOT="${SYNCLAB_ROOT:-$HOME/conductor-synclab}"
LAB="$ROOT/lab"

[ -f "$SRC_LAB/common.sh" ] || { echo "planning/lab not found at $SRC_LAB" >&2; exit 1; }

install -d -m 0700 "$ROOT" "$ROOT/state"
rm -rf "$LAB"
cp -a "$SRC_LAB" "$LAB"

# common.sh: prefix, bridge, subnet, MACs, domain, one DC, state directory.
sed -i \
  -e 's|^LAB_HOME=.*|LAB_HOME="${CONDUCTOR_LAB_HOME:-'"$ROOT"'/state}"|' \
  -e 's|^PREFIX="conductor-lab"|PREFIX="conductor-synclab"|' \
  -e 's|^BRIDGE="cndlab0"|BRIDGE="cndsync0"|' \
  -e 's|^SUBNET="10.93.0"|SUBNET="10.95.0"|' \
  -e 's|^DOMAIN="lab.conductor.test"|DOMAIN="sync.conductor.test"|' \
  -e 's|^REALM="LAB.CONDUCTOR.TEST"|REALM="SYNC.CONDUCTOR.TEST"|' \
  -e 's|^NETBIOS="LAB"|NETBIOS="SYNC"|' \
  -e 's|^BASE_DN=.*|BASE_DN="DC=sync,DC=conductor,DC=test"|' \
  -e 's|^DCS=(dc1 dc2)|DCS=(dc1)|' \
  -e 's|52:54:00:93:|52:54:00:95:|g' \
  "$LAB/common.sh"
# up.sh / seed.sh: no second DC (no join, no convergence, one snapshot).
sed -i -e '/provision dc2 /d' -e '/wait_samba dc2/d' -e '/remote\/converge.sh" "\$DOMAIN"/,+1d' "$LAB/up.sh"
sed -i -e 's|has_snapshot dc1 && has_snapshot dc2|has_snapshot dc1|' -e '/replicating to dc2/,/dc2 sees/d' "$LAB/seed.sh"

check() { grep -q -- "$2" "$LAB/$1" || { echo "synclab: patch check failed: $1 lacks $2" >&2; exit 1; }; }
check common.sh 'PREFIX="conductor-synclab"'
check common.sh 'SUBNET="10.95.0"'
check common.sh 'BRIDGE="cndsync0"'
check common.sh 'DCS=(dc1)'
check common.sh "$ROOT/state"
# Steps that would act on a second DC must be gone (DC_IP[dc2] itself stays
# defined: it is only passed as an unused argument and a DHCP reservation).
if grep -nE 'provision dc2|wait_samba dc2|converge\.sh|has_snapshot dc2|vm_ssh dc2' "$LAB/up.sh" "$LAB/seed.sh" >&2; then
  echo "synclab: a second-DC step survived patching (above)" >&2
  exit 1
fi

# svc: a plain domain user as the read-only sync account. Domain Users can
# read the user and group attributes conductor-sync needs; no extra rights.
# Its password is generated here, stored 0600 next to the lab secrets and
# reaches the DC only on stdin.
svc_account() {
  # shellcheck source=/dev/null
  source "$LAB/common.sh"
  local f="$LAB_HOME/sync-secrets.env"
  if [ ! -s "$f" ]; then
    (umask 077; printf 'SYNC_BIND_PASSWORD=Sync-%s-7q\n' "$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 24)" >"$f")
  fi
  chmod 0600 "$f"
  local opts; mapfile -t opts < <(ssh_opts)
  ssh "${opts[@]}" "debian@${DC_IP[dc1]}" 'sudo sh -c "umask 077; cat > /root/sync-secrets.env"' <"$f"
  ssh "${opts[@]}" "debian@${DC_IP[dc1]}" 'sudo bash -s' <<'EOF'
set -euo pipefail
set -a; . /root/sync-secrets.env; set +a
if ! samba-tool user show svc.sync -H /var/lib/samba/private/sam.ldb >/dev/null 2>&1; then
  # --random-password, then the real password through an LDIF (never argv).
  samba-tool user create svc.sync --random-password -H /var/lib/samba/private/sam.ldb >/dev/null
fi
dn="$(ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=svc.sync)' dn | sed -n 's/^dn: //p')"
b64="$(python3 -c 'import os,base64; print(base64.b64encode(("\"%s\"" % os.environ["SYNC_BIND_PASSWORD"]).encode("utf-16-le")).decode())')"
umask 077
printf 'dn: %s\nchangetype: modify\nreplace: unicodePwd\nunicodePwd:: %s\n' "$dn" "$b64" >/root/svc.ldif
ldbmodify -H /var/lib/samba/private/sam.ldb /root/svc.ldif >/dev/null
rm -f /root/svc.ldif /root/sync-secrets.env
samba-tool user setexpiry svc.sync --noexpiry -H /var/lib/samba/private/sam.ldb >/dev/null
echo "svc.sync ready: $dn"
EOF
}

cmd="${1:-status}"
case "$cmd" in
up) "$LAB/up.sh" ;;
seed) "$LAB/seed.sh" "${@:2}" ;;
reset) "$LAB/reset.sh" "${@:2}" ;;
status) "$LAB/status.sh" ;;
svc) svc_account ;;
down) "$LAB/down.sh" ;;
purge) "$LAB/down.sh" --purge; rm -rf "$ROOT" ;;
*) echo "usage: $0 up|seed|reset [snapshot]|status|svc|down|purge" >&2; exit 2 ;;
esac
