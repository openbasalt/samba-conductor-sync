#!/usr/bin/env bash
# Run conductor-sync's lab tests on server-home (its own sync lab, see
# synclab.sh) from the laptop: build here, copy the binaries over, reset
# the lab domain to its "seeded" snapshot, run the Go lab tests and the CLI
# end-to-end script, reset again. Secrets stay on server-home.
#
#   scripts/lab-test.sh            # Go lab tests + CLI end to end
#   scripts/lab-test.sh go|cli     # only one of them
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
HOST="${SYNCLAB_HOST:-server-home}"
WHAT="${1:-all}"
REMOTE_ROOT='~/conductor-synclab'

cd "$REPO"
export GOWORK=off CGO_ENABLED=0
mkdir -p bin/lab
go build -trimpath -o bin/lab/conductor-sync ./cmd/conductor-sync
go build -trimpath -o bin/lab/fakegws ./tools/fakegws
go test -c -tags lab -o bin/lab/labtest.test ./internal/labtest

ssh "$HOST" "mkdir -p $REMOTE_ROOT/bin $REMOTE_ROOT/src/conductor-sync/scripts $REMOTE_ROOT/src/planning"
rsync -a bin/lab/ "$HOST:conductor-synclab/bin/"
rsync -a --delete scripts/ "$HOST:conductor-synclab/src/conductor-sync/scripts/"
rsync -a --delete --exclude .git/ ../planning/lab/ "$HOST:conductor-synclab/src/planning/lab/"

reset_lab() { ssh "$HOST" "cd $REMOTE_ROOT/src/conductor-sync && ./scripts/synclab.sh reset >/dev/null"; }

rc=0
if [ "$WHAT" = all ] || [ "$WHAT" = go ]; then
  reset_lab
  ssh "$HOST" "cd $REMOTE_ROOT/bin && ./labtest.test -test.v -test.timeout 30m" || rc=$?
fi
if [ "$WHAT" = all ] || [ "$WHAT" = cli ]; then
  reset_lab
  ssh "$HOST" "cd $REMOTE_ROOT && ./src/conductor-sync/scripts/lab-cli-e2e.sh" || rc=$?
fi
reset_lab
exit "$rc"
