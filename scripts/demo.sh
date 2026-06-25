#!/bin/sh
# demo.sh — see omp-jail working without any manual setup.
#
# Sets up a throwaway project directory, then launches the jailed watcher with a
# stand-in workload that does exactly what a real coding agent does: reads files
# inside the project (in-bounds), and reaches for secrets outside it (escapes).
# The dashboard fills immediately so you can watch the leaderboard populate and
# the verdicts land.
#
#   sudo ~/omp-jail-fresh/scripts/demo.sh           # JAILED — escapes show "blocked"
#   sudo ~/omp-jail-fresh/scripts/demo.sh --audit   # UNCONFINED — escapes show "LEAKED"
#
# Press q to quit the watcher. The real tool is scripts/omp-jail; this just
# wires up activity so there's something to see.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAIL_BIN="$HERE/bin/omp-jail-bin"
PROBE_OBJ="$HERE/bin/probe.bpf.o"
MODE=jail
[ "${1:-}" = "--audit" ] && MODE=audit

[ -f "$JAIL_BIN" ]  || { echo "demo: $JAIL_BIN missing — run 'make' first" >&2; exit 1; }
[ -f "$PROBE_OBJ" ] || { echo "demo: $PROBE_OBJ missing — run 'make' first" >&2; exit 1; }

# --- a throwaway "project" to jail into, with a few real files to read ---
PROJ=${DEMO_DIR:-/tmp/omp-jail-demo}
rm -rf "$PROJ"; mkdir -p "$PROJ/src"
printf 'package main\nfunc main() {}\n' > "$PROJ/src/main.go"
printf 'module demo\n'                   > "$PROJ/go.mod"
printf '# Demo project\n'                > "$PROJ/README.md"

# A couple of fake secrets OUTSIDE the project, so escapes have real targets to
# reach for even on a fresh machine. (These are decoys created just for the demo.)
DECOY_HOME=${HOME:-/root}
mkdir -p "$DECOY_HOME/.aws" "$DECOY_HOME/.ssh" 2>/dev/null || true
[ -f "$DECOY_HOME/.aws/credentials" ] || printf '[default]\nDEMO=not-a-real-key\n' > "$DECOY_HOME/.aws/credentials" 2>/dev/null || true
DECOY_SECRET=/tmp/omp-jail-demo-secret.txt
printf 'pretend-this-is-sensitive\n' > "$DECOY_SECRET"

# The stand-in workload. The jail will exec THIS (comm becomes the basename), and
# the watcher tracks it + its children. It opens files in a loop: in-bounds work,
# then reaches at secrets outside the jail. Reads are in-process (via the shell's
# own redirection) so they're attributed to the jailed process tree.
WORKLOAD=/tmp/omp-jail-demo-workload
cat > "$WORKLOAD.sh" <<EOF
n=0
while [ \$n -lt 100000 ]; do
  # in-bounds: the kind of thing an agent reads constantly
  { read x < "$PROJ/src/main.go"; } 2>/dev/null
  { read x < "$PROJ/go.mod"; } 2>/dev/null
  { read x < "$PROJ/README.md"; } 2>/dev/null
  # escapes: reaching outside the project at user secrets
  { read x < /etc/passwd; } 2>/dev/null
  { read x < "$DECOY_HOME/.ssh/id_rsa"; } 2>/dev/null
  { read x < "$DECOY_HOME/.aws/credentials"; } 2>/dev/null
  { read x < "$DECOY_SECRET"; } 2>/dev/null
  n=\$((n+1))
  sleep 0.25
done
EOF

# Name the workload interpreter "omp" so the watcher's comm-seed matches the real
# tool. We copy a shell into an "omp"-named path and read the script via -c (no
# script file to grant — keeps the jail file-only-clean). The standin lives in
# its own per-run dir so a lingering previous run can't make the copy fail with
# "Text file busy".
STANDIN_DIR=$(mktemp -d /tmp/omp-jail-demo.XXXXXX)
OMP_STANDIN="$STANDIN_DIR/omp"
# Clear any stale standins/processes from earlier demo runs.
pkill -9 -f "/tmp/omp-jail-demo\." 2>/dev/null || true
cp "$(command -v dash 2>/dev/null || command -v sh)" "$OMP_STANDIN"
WORKLOAD_BODY=$(cat "$WORKLOAD.sh")

echo "demo: $MODE — project $PROJ"
echo "demo: starting workload + watcher; press q in the dashboard to quit."

# Background the jailed workload, then run the watcher in the foreground.
if [ "$MODE" = audit ]; then
  ( sleep 3; "$JAIL_BIN" --no-jail "$PROJ" -- "$OMP_STANDIN" -c "$WORKLOAD_BODY" >/dev/null 2>&1 ) &
else
  ( sleep 3; "$JAIL_BIN" "$PROJ" -- "$OMP_STANDIN" -c "$WORKLOAD_BODY" >/dev/null 2>&1 ) &
fi
WL=$!

yeet run "$HERE" -- --dir "$PROJ" --mode "$MODE" --home "$DECOY_HOME" --comm omp || true

# Cleanup
kill "$WL" 2>/dev/null || true
pkill -9 -f "$OMP_STANDIN" 2>/dev/null || true
rm -rf "$STANDIN_DIR" 2>/dev/null || true
echo "demo: done."
