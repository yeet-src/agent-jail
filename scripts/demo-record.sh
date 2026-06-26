#!/bin/sh
# demo-record.sh — one command that launches a POPULATED, realistic dashboard for
# recording. Scaffolds a real-looking project, backgrounds a jailed workload that
# mimics an omp coding session (bursts of in-bounds work + the occasional reach
# outside the project), then runs the live dashboard in the foreground. By the
# time the TUI paints, the panels are already filling with believable activity.
#
#   sudo ~/omp-jail-fresh/scripts/demo-record.sh
#
# Press ↑/↓ to scroll the escape list, c to copy a summary, q to quit.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJ=${DEMO_DIR:-$HOME/webapp}
HOME_ABS=${HOME:-/root}

[ -f "$HERE/bin/omp-jail-bin" ] || { echo "run 'make' first"; exit 1; }
[ -f "$HERE/bin/probe.bpf.o" ]  || { echo "run 'make' first"; exit 1; }

# Scaffold the realistic project + decoy secrets.
sh "$HERE/scripts/demo-project.sh" "$PROJ" >/dev/null

# omp-named workload so the watcher's comm-seed tracks it. The agent script reads
# the project via PROJECT=… ; copy a shell to an "omp"-named path and run it.
STANDIN=$(mktemp -d)/omp
cp "$(command -v dash 2>/dev/null || command -v sh)" "$STANDIN"
AGENT=$(cat "$HERE/scripts/demo-agent.sh")

echo "starting realistic jailed agent + dashboard…"
# Background the jailed agent. In an interactive shell this child persists for
# the life of the script; cleaned up on exit.
PROJECT="$PROJ" "$HERE/bin/omp-jail-bin" "$PROJ" -- "$STANDIN" -c "$AGENT" >/dev/null 2>&1 &
WL=$!
cleanup() {
  kill "$WL" 2>/dev/null || true
  pkill -9 -f "$STANDIN" 2>/dev/null || true
  rm -rf "$(dirname "$STANDIN")" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 2  # let the agent build up some activity before the TUI paints

yeet run "$HERE" -- --dir "$PROJ" --mode jail --home "$HOME_ABS" --comm omp
