#!/bin/sh
# demo-record.sh — one command that launches a POPULATED dashboard for recording.
# Backgrounds a jailed workload (steady in-bounds work + escape attempts at real
# secrets), then runs the live dashboard in the foreground. By the time the TUI
# paints, the leaderboard is already filling. Press q to quit.
#
#   sudo ~/omp-jail-fresh/scripts/demo-record.sh
#
# Self-contained: creates its own project + decoy secrets, cleans up on exit.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJ=${DEMO_DIR:-$HOME/project}
HOME_ABS=${HOME:-/root}

[ -f "$HERE/bin/omp-jail-bin" ] || { echo "run 'make' first"; exit 1; }
[ -f "$HERE/bin/probe.bpf.o" ]  || { echo "run 'make' first"; exit 1; }

# --- project to work in (in-bounds reads land here) ---
rm -rf "$PROJ"; mkdir -p "$PROJ/src"
printf 'package main\nfunc main(){}\n' > "$PROJ/src/main.go"
printf 'module project\n'              > "$PROJ/go.mod"
printf '# My Project\n'                > "$PROJ/README.md"
printf 'func add(a,b int)int{return a+b}\n' > "$PROJ/src/util.go"

# --- decoy secrets OUTSIDE the jail (escape targets) ---
# Best-effort (|| true): a pre-existing root-owned decoy from an earlier run
# shouldn't abort the demo under `set -e`.
mkdir -p "$HOME_ABS/.ssh" "$HOME_ABS/.aws" 2>/dev/null || true
printf 'PRIVATE-KEY\n'        > "$HOME_ABS/.ssh/id_rsa" 2>/dev/null || true
printf '[default]\nk=SECRET\n'> "$HOME_ABS/.aws/credentials" 2>/dev/null || true
SECRET_ENV=$(mktemp /tmp/host-secret.XXXXXX.env)
printf 'DB_PASSWORD=hunter2\n'> "$SECRET_ENV"

# --- omp-named workload (comm must be "omp" for the watcher to track it) ---
STANDIN=$(mktemp -d)/omp
cp "$(command -v dash 2>/dev/null || command -v sh)" "$STANDIN"

WORKLOAD='i=0
while [ $i -lt 100000 ]; do
  { read x < '"$PROJ"'/src/main.go; } 2>/dev/null
  { read x < '"$PROJ"'/go.mod; } 2>/dev/null
  { read x < '"$PROJ"'/README.md; } 2>/dev/null
  { read x < '"$PROJ"'/src/util.go; } 2>/dev/null
  { read x < /etc/passwd; } 2>/dev/null
  { read x < '"$HOME_ABS"'/.ssh/id_rsa; } 2>/dev/null
  { read x < '"$HOME_ABS"'/.aws/credentials; } 2>/dev/null
  { read x < '"$SECRET_ENV"'; } 2>/dev/null
  cat /etc/shadow >/dev/null 2>&1
  i=$((i+1)); sleep 0.18
done'

echo "starting jailed workload + dashboard…"
# Background the jailed workload. In an interactive shell this child persists
# for the life of the script; we kill it on exit.
"$HERE/bin/omp-jail-bin" "$PROJ" -- "$STANDIN" -c "$WORKLOAD" >/dev/null 2>&1 &
WL=$!
cleanup() {
  kill "$WL" 2>/dev/null || true
  pkill -9 -f "$STANDIN" 2>/dev/null || true
  rm -rf "$(dirname "$STANDIN")" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 2  # let the workload start reaching before the TUI paints

yeet run "$HERE" -- --dir "$PROJ" --mode jail --home "$HOME_ABS" --comm omp
