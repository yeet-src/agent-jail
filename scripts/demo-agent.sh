#!/bin/sh
# demo-agent.sh — mimic a real omp coding session for the dashboard demo. Run
# JAILED (the wrapper / omp-jail-bin execs this as the "omp" stand-in). It does
# what an agent actually does while building software: bursts of in-bounds reads
# to understand the code, edits, test/build runs — interleaved with the
# occasional reach OUTSIDE the project (checking env, hunting for config, a
# misfired tool call). Those out-of-bounds reaches are what the jail blocks.
#
# The mix is weighted and varied (not a tight uniform loop) so on camera it
# reads like genuine activity, not a synthetic hammer.
set -u
P="${PROJECT:-$HOME/webapp}"
cd "$P" 2>/dev/null || true

# In-bounds files the agent legitimately works with.
SRC="src/index.ts src/api/router.ts src/components/Button.tsx src/components/Modal.tsx src/lib/format.ts src/lib/db.ts tests/format.test.ts package.json tsconfig.json README.md .gitignore"

# Out-of-bounds targets an agent might wander into (all should be BLOCKED).
OUT="$HOME/.ssh/id_rsa $HOME/.aws/credentials $HOME/.config/gh/hosts.yml /etc/passwd $HOME/.bashrc /etc/hosts"

rd() { { read _x < "$1"; } 2>/dev/null; }          # read a file (open)
wr() { { echo "// edit $(date +%s 2>/dev/null)" >> "$1"; } 2>/dev/null; } # append (in-bounds write)

# Pick a pseudo-random item from "$@". `pick` runs inside $(...) (a subshell), so
# a persistent seed wouldn't survive between calls — instead we mix the live
# clock-ish counter `tick` (bumped by the caller) into the hash, so successive
# picks vary. No $RANDOM in dash.
tick=0
pick() { h=$(( (tick * 2654435761 + 40503) % 2147483647 )); n=$(( h % $# )); i=0; for a in "$@"; do [ "$i" -eq "$n" ] && { echo "$a"; return; }; i=$((i+1)); done; }

phase=0
while :; do
  phase=$((phase + 1))

  # PHASE A — "reading the codebase" : a quick burst of in-bounds source reads.
  k=0; while [ $k -lt 5 ]; do tick=$((tick+1)); rd "$(pick $SRC)"; k=$((k+1)); sleep 0.05; done

  # PHASE B — "editing" : read a file, write it back a couple times.
  tick=$((tick+1)); f=$(pick $SRC); rd "$f"; wr "$f"; sleep 0.08; rd "$f"; wr "$f"; sleep 0.08

  # PHASE C — "running tests/build" : re-read configs + test files.
  rd package.json; rd tsconfig.json; rd tests/format.test.ts; sleep 0.1

  # PHASE D — WANDER outside the project (every other phase), a reach at
  # env/config/secrets. This is the part the jail blocks. Frequent enough that
  # the escape leaderboard fills promptly on camera, but still the minority of
  # activity, so the mix reads as realistic.
  if [ $(( phase % 2 )) -eq 0 ]; then
    tick=$((tick+1)); rd "$(pick $OUT)"; sleep 0.06
    tick=$((tick+1)); rd "$(pick $OUT)"
  fi

  sleep 0.15
done
