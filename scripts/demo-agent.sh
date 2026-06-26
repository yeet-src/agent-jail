#!/bin/sh
# demo-agent.sh — mimic a real omp coding session for the dashboard demo, the way
# omp actually works: by SHELLING OUT to real tools. omp is a Bun process that
# runs cat/grep/git/node/ls/find to read and search the codebase, run tests, and
# inspect git — so the file opens come from a TREE of child processes, each with
# its own comm. The jail confines the whole tree (inherited across exec), and the
# watcher attributes every open to the child that made it.
#
# Run JAILED (omp-jail-bin execs this as the "omp" stand-in). The agent's own
# reads are rare; the real work is delegated to children — which is what makes
# the dashboard show `git`, `cat`, `grep`, `node` in the feed, and occasionally a
# BLOCKED escape attributed to one of them (e.g. `git` reaching for ~/.gitconfig,
# `cat` for /etc/passwd).
set -u
P="${PROJECT:-$HOME/webapp}"
cd "$P" 2>/dev/null || true

# In-bounds source the agent works with, and out-of-bounds targets it may wander
# into (all blocked by the jail).
SRC="src/index.ts src/api/router.ts src/components/Button.tsx src/components/Modal.tsx src/lib/format.ts src/lib/db.ts tests/format.test.ts package.json tsconfig.json README.md"
OUT="$HOME/.ssh/id_rsa $HOME/.aws/credentials $HOME/.config/gh/hosts.yml /etc/passwd $HOME/.gitconfig $HOME/.bashrc"

tick=0
pick() { h=$(( (tick * 2654435761 + 40503) % 2147483647 )); n=$(( h % $# )); i=0; for a in "$@"; do [ "$i" -eq "$n" ] && { echo "$a"; return; }; i=$((i+1)); done; }

phase=0
while :; do
  phase=$((phase + 1))

  # "read the codebase" — omp shells out to cat/head to read source files.
  tick=$((tick+1)); cat   "$(pick $SRC)" >/dev/null 2>&1; sleep 0.05
  tick=$((tick+1)); head -n 20 "$(pick $SRC)" >/dev/null 2>&1; sleep 0.05

  # "search for a symbol" — grep across the tree (reads many files).
  grep -r "export" src >/dev/null 2>&1; sleep 0.06

  # "list / explore" — ls and find, like an agent orienting itself.
  ls -la src/components >/dev/null 2>&1
  find src -name "*.ts" >/dev/null 2>&1; sleep 0.05

  # "edit a file" — the agent itself writes (in-bounds).
  tick=$((tick+1)); f=$(pick $SRC); echo "// edit $phase" >> "$f" 2>/dev/null; sleep 0.06

  # "check git / run tests" — real git + node children reading the project.
  git status >/dev/null 2>&1
  git log --oneline -5 >/dev/null 2>&1
  node -e "require('"'"'fs'"'"').readFileSync('"'"'package.json'"'"')" >/dev/null 2>&1; sleep 0.08

  # WANDER — every other phase a child reaches OUTSIDE the project at a secret.
  # Attributed to that child (cat/grep/git), and BLOCKED by the jail. Different
  # tools so the feed shows a believable spread of who-tried-what.
  if [ $(( phase % 2 )) -eq 0 ]; then
    tick=$((tick+1)); cat  "$(pick $OUT)" >/dev/null 2>&1; sleep 0.05
    tick=$((tick+1)); grep "token" "$(pick $OUT)" >/dev/null 2>&1
  fi
  # occasionally git itself reaches for ~/.gitconfig (a classic real escape).
  [ $(( phase % 3 )) -eq 0 ] && cat "$HOME/.gitconfig" >/dev/null 2>&1

  sleep 0.15
done
