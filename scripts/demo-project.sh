#!/bin/sh
# demo-project.sh — scaffold a realistic project tree + decoy secrets for the
# agent-jail demo, so a recording looks like an actual coding session rather than
# a synthetic loop. Idempotent: safe to re-run.
set -eu
P="${1:-$HOME/webapp}"

rm -rf "$P"
mkdir -p "$P/src/components" "$P/src/lib" "$P/src/api" "$P/tests" "$P/public" "$P/.git"

cat > "$P/src/index.ts" <<'EOF'
import { Router } from "./api/router";
import { db } from "./lib/db";
export function main() { db.connect(); Router.start(); }
EOF
cat > "$P/src/api/router.ts" <<'EOF'
import { Button } from "../components/Button";
export const Router = { start() { /* mount routes */ } };
EOF
printf 'export function Button(){ return null; }\n'  > "$P/src/components/Button.tsx"
printf 'export function Modal(){ return null; }\n'   > "$P/src/components/Modal.tsx"
printf 'export const fmt = (s)=>String(s).trim();\n' > "$P/src/lib/format.ts"
printf 'export const db = { connect(){}, query(){} };\n' > "$P/src/lib/db.ts"
cat > "$P/tests/format.test.ts" <<'EOF'
import { fmt } from "../src/lib/format";
test("fmt trims", () => { /* ... */ });
EOF
cat > "$P/package.json" <<'EOF'
{ "name": "webapp", "scripts": { "build": "tsc", "test": "vitest" } }
EOF
printf '{ "compilerOptions": { "strict": true } }\n' > "$P/tsconfig.json"
printf '# Webapp\n\nA sample project the agent is working on.\n'    > "$P/README.md"
printf 'node_modules/\ndist/\n.env\n'                 > "$P/.gitignore"
printf 'DATABASE_URL=postgres://localhost/dev\n'      > "$P/.env.example"
printf 'ref: refs/heads/main\n'                       > "$P/.git/HEAD"

# Decoy secrets OUTSIDE the project — what a wandering agent shouldn't reach.
mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.config/gh"
printf 'ssh-rsa AAAA...realkey\n'                                          > "$HOME/.ssh/id_rsa"
printf '[default]\naws_access_key_id=AKIAREAL\naws_secret_access_key=xyz\n'> "$HOME/.aws/credentials"
printf 'github.com:\n  oauth_token: ghp_realtoken\n'                       > "$HOME/.config/gh/hosts.yml"

echo "project: $P ($(find "$P" -type f | wc -l | tr -d ' ') files)"
echo "decoys:  ~/.ssh/id_rsa  ~/.aws/credentials  ~/.config/gh/hosts.yml"
