# agent-jail

<sub>(the command, binary, and scripts are still named `omp-jail` — rename in progress)</sub>

> **⚠️ Status: experimental (v0.x). Not yet production-hardened.**
> The core confinement works and survives an adversarial breakout suite, but it
> has only been verified on **one kernel/arch** (Linux 6.12, arm64, Debian 13)
> against a **shell stand-in**, not real `omp` across the environments users
> actually run. Treat it as a defence-in-depth layer to evaluate and help harden
> — **not** as a sole barrier you bet secrets on. See
> [Security & threat model](#security--threat-model) for exactly what is and
> isn't verified.

Confine [oh-my-pi (`omp`)](https://github.com/can1357/oh-my-pi) to a single
directory, and watch — live — every file it tries to open outside that
directory. One command does both halves:

- **Enforce.** A tiny [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
  launcher locks `omp` (and every process it spawns) to the current directory
  before it starts. Reads and writes outside the directory are refused by the
  kernel. No root, no container, no namespaces.
- **Observe.** A [yeet](https://yeet.cx) eBPF dashboard traces the whole `omp`
  process tree and shows each file open: in-bounds, a permitted system read, or
  an **escape attempt** — with the kernel's verdict next to it (`blocked` =
  the jail held). Sensitive targets (SSH keys, cloud creds, shell history) are
  flagged in red with a 🔥.

The enforcement is what protects you. The dashboard proves it's working, and
turns "my AI agent is sandboxed" into something you can watch and screenshot.

```
 ● agent-jail  ⊟ JAILED   ▏  dir ~/project
 ████████████░░░░░░░░░██  812 in-bounds  ▏  37 blocked  ▏  9.5K system  ▁▂▅▃▂ 41/s
 ⤳ escape attempts (outside the jail)            ◇ live file opens
  🔥 /etc/passwd            6×  blocked        · ./src/main.go        ok
  🔥 ~/.ssh/id_rsa          4×  blocked        · ./go.mod             ok
     ~/.aws/credentials     3×  blocked        ⮌ /etc/passwd          blocked
     /tmp/scratch.log       2×  blocked        ⮌ ~/.ssh/id_rsa        blocked
```

## Why

`omp` is a terminal coding agent: it reads your code, runs commands, and spawns
subagents. That's useful — and it's also a process with your full filesystem
permissions, driven by a model. `agent-jail` pins it to the project you're working
in, so a stray read of `~/.ssh/id_rsa` or `~/.aws/credentials` is refused by the
kernel rather than trusted to good behaviour.

## Install

Requires Linux ≥ 5.13 with Landlock enabled, a BTF kernel for eBPF, and `yeet`.
On macOS, run inside the Lima VM (see the top-level `CLAUDE.md`). Build needs
`clang`, `bpftool`, `make`, and a C compiler.

```sh
git clone <this repo> && cd omp-jail
make                       # builds the BPF object, the Landlock launcher, and the JS bundle
sudo ./scripts/omp-jail    # jail omp in the current directory and watch it
```

Put `scripts/omp-jail` on your `PATH` (or symlink it) to run `omp-jail` from
anywhere.

## Usage

```sh
omp-jail                      # jail omp in the current directory
omp-jail ~/project            # jail omp in ~/project
omp-jail --allow ~/.config/omp ~/project   # also permit one extra path (repeatable)
omp-jail --audit              # run UNCONFINED, watch what WOULD leak (see below)
omp-jail -- --some-omp-flag   # everything after -- is passed through to omp
```

The dashboard runs in your terminal; `omp` runs underneath it. Press **c** to
copy a shareable session summary, **q** to quit the watcher.

### Audit mode

`--audit` runs `omp` **without** the jail but with the watcher. Every escape
that would normally be blocked instead **succeeds** and is shown as `LEAKED` in
loud magenta. It's the before picture: run it once to see what `omp` reaches for
unconfined, then drop `--audit` to lock it down. Good for convincing yourself
(or a teammate) the jail earns its place.

## What it protects — and what it doesn't

**It confines the filesystem.** `omp` and every child it spawns (git, language
servers, subagents, anything) can read and write only within the target
directory. This is inherited at the kernel level across `exec`, so children
cannot escape it — verified against parent, child, and grandchild processes.

**It does not touch the network.** Landlock governs files, not sockets. `omp`'s
calls to model APIs keep working — which is what you want. "Restrict to this
directory" means the filesystem; if you need network confinement too, pair this
with a network namespace or firewall. The dashboard says so plainly so nobody
mistakes it for a network sandbox.

**Environment secrets are scrubbed.** Landlock is filesystem-only — it can't
stop a process from reading its own environment via `/proc/self/environ`. Since
agents often receive API keys that way, the launcher strips secret-bearing
variables (anything whose name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`,
`CREDENTIAL`, `AWS_`, `ANTHROPIC`, `OPENAI`, `GH_`, `AUTH`, …) before `exec`, so
the confined agent can't read them back. Residual caveat: a secret passed under
an unrecognised name still rides through — prefer giving a jailed agent its key
via a config file *inside* the directory rather than the environment.

### Adversary self-test

`scripts/adversary.sh` is a breakout suite: it plays a malicious agent trying
every filesystem escape — direct reads, `../../` traversal, symlinks out, the
`/proc/self/root` re-entry trick, hardlinks, parent-dir listing, exfil writes,
and reading its own environment. Run it both ways to see the jail work:

```sh
# baseline — unconfined, the attacks succeed (proves they're real)
sh scripts/adversary.sh                                   # ~10 leaks

# jailed — Landlock + the env scrub defeat every one
cp scripts/adversary.sh ~/project/ && \
  sudo bin/omp-jail-bin ~/project -- /bin/sh ~/project/adversary.sh   # 0 leaks
```

Verified result: **10 leaks unconfined → 0 leaks jailed**, including with a real
`ANTHROPIC_API_KEY` in the environment. The exit code is the leak count, so it
doubles as a regression test.

**System paths stay readable.** Programs need to load libraries and a few
loader/resolver files to run at all, so `/usr`, `/lib`, `/bin`, the dynamic
loader's `/etc/ld.so.*`, and the pseudo-filesystems `/dev` `/proc` `/sys` are
granted read-only. User secrets in `/etc` (`/etc/passwd`, `/etc/ssh/…`) are
**not** — only the specific loader/resolver files are. The dashboard counts
these permitted system reads separately ("system") and keeps them out of the
escape leaderboard so the genuine reaches at your data stand out.

**The `omp` binary's directory is not exposed.** The launcher grants execute on
the `omp` binary file itself, not its containing directory — so a secret sitting
next to `omp` (say in `~/.local/bin`) stays unreadable. (An earlier version
granted the whole directory; that leaked siblings and was fixed.)

## Security & threat model

Read this before relying on it for anything that matters.

**Threat it addresses:** an AI coding agent (or a tool it runs) reading or
writing files *outside the project directory* it was pointed at — e.g. wandering
into `~/.ssh`, `~/.aws`, `/etc`, or other projects. The enforcement is the
Linux **Landlock** LSM, applied to the process and inherited by every child.

**Explicitly out of scope** (it does *not* protect against these):
- **Network.** Landlock is filesystem-only. The agent can still make any network
  call. Exfiltration over the network is not prevented. Pair with a network
  namespace/firewall if you need that.
- **Resource abuse / fork bombs / CPU / memory.** No cgroup limits here.
- **Kernel exploits.** A kernel-level privilege escalation defeats any LSM.
- **What you explicitly `--allow`.** Extra allowed paths are fully accessible.
- **The agent's own environment.** Mitigated (secret-named env vars are scrubbed
  before exec) but not absolute — don't pass secrets to a jailed agent via env;
  use a config file inside the directory.

**What is actually verified, and what isn't — be honest with yourself:**

| Claim | Status |
|---|---|
| Blocks reads/writes outside the dir (parent, child, grandchild) | ✅ verified |
| Withstands traversal / symlink / procfs / hardlink / exfil tricks | ✅ verified (`make adversary`, 0 leaks) |
| Scrubs secret-bearing env vars before exec | ✅ verified |
| Works on **Linux 6.12 / arm64 / Debian 13** | ✅ verified |
| Works on x86_64, other distros, older kernels (5.13–6.x ABI drift) | ❌ **not yet tested** |
| Confines **real `omp`** (a Bun process) doing real work | ❌ **not yet tested** (verified against a shell stand-in only) |
| `--best-effort` fallback when Landlock is absent | ⚠️ runs **unconfined** — by design, but lightly tested |
| Clean attribution of **multiple concurrent `omp` sessions** | ❌ known-incomplete (see Coverage notes) |

**The unconfined-fallback footgun:** if the kernel lacks Landlock and you pass
`--best-effort`, the agent runs with **no confinement at all**. Without
`--best-effort` it refuses to run rather than give you a false sense of safety —
that default is intentional. Don't override it on untested kernels.

If you find a way out of the jail, that's a bug worth reporting — the adversary
suite (`scripts/adversary.sh`) is where new escape techniques should be added.

## Coverage notes

- **The watcher follows the process tree by descent.** It seeds on the root
  `omp` and marks every child at fork, so a `cat /etc/passwd` that `omp` shells
  out to is counted and shown — not just opens by the `omp` process itself.
- **A few of `omp`'s very first opens may land before the BPF attaches.** The
  watcher starts alongside `omp`; for an interactive agent the opens that matter
  happen during use, not in the first millisecond.
- **The escape classifier is a path-prefix compare**, the same model Landlock
  uses. It doesn't resolve symlinks, so a symlinked escape is classified by its
  literal path — but the kernel verdict (the open's return value) is always the
  ground truth for whether anything actually leaked.
- **Two `omp` sessions in the same directory** both appear in one dashboard.
  Uncommon; the honest trade-off for not needing a PID handshake.

## How it's built

```
src/jail/omp-jail.c       the Landlock launcher (enforcement) — dependency-free C
src/bpf/fileaccess.bpf.c  the eBPF tracer: openat/openat2 + fork/exit, retval capture
src/probes/               BPF data layer — binds maps, exposes reactive signals
src/components/            the TUI (header, escape leaderboard, live feed, footer)
src/lib/                  pure helpers — classification, layout, formatting, summary
scripts/omp-jail          the one-command wrapper that runs both halves
```

The launcher and the eBPF program are independent — the launcher enforces with
Landlock syscalls, the watcher observes with tracepoints. They cooperate only
in that both are pointed at the same `omp` process tree. Either works without
the other; together they enforce and prove.

Built from the [yeet script-template](https://github.com/yeet-src/script-template).
`make` runs three compilers: `clang`+`bpftool` for the BPF object, the system C
compiler for the launcher, and esbuild for the JS bundle.
