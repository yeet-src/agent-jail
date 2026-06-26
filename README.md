# `agent-jail`

> **A sandbox for your coding agent.** Lock `omp` to one directory with the kernel, and watch every file it touches, including the ones it tries to reach outside.

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux">
  <img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="yeet + eBPF">
  <img src="https://img.shields.io/badge/enforced%20by-Landlock-3DA639" alt="Landlock">
  <img src="https://img.shields.io/badge/status-experimental-FF8700" alt="experimental">
  <img src="https://img.shields.io/badge/category-security-0B5394" alt="security">
  <a href="https://discord.gg/dYZu9PjKB"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

![agent-jail live demo: an agent works inside its project while reaches at ~/.ssh, ~/.aws and /etc/passwd climb the escape leaderboard, every one blocked](assets/agent-jail.gif)

**`agent-jail` confines [oh-my-pi (`omp`)](https://github.com/can1357/oh-my-pi), and every process it spawns, to a single directory using the Linux Landlock LSM, while an eBPF dashboard shows each file it opens, live.**

> [!TIP]
> Two halves, working together. **Landlock** does the blocking: reads and writes outside the project directory are refused by the kernel. **eBPF** does the watching: every open is shown classified as in-bounds, a permitted system path, or an escape attempt, with the kernel's verdict beside it. The enforcement protects you; the dashboard proves it's working.

> [!WARNING]
> **Experimental (v0.x).** The core confinement holds (it survives an adversarial breakout suite at zero leaks), but it has only been verified on **one kernel/arch** (Linux 6.12, arm64, Debian 13) against a shell stand-in, not real `omp` across the environments people actually run. Treat it as a defence-in-depth layer to evaluate and help harden, not a sole barrier you bet secrets on. See [Honest caveats](#honest-caveats).

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
git clone https://github.com/yeet-src/agent-jail.git && cd agent-jail
make                              # builds the BPF object, the Landlock launcher, and the JS bundle
sudo ./scripts/agent-jail ~/project   # jail omp in ~/project and watch it live
```
<sub>[Manual install guide](https://yeet.cx/docs/install/manual-installation) | Linux only</sub>

The dashboard runs in your terminal; `omp` runs underneath it, jailed. `↑` / `↓` (or PgUp/PgDn, `g` / `G`) moves the highlighted row in the escape list, `c` copies a shareable session summary, and `q` quits. Put `scripts/agent-jail` on your `PATH` to run it from anywhere.

## A 60-second primer on jailing an agent

A coding agent reads your code, runs commands, and spawns subagents, all with your full filesystem permissions and driven by a model. `agent-jail` pins it to the project it's working in, so a stray read of `~/.ssh/id_rsa` dies at the kernel instead of being trusted to good behaviour.

| Term | What it means here |
|---|---|
| **Landlock** | A Linux security module (mainline since 5.13) that lets an unprivileged process drop its own filesystem access. No root, no container, no namespaces. |
| **inherited jail** | The restriction is applied *before* `omp` starts and is inherited across `exec`, so every child it spawns (`git`, `node`, `tsc`, a subagent) is confined too, and cannot lift it. |
| **escape attempt** | An open of a path *outside* the jailed directory. The kernel refuses it; the dashboard records it. |
| **reached** | An escape whose open *succeeded*: it got through. Under a working jail this is always 0; you see it only in `--audit` mode (no jail). |
| **sensitive target** | A known high-value path (`~/.ssh`, `~/.aws`, `~/.config/gh`, shell history, `/etc/passwd`). Flagged loudly with 🔥. |

The thing that makes Landlock trustworthy where a naive path filter is not: it judges the **resolved inode**, not the path string. So `../../etc/passwd`, a symlink pointing out, and the `/proc/self/root` re-entry trick all resolve to the same forbidden file and are all refused.

## Common use cases

Developers running an AI coding agent on a real codebase, and anyone evaluating what an agent actually does to the filesystem.

- Running `omp` on a work repo and you'd rather it never see `~/.ssh` or `~/.aws`.
- Auditing a new agent or tool before trusting it: what does it reach for?
- Demonstrating, on camera, that an agent is sandboxed, watching the kernel block its escapes.
- Running an agent headless in CI or a background job and logging any out-of-bounds reach.

## What you're looking at

A status masthead across the top, two framed panels below it, and a key-hint footer.

**Masthead.** The jail state (`⊟ JAILED` / `⚠ AUDIT`), the directory, a one-line ROI verdict (`✓ 37 escape attempts blocked, the jail is holding`), and a proportion bar splitting every open into in-bounds / system / blocked / reached, with a live access-rate sparkline.

**Escape attempts.** The headline panel: paths `omp` reached for *outside* the directory, ranked by attempt count. Sensitive targets wear a 🔥. A verdict badge on the right shows `blocked` (the jail held) or `reached` (it got through, in audit mode). `↑` / `↓` moves a highlighted cursor through the list; the pane scrolls to follow it.

**Live opens.** The stream of recent opens as they happen: in-bounds work scrolling by in green, interleaved with the occasional blocked escape, each attributed to the child process that made it (`cat`, `git`, `grep`), since the jail confines the whole tree.

Benign system and scratch reads (`/usr`, `/lib`, `/tmp`) are counted separately as "system" and kept out of the escape leaderboard, so the genuine reaches at your data stand out.

## How it works

The enforcement and the observation are two independent mechanisms pointed at the same process tree. Landlock blocks; eBPF watches. Either works without the other.

**The Landlock launcher** (`src/jail/agent-jail.c`). A tiny, dependency-free C program that builds a default-deny filesystem ruleset, grants read+write under the target directory plus read-only on the system paths a program needs to run, locks itself, then `execve`s `omp`. The lock is inherited and irreversible.

**The BPF side.** One object, tracepoints on the open and process-lifecycle paths, one ring buffer.

| Program | Hook | Captures |
|---|---|---|
| tracepoint | `sys_enter/exit_openat`, `openat2` | Every file open + the kernel's return value (the verdict) |
| tracepoint | `sched_process_fork`, `sched_process_exit` | Process-tree membership, so children are attributed too |

The open programs read the path and the return value. A `traced` map seeded on `omp` and propagated at fork is how a `cat /etc/passwd` that `omp` shells out to is caught and attributed, not just opens by `omp` itself.

**The JS side.**

- `src/probes/` is the only BPF-aware code. It loads the object, patches the jailed directory into the program, subscribes to the ring buffer once, and rolls the stream into plain reactive signals.
- `src/components/` and `src/lib/` are pure presentation reading those signals: the masthead, the two panels, the path classifier, the theme.
- `src/main.jsx` wires them together and owns keyboard input.

## Requirements

> [!IMPORTANT]
> Linux ≥ 5.13 with Landlock enabled (`CONFIG_SECURITY_LANDLOCK=y`) for the jail, and a BTF kernel (`CONFIG_DEBUG_INFO_BTF=y`) for the eBPF watcher. Both are on by default on current Ubuntu, Debian, and Fedora. The build needs `clang`, `bpftool`, `make`, and a C compiler.

The yeet daemon handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh` installs it. On macOS, run inside the Lima VM.

## Honest caveats

> [!NOTE]
> What `agent-jail` does not do, and where it is unproven.

- It confines the **filesystem, not the network.** Landlock governs files, not sockets. `omp`'s calls to model APIs keep working, which is what you want, but exfiltration over the network is not prevented. Pair with a network namespace or firewall if you need that.
- It is **verified on one kernel/arch against a shell stand-in**, not real `omp` under load across distros and kernel versions. The Landlock ABI differs across 5.13 to 6.x; treat untested kernels with suspicion.
- `--best-effort` runs **unconfined** if Landlock is unavailable. That's by design, so a missing LSM doesn't silently break your run, but it means no protection. Without it the launcher refuses rather than give false safety.
- Environment secrets are **scrubbed before exec** (any var whose name contains `KEY`, `TOKEN`, `SECRET`, `AWS_`, `ANTHROPIC`, and similar), because Landlock can't stop a process reading its own `/proc/self/environ`. A secret passed under an unrecognised name still rides through, so prefer a config file inside the directory.
- It reads paths and verdicts, not file **contents**. It tells you what was reached for, not what was in it.

## Community questions

**Do I need to change `omp` or how I run it?**
No. `agent-jail` wraps the launch: it applies the jail, then execs `omp` normally. The agent runs unmodified and inherits a restriction it can't undo.

**Does the jail cover the tools `omp` shells out to?**
Yes. Landlock is inherited across `exec`, so `git`, `node`, a subagent, every child, is confined to the same directory. Verified against parent, child, and grandchild processes.

**What about an interpreted install (`bun run omp`)?**
The prebuilt single-file binary is the smoothest path (the jail grants execute on one file). For an interpreted install, point `--runtime ~/.bun` at the runtime root to grant it read-only so it can load itself, without opening it for writes.

**Can I run it without the dashboard?**
Yes. `--headless` skips the TUI and streams one structured line per escape attempt to stdout (JSON, or `--format text`), for background runs and log shipping.

**How do I know it actually blocks anything?**
`make adversary` runs a breakout suite (traversal, symlinks, `/proc/self/root`, hardlinks, exfil writes, env reads), first unconfined (the attacks succeed) then jailed (every one blocked). Verified result: ~10 leaks down to 0.

**Is it production-ready?**
Not yet; see the experimental note and caveats. It's a working, adversarially-tested prototype shared early so the `omp` community can try it and help harden it.

## Building from source

```sh
make          # clang + bpftool compile the BPF, cc builds the launcher, esbuild bundles the JS
make adversary # build, then run the jail-breakout self-test (must report 0 leaks)
make clean
```

Requires `clang`, `bpftool`, and a C compiler for the BPF object and the launcher, plus `node` and `npm` for the esbuild bundle step. The compiled BPF object, the launcher binary, and the bundled JS are gitignored; `make` regenerates them.

## License

The BPF program is `SEC("license") = "Dual BSD/GPL"`, required because it uses GPL-only kernel helpers.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=agent-jail), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/dYZu9PjKB?utm_source=github&utm_medium=readme&utm_campaign=agent-jail).
