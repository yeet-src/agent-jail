// jail — the unified LSM-BPF core of agent-jail. One program both ENFORCES and
// OBSERVES: the lsm/file_open hook decides whether each open is allowed (and
// returns -EPERM to actually block it) and emits the decision to the ring
// buffer the dashboard reads. There is no separate Landlock launcher and no
// separate watcher; this hook is both.
//
// Scoping: enforcement applies only to processes in the `jailed` map. The
// launcher enrolls the root tgid (writing its own pid + the jailed dir) before
// exec; sched_process_fork propagates membership to children, so the whole omp
// process tree is covered without comm guessing. Unenrolled processes are never
// affected.
//
// Decision per open (for a jailed process):
//   - path under the jailed dir            -> allow, in_bounds
//   - path under a system/scratch prefix   -> allow, system  (so libc/loader work)
//   - anything else                        -> BLOCK (-EPERM), escape
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "jail.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// ---- runtime knobs, patched from JS via DataSec (.data) ----
// The jailed directory and the comm to auto-enroll. The launcher/JS patches
// these at startup. A process whose comm matches gets self-enrolled into the
// `jailed` map on its first open (zero-race), and JS may also write an explicit
// tgid into `jailed` for precise PID scoping. Non-empty init keeps these in
// .data (not .bss) so the bound section name stays "<obj>.data".
volatile char target_prefix[PREFIX_MAX] = "/\x00uninitialized";
volatile __u32 target_prefix_len = 1;
volatile char target_comm[TASK_COMM_LEN] = "omp";
// Audit mode: when == 1, the hook still classifies and emits every decision for
// the dashboard but NEVER returns -EPERM (watch what would be blocked, jail
// effectively off). Initialized non-zero (0xFF = "enforce") so it lands in
// .data, not .bss, where DataSec.patch can reach it. JS patches 0/1.
volatile __u32 audit_mode = 0xFF;

// ---- maps ----
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// tgid -> jail_cfg for every jailed process (root + descendants). The launcher
// seeds the root; on_fork copies the parent's cfg to each child.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct jail_cfg);
} jailed SEC(".maps");

// Per-CPU scratch for building a jail_cfg at comm-match time (the .data prefix
// copied into a map-backed buffer the verifier is happy to pass around).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct jail_cfg);
} cfg_scratch SEC(".maps");

// Force BTF emission of file_event so the daemon can resolve btf_struct.
struct file_event *_unused_event __attribute__((unused));

// System/scratch path prefixes a jailed program may read even though they're
// outside the project dir: loader, libraries, pseudo-fs, temp. Mirrors the
// Landlock launcher's allow-list and the JS classifier. Without these, a jailed
// program can't even load libc.
#define N_SYS 11
static const char sys_prefixes[N_SYS][12] = {
	"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/",
	"/etc/ld.so", "/dev/", "/proc/", "/sys/", "/tmp/", "/run/",
};

// Does `path` start with `pfx` (a NUL-terminated literal, at most `cap` bytes)?
static __always_inline int has_prefix(const char *path, const char *pfx, int cap)
{
#pragma unroll
	for (int i = 0; i < cap; i++) {
		char c = pfx[i];
		if (c == '\0')
			return 1; // matched the whole prefix
		if (path[i] != c)
			return 0;
	}
	return 1;
}

// Does `needle` (a short literal) appear anywhere in the first JPATH_MAX bytes
// of `path`? Bounded, verifier-friendly substring search.
static __always_inline int contains(const char *path, const char *needle, int nlen)
{
#pragma unroll
	for (int i = 0; i + 1 < JPATH_MAX; i++) {
		int match = 1;
#pragma unroll
		for (int j = 0; j < nlen; j++) {
			if (path[i + j] != needle[j]) { match = 0; break; }
		}
		if (match)
			return 1;
	}
	return 0;
}

// Cross-process introspection under /proc that leaks another task's secrets:
// environ (env vars), mem (address space), maps (layout), cmdline (args). Even
// though /proc is broadly allowed for the runtime, these are real reads at other
// processes and must NOT be treated as benign system access.
static __always_inline int is_sensitive_proc(const char *path)
{
	if (!has_prefix(path, "/proc/", 12))
		return 0;
	return contains(path, "/environ", 8) || contains(path, "/mem", 4) ||
	       contains(path, "/maps", 5) || contains(path, "/cmdline", 8);
}

static __always_inline int is_system_path(const char *path)
{
	if (is_sensitive_proc(path))
		return 0; // a sensitive /proc read is an escape, not benign system access
#pragma unroll
	for (int s = 0; s < N_SYS; s++) {
		if (has_prefix(path, sys_prefixes[s], 12))
			return 1;
	}
	return 0;
}

// Is `path` under the jailed prefix? Compares up to prefix_len, capped.
static __always_inline int under_prefix(const char *path, const struct jail_cfg *cfg)
{
	__u32 n = cfg->prefix_len;
	if (n == 0 || n > PREFIX_MAX)
		return 0;
#pragma unroll
	for (int i = 0; i < PREFIX_MAX; i++) {
		if ((__u32)i >= n)
			return 1; // matched the whole prefix
		if (path[i] != cfg->prefix[i])
			return 0;
	}
	return 1;
}

// Does the current process's comm match the configured target?
static __always_inline int comm_matches(void)
{
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));
#pragma unroll
	for (int i = 0; i < TASK_COMM_LEN; i++) {
		char t = target_comm[i];
		if (t == '\0')
			return 1;
		if (comm[i] != t)
			return 0;
	}
	return 1;
}

// Resolve the jail config for the current process. A process is jailed if its
// tgid is in the `jailed` map (root written by JS, or a child propagated at
// fork) OR its comm matches the target. On a comm match we ENROLL it into the
// `jailed` map (keyed by tgid) so that sched_process_fork propagates membership
// to children — without this write, a child the agent execs (e.g. `cat`) has a
// different comm and would never be covered. `out` is scratch used to build the
// value. NULL means "not a jailed process".
static __always_inline struct jail_cfg *jail_for_current(__u32 tgid, struct jail_cfg *out)
{
	struct jail_cfg *cfg = bpf_map_lookup_elem(&jailed, &tgid);
	if (cfg)
		return cfg;
	if (!comm_matches() || target_prefix_len == 0 || target_prefix_len > PREFIX_MAX)
		return NULL;
	// Copy the .data prefix byte-by-byte (indexed volatile reads). A bulk
	// __builtin_memcpy from a casted volatile array let the compiler collapse
	// the .data section to size 0.
#pragma unroll
	for (int i = 0; i < PREFIX_MAX; i++)
		out->prefix[i] = target_prefix[i];
	out->prefix_len = target_prefix_len;
	// Enroll the root so children inherit the jail at fork.
	bpf_map_update_elem(&jailed, &tgid, out, BPF_ANY);
	struct jail_cfg *stored = bpf_map_lookup_elem(&jailed, &tgid);
	return stored ? stored : out;
}

// ---- the enforcer + emitter ----
SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return ret; // respect an earlier LSM denial

	__u32 zero = 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct jail_cfg *cfgbuf = bpf_map_lookup_elem(&cfg_scratch, &zero);
	if (!cfgbuf)
		return 0;
	struct jail_cfg *cfg = jail_for_current(tgid, cfgbuf);
	if (!cfg)
		return 0; // not a jailed process — never interfere

	// Resolve the path into a STACK buffer. bpf_d_path into a stack buffer is
	// what actually enforces; reading the path from a map-value pointer did not.
	char path[JPATH_MAX] = {};
	long n = bpf_d_path(&file->f_path, path, sizeof(path));
	if (n < 0)
		return 0; // couldn't resolve — don't block on uncertainty

	int in_bounds = under_prefix(path, cfg);
	int system = !in_bounds && is_system_path(path);
	int escape = !in_bounds && !system;

	// Emit the decision for the dashboard (skip benign system noise so the
	// stream and leaderboard stay about real reaches).
	if (!system) {
		struct file_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
		if (out) {
			out->pid = tgid;
			out->in_bounds = in_bounds;
			out->system = system;
			out->blocked = escape;
			bpf_get_current_comm(&out->comm, sizeof(out->comm));
			__builtin_memcpy(out->path, path, sizeof(out->path));
			bpf_ringbuf_submit(out, 0);
		}
	}

	// Audit mode observes but never blocks: report the would-be verdict above,
	// then allow the open. (`blocked` in the emitted event still shows what a
	// live jail would have done.)
	if (audit_mode == 1)
		return 0;

	// Force the verdict through an asm identity so clang doesn't fuse the
	// comparisons into the return as -(bits) (unsigned, out of the [-4095,0]
	// range the LSM verifier demands). With the barrier it compiles to a clean
	// select of two known constants.
	asm volatile("" : "+r"(escape));
	return escape ? -EPERM : 0;
}

// ---- subtree propagation ----
SEC("tracepoint/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent = ctx->parent_pid;
	struct jail_cfg *cfg = bpf_map_lookup_elem(&jailed, &parent);
	if (!cfg)
		return 0; // parent not jailed -> child isn't either
	__u32 child = ctx->child_pid;
	bpf_map_update_elem(&jailed, &child, cfg, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&jailed, &tgid);
	return 0;
}
