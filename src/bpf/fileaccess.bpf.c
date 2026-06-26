// fileaccess — trace every file-open a jailed program attempts, classify it as
// in-bounds or an escape, and capture the kernel's verdict (the open's return
// value). This is the OBSERVABILITY half of agent-jail: it does not block
// anything (a tracepoint fires after the kernel already decided), it witnesses.
//
// The story it tells, per open:
//   - which path the program reached for
//   - whether that path is under the jailed directory (in-bounds) or outside
//     it (an ESCAPE)
//   - what the kernel returned: fd >= 0 (the open succeeded) or a negative
//     errno like -EACCES (Landlock refused it)
//
// Put together: an escape with -EACCES is the jail doing its job, visibly.
// An escape that SUCCEEDS (fd >= 0) is a leak — which is exactly what you see
// in --no-jail / audit mode, proving what confinement buys you.
//
// Correlation: openat is two tracepoints, enter (has the path) and exit (has
// the return value). We stash the enter details keyed by pid_tgid and join
// them on exit. Single event emitted at exit, when the verdict is known.
//
// Filter: only threads whose comm starts with the target comm (default "omp")
// AND only after the daemon patches `target_prefix` (the jailed dir) into
// .data. The escape classification is a prefix compare done in-kernel.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "fileaccess.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ---- runtime knobs, patched live from JS via DataSec (.data section) ----
// The absolute, canonical jailed directory, e.g. "/home/u/proj". An open whose
// resolved-ish path does not start with this is an escape. Non-empty initial
// value keeps these in .data (not .bss) so the bound section stays "<obj>.data".
volatile char target_prefix[PATH_MAX] = "/\x00uninitialized";
volatile __u32 target_prefix_len = 1; // bytes of target_prefix that matter

// The comm to match (the jailed program). Default "omp". 16 bytes = TASK_COMM_LEN.
volatile char target_comm[TASK_COMM_LEN] = "omp";

// ---- maps ----
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// The traced process set: tgid -> 1 for the jailed root and every descendant.
// This is what makes the watcher see the WHOLE process tree, not just comm=omp.
// Seeded lazily when a comm-matching thread opens a file (the root omp), then
// propagated to children at fork. The jail (Landlock) already confines the
// whole tree; this map makes the dashboard's visibility match that reality, so
// a `cat /etc/passwd` that omp shells out to is counted and shown, not missed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);   // tgid
	__type(value, __u8);  // 1 = traced
} traced SEC(".maps");

// enter -> exit join table, keyed by pid_tgid (one in-flight open per thread).
// The path buffer is PATH_MAX (512B) — far over the 512B BPF stack limit — so
// this struct never lives on the stack: the enter handler fills it via a
// per-CPU scratch buffer, and the exit handler reads it straight from the map.
struct inflight {
	char path[PATH_MAX];
	__u32 dirfd_is_cwd; // 1 if the path was relative (AT_FDCWD) — best-effort note
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct inflight);
} inflight SEC(".maps");

// Per-CPU scratch for building an `inflight` without using stack space.
// A single slot per CPU; the enter handler runs to completion (no sleeping)
// before another open on the same CPU, so one slot is safe.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct inflight);
} scratch SEC(".maps");

// Force BTF emission of the event struct so the daemon can resolve
// btf_struct: "file_event" on the ring buffer.
struct file_event *_unused_event __attribute__((unused));

// Does this thread's comm match the target? Compares up to the first NUL or
// TASK_COMM_LEN. Returns 1 on match. Used only to SEED the traced set with the
// root omp; thereafter membership is by descent (the traced map), so children
// with different comms (cat, git, node…) are tracked too.
static __always_inline int comm_matches(void)
{
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));
#pragma unroll
	for (int i = 0; i < TASK_COMM_LEN; i++) {
		char t = target_comm[i];
		if (t == '\0')
			return 1; // matched the whole target prefix
		if (comm[i] != t)
			return 0;
	}
	return 1;
}

// Should this thread's process be traced? Yes if its tgid is already in the
// traced set, OR if its comm matches the target (the root omp) — in which case
// we seed it so descendants inherit tracking at fork. Returns 1 if traced.
static __always_inline int should_trace(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u8 *m = bpf_map_lookup_elem(&traced, &tgid);
	if (m)
		return 1;
	if (comm_matches()) {
		__u8 one = 1;
		bpf_map_update_elem(&traced, &tgid, &one, BPF_ANY);
		return 1;
	}
	return 0;
}

// Propagate tracking to children: when a traced process forks, mark the child
// traced too. This is what extends coverage across the whole subtree — exactly
// the set of processes Landlock confines.
SEC("tracepoint/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent = ctx->parent_pid;
	__u8 *m = bpf_map_lookup_elem(&traced, &parent);
	if (!m)
		return 0; // parent not traced -> child isn't either
	__u32 child = ctx->child_pid;
	__u8 one = 1;
	bpf_map_update_elem(&traced, &child, &one, BPF_ANY);
	return 0;
}

// Clean up the traced set when a process exits, so tgids don't accumulate or
// collide with future reuse.
SEC("tracepoint/sched/sched_process_exit")
int on_exit_proc(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&traced, &tgid);
	return 0;
}

// Is `path` under target_prefix? Returns 1 for in-bounds, 0 for escape.
// A simple byte-prefix compare: relative paths (not starting with '/') are
// treated as in-bounds, since they resolve against the (jailed) cwd. This is
// the same prefix model the Landlock rule uses; it can't follow symlinks, so
// it's a faithful-but-not-perfect classifier — good enough to count and rank,
// and the kernel verdict (retval) is the ground truth for whether it leaked.
// Max prefix bytes we compare. A jailed directory path longer than this is
// astronomically unlikely; capping keeps the verifier's state space small and
// the compare fully unrolled. Must be <= PATH_MAX and a power of two.
#define PREFIX_CMP_MAX 256

static __always_inline int is_in_bounds(const char *path)
{
	if (path[0] != '/')
		return 1; // relative -> resolves under cwd (jailed)

	__u32 n = target_prefix_len;
	if (n == 0)
		return 1; // not configured yet — don't cry escape on everything
	if (n > PREFIX_CMP_MAX)
		n = PREFIX_CMP_MAX; // compare at most this many bytes

	// Fully-unrolled, fixed-bound compare. Every index is masked to the buffer
	// size so the verifier sees each load as provably in-bounds, and the only
	// loop-carried branch is the early "matched whole prefix" exit.
#pragma clang loop unroll(full)
	for (int i = 0; i < PREFIX_CMP_MAX; i++) {
		if ((__u32)i >= n)
			return 1; // matched the whole prefix -> in bounds
		__u32 pi = (__u32)i & (PATH_MAX - 1);        // path[] is PATH_MAX
		__u32 ti = (__u32)i & (PREFIX_CMP_MAX - 1);  // prefix compared region
		char pc = path[pi];
		char tc = target_prefix[ti];
		if (pc != tc)
			return 0; // diverged before prefix end -> escape
	}
	return 1;
}

// Shared enter logic for openat / openat2 (same arg layout: dfd, filename).
// Uses the per-CPU scratch slot so the 512B path never touches the stack.
static __always_inline int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;

	__u32 zero = 0;
	struct inflight *inf = bpf_map_lookup_elem(&scratch, &zero);
	if (!inf)
		return 0;

	const char *upath = (const char *)ctx->args[1];
	long n = bpf_probe_read_user_str(&inf->path, sizeof(inf->path), upath);
	if (n < 0)
		return 0;
	inf->dirfd_is_cwd = ((long)ctx->args[0] == AT_FDCWD);

	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&inflight, &id, inf, BPF_ANY);
	return 0;
}

// Shared exit logic. Reserves the ring entry first, copies path into ring
// memory (not stack), joins the verdict, submits.
static __always_inline int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct inflight *inf = bpf_map_lookup_elem(&inflight, &id);
	if (!inf)
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&inflight, &id);
		return 0; // ring full — drop is the backpressure
	}
	e->pid = id >> 32;
	e->ret = (__s64)ctx->ret; // fd >= 0, or negative errno
	e->in_bounds = is_in_bounds(inf->path);
	e->relative = inf->dirfd_is_cwd;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->path, inf->path, sizeof(e->path));
	bpf_ringbuf_submit(e, 0);

	bpf_map_delete_elem(&inflight, &id);
	return 0;
}

// ---- openat ----
SEC("tracepoint/syscalls/sys_enter_openat")
int on_enter_openat(struct trace_event_raw_sys_enter *ctx) { return handle_enter(ctx); }

SEC("tracepoint/syscalls/sys_exit_openat")
int on_exit_openat(struct trace_event_raw_sys_exit *ctx) { return handle_exit(ctx); }

// ---- openat2 (newer libc/Bun may use this) ----
SEC("tracepoint/syscalls/sys_enter_openat2")
int on_enter_openat2(struct trace_event_raw_sys_enter *ctx) { return handle_enter(ctx); }

SEC("tracepoint/syscalls/sys_exit_openat2")
int on_exit_openat2(struct trace_event_raw_sys_exit *ctx) { return handle_exit(ctx); }
