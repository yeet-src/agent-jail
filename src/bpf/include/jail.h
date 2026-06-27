// Shared definitions for the LSM-BPF jail. The struct layout here is what the
// JS side reads via btf_struct "file_event"; keep it in sync with probes/.
#ifndef JAIL_H
#define JAIL_H

#define TASK_COMM_LEN 16

// Resolved path buffer for bpf_d_path. 256 covers the overwhelming majority of
// real paths; longer paths are truncated for display but still classified by
// their (truncated) prefix. Power of two keeps the verifier's unrolled compares
// cheap.
#define JPATH_MAX 256

// Max bytes of the jail-dir prefix we compare against (a jailed project path
// longer than this is astronomically unlikely). Must be <= JPATH_MAX.
#define PREFIX_MAX 200

// Per-jailed-process config, keyed by tgid in the `jailed` map. The root is
// enrolled by the launcher writing its own tgid; children inherit at fork.
struct jail_cfg {
	char prefix[PREFIX_MAX]; // absolute jailed dir, e.g. "/home/u/project"
	__u32 prefix_len;        // meaningful bytes of prefix
};

// One open decision, emitted from the lsm/file_open hook. `blocked` is the
// ground truth: this hook MADE the decision, so the verdict is exact, not an
// after-the-fact errno read.
struct file_event {
	__u32 pid;
	__s32 in_bounds; // 1 = under jail dir, 0 = outside
	__s32 system;    // 1 = permitted system/scratch path (allowed despite outside)
	__s32 blocked;   // 1 = this open was refused (-EPERM)
	char comm[TASK_COMM_LEN];
	char path[JPATH_MAX];
};

#endif // JAIL_H
