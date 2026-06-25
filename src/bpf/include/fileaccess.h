// Shared definitions for the fileaccess tracer. Included by the .bpf.c; the
// struct layout here is what the JS side reads via btf_struct "file_event".
#ifndef FILEACCESS_H
#define FILEACCESS_H

#define TASK_COMM_LEN 16

// Path buffer size. The real kernel PATH_MAX is 4096, but copying 4KB per open
// into the ring buffer (and per in-flight slot) is wasteful — almost every
// real path fits comfortably below this. Truncated paths are still classified
// and counted correctly; only the displayed tail is clipped. Keep it a power
// of two so the #pragma unroll bound is friendly to the verifier.
#define PATH_MAX 512

// AT_FDCWD from fcntl.h — relative opens pass this as the dirfd.
#define AT_FDCWD -100

// One completed open attempt, emitted at syscall exit when the verdict is
// known. `ret` is the raw return value: an fd (>= 0) means the open SUCCEEDED;
// a negative value is -errno (e.g. -13 = -EACCES, Landlock refused it).
struct file_event {
	__u32 pid;
	__s32 in_bounds; // 1 = path under jailed dir, 0 = escape attempt
	__s32 relative;  // 1 = opened relative to cwd (AT_FDCWD)
	__s64 ret;       // fd >= 0 on success, negative errno on failure
	char comm[TASK_COMM_LEN];
	char path[PATH_MAX];
};

#endif // FILEACCESS_H
