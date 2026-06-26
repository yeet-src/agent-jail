// agent-jail — confine a process to one directory tree with Landlock, then exec it.
//
// This is the ENFORCEMENT half of the agent-jail tool. It is deliberately tiny
// and dependency-free: three Landlock syscalls and an execve. Read it top to
// bottom — there is nothing hidden.
//
// What it does:
//   1. Build a default-DENY Landlock ruleset covering filesystem access.
//   2. Allow read+write beneath the target directory (the "current dir").
//   3. Allow read+execute on the system paths a program needs to run at all
//      (loader, libs, the omp binary itself), plus any --allow extras.
//   4. landlock_restrict_self() — the lock clicks shut, irreversibly, for this
//      process and every child it ever spawns.
//   5. execve() the real command. It wakes up already jailed and cannot undo it.
//
// Landlock is an unprivileged LSM (mainline since Linux 5.13). No root, no
// namespaces, no container. If the kernel lacks Landlock we fail loud unless
// --best-effort is passed, in which case we warn and run unconfined (so the
// eBPF watcher can still show what WOULD leak — useful for --dry-run).
//
// Scope, stated plainly: Landlock governs the FILESYSTEM only. Network access
// (e.g. an AI agent calling a model API) is untouched by design — you want
// those calls to work. "Restrict to this directory" means filesystem paths.
//
// Build: cc -O2 -Wall -o bin/agent-jail src/jail/agent-jail.c   (see Makefile)

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// These syscalls are recent enough that glibc may not wrap them yet; call them
// directly so we build on any toolchain with the linux/landlock.h header.
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

static inline long ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                                     size_t size, __u32 flags) {
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline long ll_add_rule(int fd, enum landlock_rule_type type,
                               const void *attr, __u32 flags) {
	return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}
static inline long ll_restrict_self(int fd, __u32 flags) {
	return syscall(__NR_landlock_restrict_self, fd, flags);
}

// Substrings marking an environment variable as secret-bearing. Landlock
// confines the filesystem but not a process's own environment: a jailed agent
// can read its own variables back via /proc/self/environ (the adversary suite
// found exactly this). Since agents commonly receive API keys via the env, we
// scrub these before exec so the secret never reaches the confined process.
// Matched as a case-insensitive substring of the variable NAME.
static const char *const SECRET_ENV_NEEDLES[] = {
	"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
	"AWS_", "ANTHROPIC", "OPENAI", "GEMINI", "GH_", "GITHUB_",
	"SESSION", "COOKIE", "PRIVATE", "AUTH",
};

static int name_is_secret(const char *name, size_t namelen) {
	for (size_t i = 0; i < sizeof(SECRET_ENV_NEEDLES) / sizeof(*SECRET_ENV_NEEDLES); i++) {
		const char *needle = SECRET_ENV_NEEDLES[i];
		size_t nl = strlen(needle);
		if (nl > namelen)
			continue;
		for (size_t off = 0; off + nl <= namelen; off++) {
			size_t k = 0;
			for (; k < nl; k++) {
				char a = name[off + k];
				char b = needle[k];
				if (a >= 'a' && a <= 'z')
					a -= 32; // upper-case the env name char
				if (a != b)
					break;
			}
			if (k == nl)
				return 1;
		}
	}
	return 0;
}

// Remove secret-bearing variables from the environment before exec, so the
// confined process (and anything reading its /proc/self/environ) cannot see
// them. Walks `environ`, unsetting matches. Best-effort: a residual leak is
// possible for any secret passed under a name we don't recognise, which is why
// the README also says not to rely on env for secrets in a jail.
extern char **environ;
static void scrub_secret_env(void) {
	// Collect names first; unsetenv mutates environ as we go.
	for (int pass = 0; pass < 64; pass++) {
		int removed = 0;
		for (char **e = environ; e && *e; e++) {
			const char *eq = strchr(*e, '=');
			if (!eq)
				continue;
			size_t namelen = (size_t)(eq - *e);
			if (namelen == 0 || namelen > 256)
				continue;
			char name[257];
			memcpy(name, *e, namelen);
			name[namelen] = '\0';
			if (name_is_secret(name, namelen)) {
				unsetenv(name);
				removed = 1;
				break; // environ shifted; restart the scan
			}
		}
		if (!removed)
			return;
	}
}

// All filesystem access rights we know how to name. We grant subsets of this:
// the full set under the target dir, a read/execute subset on system paths.
// Newer ABI versions add rights (refer, truncate, ioctl_dev); we mask the
// ruleset's handled rights down to what THIS kernel's ABI supports so the
// create call doesn't fail on an older kernel.
#define ACCESS_FS_ALL                                                          \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |               \
	 LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |              \
	 LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |          \
	 LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |              \
	 LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |              \
	 LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |            \
	 LANDLOCK_ACCESS_FS_MAKE_SYM)

#define ACCESS_FS_READ                                                         \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |               \
	 LANDLOCK_ACCESS_FS_READ_DIR)

// System DIRECTORIES safe to grant read+execute as a whole — code and libs,
// no user secrets. We deliberately do NOT grant /etc wholesale: that would
// leak /etc/passwd, /etc/ssh/, etc., which defeats the point of the jail.
// Missing entries are skipped quietly (not every distro has every path).
static const char *const SYS_RO_DIRS[] = {
    "/usr", "/lib", "/lib64", "/bin", "/sbin",
};

// Specific /etc FILES a dynamically-linked program needs to start and resolve
// names — granted individually so the rest of /etc stays unreadable. The
// loader needs ld.so.{cache,preload}; name resolution and tz are common
// enough that omitting them breaks ordinary programs. Each is a single file,
// not a tree, so nothing else under /etc becomes visible.
static const char *const SYS_RO_FILES[] = {
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/localtime",
};

// Pseudo-filesystem paths granted read+write so the runtime works: /dev for
// null/urandom/tty, /proc and /sys for self-inspection. These expose no
// on-disk user data; an AI agent reading /proc/self is benign. Granted as
// trees because their contents are generated, not secrets on disk.
static const char *const SYS_RW_PSEUDO[] = {
    "/dev",
    "/proc",
    "/sys",
};

static void usage(const char *argv0) {
	fprintf(stderr,
	        "usage: %s [--allow PATH]... [--runtime PATH]... [--best-effort] [--no-jail] DIR -- CMD [ARGS...]\n"
	        "       %s [opts] DIR CMD [ARGS...]\n"
	        "\n"
	        "Confine CMD to DIR (read+write) plus system paths (read-only), then exec it.\n"
	        "  --allow PATH    also grant read+write beneath PATH (repeatable)\n"
	        "  --runtime PATH  grant read+EXECUTE beneath PATH for an interpreter/runtime\n"
	        "                  (e.g. --runtime ~/.bun for `bun run omp`); repeatable\n"
	        "  --best-effort   if Landlock is unavailable, warn and run UNCONFINED\n"
	        "  --no-jail       skip Landlock entirely (audit mode; run unconfined)\n"
	        "\n"
	        "Tip: a prebuilt single-file binary needs no --runtime — it's the smoothest\n"
	        "install. Use --runtime only for interpreted installs (bun/node/python).\n",
	        argv0, argv0);
}

// Add one path to the ruleset with the given rights. Returns 0 on success,
// -1 on a hard error, 1 if the path simply doesn't exist (caller decides).
static int allow_path(int ruleset_fd, const char *path, __u64 rights) {
	struct landlock_path_beneath_attr pb = {.allowed_access = rights};
	pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
	if (pb.parent_fd < 0) {
		return (errno == ENOENT) ? 1 : -1;
	}
	int rc = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	int saved = errno;
	close(pb.parent_fd);
	if (rc) {
		errno = saved;
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {
	const char *allow_extra[64]; // read+write extra dirs (--allow)
	int n_allow = 0;
	const char *runtime_extra[64]; // read+execute interpreter/runtime trees (--runtime)
	int n_runtime = 0;
	int best_effort = 0;
	int no_jail = 0;

	// --- parse args up to DIR, then optional "--", then CMD... ---
	int i = 1;
	for (; i < argc; i++) {
		if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc) {
			if (n_allow < (int)(sizeof(allow_extra) / sizeof(*allow_extra)))
				allow_extra[n_allow++] = argv[++i];
		} else if (strcmp(argv[i], "--runtime") == 0 && i + 1 < argc) {
			if (n_runtime < (int)(sizeof(runtime_extra) / sizeof(*runtime_extra)))
				runtime_extra[n_runtime++] = argv[++i];
		} else if (strcmp(argv[i], "--best-effort") == 0) {
			best_effort = 1;
		} else if (strcmp(argv[i], "--no-jail") == 0) {
			no_jail = 1;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			break; // first non-flag is DIR
		}
	}
	if (i >= argc) {
		usage(argv[0]);
		return 2;
	}
	const char *dir = argv[i++];
	if (i < argc && strcmp(argv[i], "--") == 0)
		i++; // optional separator
	if (i >= argc) {
		fprintf(stderr, "agent-jail: no command given\n");
		usage(argv[0]);
		return 2;
	}
	char **cmd = &argv[i];

	// Resolve DIR to an absolute, canonical path so the watcher and the jail
	// agree on exactly one prefix.
	char dir_abs[PATH_MAX];
	if (!realpath(dir, dir_abs)) {
		fprintf(stderr, "agent-jail: cannot resolve directory '%s': %s\n", dir,
		        strerror(errno));
		return 1;
	}

	if (no_jail) {
		fprintf(stderr, "agent-jail: --no-jail — running UNCONFINED (audit mode)\n");
		execvp(cmd[0], cmd);
		fprintf(stderr, "agent-jail: exec '%s' failed: %s\n", cmd[0], strerror(errno));
		return 127;
	}

	// --- probe the Landlock ABI this kernel supports ---
	long abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1) {
		if (best_effort) {
			fprintf(stderr,
			        "agent-jail: Landlock unavailable (abi=%ld) — running UNCONFINED "
			        "(--best-effort)\n",
			        abi);
			execvp(cmd[0], cmd);
			fprintf(stderr, "agent-jail: exec failed: %s\n", strerror(errno));
			return 127;
		}
		fprintf(stderr,
		        "agent-jail: Landlock not available on this kernel (abi=%ld).\n"
		        "          Need Linux >= 5.13 with CONFIG_SECURITY_LANDLOCK=y.\n"
		        "          Re-run with --best-effort to run unconfined anyway.\n",
		        abi);
		return 1;
	}

	// Mask the rights we declare as "handled" to those this ABI knows about.
	// ABI 1 is the baseline ACCESS_FS_ALL above. Later ABIs added rights we do
	// not name here; the kernel rejects unknown handled bits, so naming only
	// the baseline set is the portable choice.
	__u64 handled = ACCESS_FS_ALL;

	struct landlock_ruleset_attr ra = {.handled_access_fs = handled};
	int ruleset_fd = ll_create_ruleset(&ra, sizeof(ra), 0);
	if (ruleset_fd < 0) {
		fprintf(stderr, "agent-jail: landlock_create_ruleset failed: %s\n",
		        strerror(errno));
		return 1;
	}

	// 1) Full access beneath the target dir.
	if (allow_path(ruleset_fd, dir_abs, handled) < 0) {
		fprintf(stderr, "agent-jail: cannot allow target dir '%s': %s\n", dir_abs,
		        strerror(errno));
		return 1;
	}
	// 2) Any user-requested extra dirs (full access).
	for (int a = 0; a < n_allow; a++) {
		int rc = allow_path(ruleset_fd, allow_extra[a], handled);
		if (rc < 0) {
			fprintf(stderr, "agent-jail: --allow '%s' failed: %s\n", allow_extra[a],
			        strerror(errno));
			return 1;
		}
		if (rc == 1)
			fprintf(stderr, "agent-jail: --allow '%s' does not exist — skipped\n",
			        allow_extra[a]);
	}
	// 2b) Runtime/interpreter trees, read+EXECUTE only (no write). For an
	//     interpreted agent (e.g. `bun run omp`), the runtime and the agent's JS
	//     live outside the project — grant the runtime root (e.g. ~/.bun) so it
	//     can load its code, without giving write access or exposing it as a
	//     general escape target. This is the smooth path for non-binary installs.
	for (int a = 0; a < n_runtime; a++) {
		int rc = allow_path(ruleset_fd, runtime_extra[a], ACCESS_FS_READ & handled);
		if (rc < 0) {
			fprintf(stderr, "agent-jail: --runtime '%s' failed: %s\n", runtime_extra[a],
			        strerror(errno));
			return 1;
		}
		if (rc == 1)
			fprintf(stderr, "agent-jail: --runtime '%s' does not exist — skipped\n",
			        runtime_extra[a]);
	}
	// 3) System code/lib directories: read+execute, so the program can load
	//    libraries and run. No user secrets live here.
	for (size_t s = 0; s < sizeof(SYS_RO_DIRS) / sizeof(*SYS_RO_DIRS); s++) {
		if (allow_path(ruleset_fd, SYS_RO_DIRS[s], ACCESS_FS_READ & handled) < 0) {
			fprintf(stderr, "agent-jail: warning: could not add %s read rule: %s\n",
			        SYS_RO_DIRS[s], strerror(errno));
		}
	}
	// 4) Specific /etc files the loader and name resolution need — granted
	//    individually so the rest of /etc (passwd, ssh, shadow…) stays unseen.
	//    A path_beneath rule on a regular FILE may only request file-type
	//    rights (READ_FILE) — requesting dir rights like READ_DIR/EXECUTE on a
	//    file is EINVAL. Absence of any one file is fine (rc==1, skipped).
	for (size_t s = 0; s < sizeof(SYS_RO_FILES) / sizeof(*SYS_RO_FILES); s++) {
		int rc = allow_path(ruleset_fd, SYS_RO_FILES[s],
		                    LANDLOCK_ACCESS_FS_READ_FILE & handled);
		if (rc < 0)
			fprintf(stderr, "agent-jail: warning: %s read rule failed: %s\n",
			        SYS_RO_FILES[s], strerror(errno));
	}
	// 5) Pseudo-filesystems (/dev, /proc, /sys): read+write, needed at runtime,
	//    no on-disk user data exposed.
	for (size_t s = 0; s < sizeof(SYS_RW_PSEUDO) / sizeof(*SYS_RW_PSEUDO); s++) {
		if (allow_path(ruleset_fd, SYS_RW_PSEUDO[s], handled) < 0)
			fprintf(stderr, "agent-jail: warning: %s rule failed: %s\n",
			        SYS_RW_PSEUDO[s], strerror(errno));
	}
	// 6) The command's own binary, read+execute. The program lives outside the
	//    target dir (e.g. ~/.local/bin/omp) and the loader must be able to
	//    read+exec it. We grant the BINARY FILE ITSELF, not its directory:
	//    granting the dir would expose every sibling file — and if the binary
	//    sits in a sensitive dir (say it was copied to /tmp), that silently
	//    re-opens the very files the jail is meant to hide. File-only is the
	//    safe grant for a self-contained binary like omp.
	//
	//    We also remember the resolved absolute path and exec THAT below, so the
	//    post-jail exec doesn't re-walk $PATH (whose probing the jail may block).
	char exec_path[PATH_MAX];
	exec_path[0] = '\0';
	{
		char cmd_path[PATH_MAX];
		const char *resolved = NULL;
		if (strchr(cmd[0], '/')) {
			resolved = realpath(cmd[0], cmd_path) ? cmd_path : NULL;
		} else {
			// Search PATH for a bare command name.
			const char *path_env = getenv("PATH");
			char tryp[PATH_MAX];
			if (path_env) {
				const char *p = path_env;
				while (*p && !resolved) {
					const char *colon = strchr(p, ':');
					size_t len = colon ? (size_t)(colon - p) : strlen(p);
					if (len && len < sizeof(tryp) - 1 - strlen(cmd[0])) {
						memcpy(tryp, p, len);
						tryp[len] = '/';
						strcpy(tryp + len + 1, cmd[0]);
						if (access(tryp, X_OK) == 0)
							resolved = realpath(tryp, cmd_path) ? cmd_path : NULL;
					}
					p = colon ? colon + 1 : p + len;
				}
			}
		}
		if (resolved) {
			// Read+execute on just this file so the loader can mmap and run it.
			__u64 binrights = (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE) & handled;
			if (allow_path(ruleset_fd, resolved, binrights) < 0)
				fprintf(stderr, "agent-jail: warning: binary '%s' rule failed: %s\n",
				        resolved, strerror(errno));
			strncpy(exec_path, resolved, sizeof(exec_path) - 1);
			exec_path[sizeof(exec_path) - 1] = '\0';
			// Note: we intentionally do NOT grant the binary's parent directory.
			// A file-only EXECUTE+READ_FILE grant is enough for the loader to
			// run a self-contained binary (verified against real omp), and it
			// keeps sibling files in that directory unreadable — which is the
			// whole point when omp lives somewhere like /tmp or ~/.local/bin.
		}
	}

	// No new privileges, then lock. PR_SET_NO_NEW_PRIVS is required before
	// landlock_restrict_self for an unprivileged caller.
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fprintf(stderr, "agent-jail: prctl(NO_NEW_PRIVS) failed: %s\n",
		        strerror(errno));
		return 1;
	}
	if (ll_restrict_self(ruleset_fd, 0)) {
		fprintf(stderr, "agent-jail: landlock_restrict_self failed: %s\n",
		        strerror(errno));
		return 1;
	}
	close(ruleset_fd);

	// Strip secret-bearing env vars so the now-confined process can't read its
	// own API keys/tokens back via /proc/self/environ. (Landlock is FS-only; it
	// doesn't cover the environment. This closes the leak the adversary found.)
	scrub_secret_env();

	// The lock is shut. Hand off to the real command — it inherits the jail.
	// Exec the resolved absolute path when we have one (avoids a post-jail $PATH
	// walk); fall back to execvp for the rare case resolution failed.
	if (exec_path[0]) {
		execv(exec_path, cmd);
	}
	execvp(cmd[0], cmd);
	fprintf(stderr, "agent-jail: exec '%s' failed: %s\n", cmd[0], strerror(errno));
	return 127;
}
