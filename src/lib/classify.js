// Pure classification helpers — no signals, no BPF. Turn a raw open attempt
// (path, in-bounds flag, syscall return value) into the facts the UI renders:
// the verdict (what the kernel did), whether the escape hit a sensitive target,
// and a leaked flag (an escape that succeeded anyway).

export const EACCES = 13; // Landlock refuses with -EACCES
export const EPERM = 1;

// System path prefixes the jail grants read access to so programs can run at
// all (mirrors SYS_RO_DIRS / SYS_RW_PSEUDO in src/jail/agent-jail.c). An open
// under these is OUTSIDE the project dir but PERMITTED and benign — loader,
// libraries, locale, /proc self-inspection. We classify these as "system", not
// escapes, so the leaderboard shows only genuine reaches at user data instead
// of being buried under thousands of libc/locale lookups. Keep in sync with
// the launcher's allow-list.
const SYSTEM_PREFIXES = [
  "/usr/",
  "/lib/",
  "/lib64/",
  "/bin/",
  "/sbin/",
  "/dev/",
  "/proc/",
  "/sys/",
  "/etc/ld.so",
  "/etc/nsswitch.conf",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/localtime",
];

// Bare system directory names — an open of the directory itself (e.g. a stat or
// O_PATH on "/usr") is benign traversal, not a reach at user data.
const SYSTEM_DIRS = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/dev", "/proc", "/sys", "/etc"];

// Scratch/temp trees. A jailed process (and its toolchain) routinely touches
// these for lockfiles, sockets, caches — they hold no user secrets, so an open
// here is noise, not an escape. Without this, opening /tmp itself shows up as a
// (succeeded) out-of-bounds reach, which read as a "leak" on a containment tool.
const SCRATCH_PREFIXES = ["/tmp/", "/var/tmp/", "/run/", "/var/run/", "/dev/shm/"];
const SCRATCH_DIRS = ["/tmp", "/var/tmp", "/run", "/var/run", "/dev/shm"];

export function isSystemPath(path) {
  if (!path) return false;
  for (const pre of SYSTEM_PREFIXES) {
    if (path.indexOf(pre) === 0) return true;
  }
  for (const pre of SCRATCH_PREFIXES) {
    if (path.indexOf(pre) === 0) return true;
  }
  // A bare top-level system/scratch directory open (no trailing path) is benign.
  for (const d of SYSTEM_DIRS) {
    if (path === d) return true;
  }
  for (const d of SCRATCH_DIRS) {
    if (path === d) return true;
  }
  return false;
}

// Substrings that mark a path as a high-value target worth flagging loudly.
// These are the things an AI coding agent reaching outside its project should
// never get: credentials, keys, shell history, cloud/CI tokens. Matched as
// plain substrings against the absolute path — cheap and good enough to
// surface the scary ones above the noise of /usr/lib lookups.
const SENSITIVE = [
  "/.ssh/",
  "/.aws/",
  "/.config/gcloud",
  "/.kube/",
  "/.docker/config",
  "/.gnupg/",
  "/.netrc",
  "/.npmrc",
  "/.pypirc",
  "/.git-credentials",
  "/.config/gh/",
  "/.password-store/",
  "/.mozilla/",
  "/.config/google-chrome",
  "/.bash_history",
  "/.zsh_history",
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "id_rsa",
  "id_ed25519",
  ".env",
  "credentials",
  ".pem",
];

export function isSensitive(path) {
  if (!path) return false;
  for (const needle of SENSITIVE) {
    if (path.indexOf(needle) !== -1) return true;
  }
  return false;
}

// Name the kernel's verdict from the raw return value. fd >= 0 means the open
// succeeded; negative is -errno.
export function verdictOf(ret) {
  if (ret >= 0) return { ok: true, label: "ok", errno: 0 };
  const errno = -ret;
  if (errno === EACCES) return { ok: false, label: "EACCES", errno };
  if (errno === EPERM) return { ok: false, label: "EPERM", errno };
  if (errno === 2) return { ok: false, label: "ENOENT", errno }; // not found — neutral
  return { ok: false, label: `errno ${errno}`, errno };
}

// Full classification used by the data layer. Three categories:
//   category : "in" (under jailed dir), "system" (permitted system/scratch path
//              — benign, de-emphasized), or "escape" (outside both — the story)
//   inBounds : convenience: category === "in"
//   isEscape : a genuine escape attempt (outside dir AND not a system path)
//   reached  : an ESCAPE whose open SUCCEEDED (fd >= 0) — it got through. We say
//              "reached", not "leaked": the open succeeded, but we don't claim
//              the contents were exfiltrated (a directory/handle open succeeds
//              too). Under a working jail this is 0; in audit/--no-jail it's the
//              count of out-of-bounds opens that the kernel did NOT refuse.
//   sensitive: escape hit a known high-value target (keys, creds, history)
//   verdict  : { ok, label, errno } from the return value
export function classify(path, inBounds, ret) {
  const verdict = verdictOf(ret);
  let category;
  if (inBounds) category = "in";
  else if (isSystemPath(path)) category = "system";
  else category = "escape";

  const isEscape = category === "escape";
  const sensitive = isEscape && isSensitive(path);
  const reached = isEscape && verdict.ok; // out-of-bounds open that succeeded
  return { category, inBounds, isEscape, reached, sensitive, verdict };
}
