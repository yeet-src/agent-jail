// BPF data layer — the only BPF-aware module. It patches the target directory
// and comm into the running program's .data section, subscribes to the
// open-attempt ring buffer, and exposes plain reactive signals the UI reads.
//
// Two directions of reactivity:
//   user -> kernel : configure() patches target_prefix/_len/target_comm so the
//                    kernel classifies escapes against the jailed dir, live.
//   kernel -> user : `stats` is built with from() over the ring buffer — the
//                    subscription's lifecycle follows the UI. A window timer
//                    publishes counters, the escape leaderboard, the recent
//                    feed, and a rolling access-rate sparkline.
import { DataSec, RingBuf } from "yeet:bpf";
import { from, signal } from "yeet:tui";
import { _ } from "yeet:helpers";
import { control } from "@/probes/probe.js";
import { isSensitive } from "@/lib/classify.js";

const WINDOW_MS = 400; // publish cadence + sparkline bucket width
const FEED = 200; // recent open attempts kept for the live feed
const SPARK = 80; // sparkline history buckets
const TARGET_COMM = "omp";

const events = new RingBuf(control, "events");
const knobs = new DataSec(control, "probe.data");

const commStr = (c) => {
  if (typeof c === "string") return c.replace(/\0.*$/s, "");
  if (!c) return "";
  let s = "";
  for (const b of c) { if (b === 0) break; s += String.fromCharCode(b); }
  return s;
};

// Patch the jailed directory + comm into the kernel program. Call once at
// startup, before the UI starts classifying. `dir` is the absolute, canonical
// path the launcher locked to. The kernel does a byte-prefix compare, so the
// prefix must match exactly what paths will start with — no trailing slash
// unless the dir is "/".
const PREFIX_MAX = 200; // must match PREFIX_MAX in src/bpf/include/jail.h

export function configure(dir, comm = TARGET_COMM, audit = false) {
  // target_prefix is a fixed char[PREFIX_MAX]; target_comm a char[16].
  // DataSec.patch copies a JS string into a char[] (NUL-padded). _len is the
  // count of meaningful prefix bytes the kernel compares against. Clamp to the
  // buffer so an unusually long project path can't overflow the patch.
  // audit_mode: when set, the hook emits decisions but never returns -EPERM.
  const prefix = dir.length > PREFIX_MAX ? dir.slice(0, PREFIX_MAX) : dir;
  knobs.patch({
    target_prefix: prefix,
    target_prefix_len: prefix.length,
    target_comm: comm,
    audit_mode: audit ? 1 : 0,
  });
}

// Headless tap: subscribe to every classified open and hand the caller a plain
// fact object. Unlike `stats` (a UI-watched from() signal that only runs while
// rendered), this runs as soon as it's called — the path for --headless, where
// there is no TUI watching anything. Returns the subscription handle.
//   cb({ path, comm, category, reached, sensitive, verdict })
// Read one raw ring-buffer event into the shape the UI/headless layers use. The
// LSM hook already decided in_bounds / system / blocked in-kernel (it MADE the
// open decision), so we trust those fields directly. JS only adds the
// sensitive-target flag, which the kernel doesn't compute.
function readEvent(w) {
  const e = w?.file_event ?? w;
  if (!e) return null;
  const path = commStr(e.path);
  const inBounds = e.in_bounds === 1 || e.in_bounds === true;
  const system = e.system === 1 || e.system === true;
  const blocked = e.blocked === 1 || e.blocked === true;
  const category = inBounds ? "in" : system ? "system" : "escape";
  return {
    path,
    comm: commStr(e.comm),
    category,
    inBounds,
    system,
    blocked,                       // the kernel refused this open (-EPERM)
    isEscape: category === "escape",
    sensitive: category === "escape" && isSensitive(path),
  };
}

export function watchEscapes(cb) {
  return events.subscribe((w) => {
    const ev = readEvent(w);
    if (ev) cb(ev);
  });
}

// Live aggregate, republished every window. Shape consumed by the UI:
//   { allowed, blocked, reached, total, escapes: [{path, count, sensitive,
//     lastVerdict}], feed: [{path, in_bounds, verdict, sensitive, ts}],
//     spark: [rate,...] }
const blank = () => ({
  allowed: 0, system: 0, blocked: 0, reached: 0, total: 0,
  sensitiveHits: 0, // count of escape events that hit a sensitive target
  escapes: [], feed: [], spark: new Array(SPARK).fill(0),
});

export const stats = from((state) => {
  // Persistent accumulators across windows.
  const escapeMap = new Map(); // path -> { count, sensitive, lastVerdict }
  const feed = [];
  const spark = new Array(SPARK).fill(0);
  let allowed = 0, system = 0, blocked = 0, reached = 0, total = 0, sensitiveHits = 0;
  let windowCount = 0;
  let ts = 0; // monotonic-ish event sequence for feed ordering (no Date in runtime)

  const sub = events.subscribe((w) => {
    const ev = readEvent(w);
    if (ev === null) return;

    total++;
    windowCount++;
    if (ev.category === "in") {
      allowed++;
    } else if (ev.category === "system") {
      system++; // permitted system path — benign (rarely emitted)
    } else if (ev.blocked) {
      blocked++; // escape the kernel refused — the jail working
    } else {
      reached++; // out-of-bounds open that got through (only if jail is off)
    }

    if (ev.sensitive) sensitiveHits++;

    // Verdict object the components render (kernel decided it, so it's exact).
    const verdict = ev.blocked
      ? { ok: false, label: "EACCES" }
      : { ok: true, label: "ok" };

    // Only genuine escapes go on the leaderboard and the feed's escape rows.
    if (ev.isEscape) {
      const cur = escapeMap.get(ev.path) || { count: 0, sensitive: ev.sensitive, lastVerdict: verdict };
      cur.count++;
      cur.lastVerdict = verdict;
      cur.sensitive = ev.sensitive;
      cur.reached = !ev.blocked; // got through (jail off); 0 under a live jail
      escapeMap.set(ev.path, cur);
    }

    // Feed shows in-bounds + escapes; system noise stays off the stream.
    if (ev.category !== "system") {
      feed.unshift({ path: ev.path, in_bounds: ev.inBounds, verdict, sensitive: ev.sensitive, reached: !ev.blocked && ev.isEscape, ts: ts++ });
      if (feed.length > FEED) feed.pop();
    }
  });

  const secs = WINDOW_MS / 1000;
  const h = setInterval(() => {
    spark.push(windowCount / secs);
    spark.shift();
    windowCount = 0;

    const escapes = [...escapeMap.entries()]
      .map(([path, v]) => ({ path, ...v }))
      .sort((a, b) => b.count - a.count);

    state.set({
      allowed, system, blocked, reached, total, sensitiveHits,
      escapes,
      feed: feed.slice(),
      spark: spark.slice(),
    });
  }, WINDOW_MS);

  return () => { clearInterval(h); sub.then(_.unsubscribe()); };
}, blank());
