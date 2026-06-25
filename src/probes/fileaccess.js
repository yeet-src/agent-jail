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
import { classify, EACCES } from "@/lib/classify.js";

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
export function configure(dir, comm = TARGET_COMM) {
  // target_prefix is a fixed char[512]; target_comm a char[16]. DataSec.patch
  // copies a JS string into a char[] field (NUL-terminated/padded). _len is the
  // count of meaningful prefix bytes the kernel compares against.
  knobs.patch({
    target_prefix: dir,
    target_prefix_len: dir.length,
    target_comm: comm,
  });
}

// Live aggregate, republished every window. Shape consumed by the UI:
//   { allowed, blocked, leaked, total, escapes: [{path, count, sensitive,
//     lastVerdict}], feed: [{path, in_bounds, verdict, sensitive, ts}],
//     spark: [rate,...] }
const blank = () => ({
  allowed: 0, system: 0, blocked: 0, leaked: 0, total: 0,
  sensitiveHits: 0, // count of escape events that hit a sensitive target
  escapes: [], feed: [], spark: new Array(SPARK).fill(0),
});

export const stats = from((state) => {
  // Persistent accumulators across windows.
  const escapeMap = new Map(); // path -> { count, sensitive, lastVerdict }
  const feed = [];
  const spark = new Array(SPARK).fill(0);
  let allowed = 0, system = 0, blocked = 0, leaked = 0, total = 0, sensitiveHits = 0;
  let windowCount = 0;
  let ts = 0; // monotonic-ish event sequence for feed ordering (no Date in runtime)

  const sub = events.subscribe((w) => {
    const e = w?.file_event ?? w;
    if (!e) return;
    const path = commStr(e.path);
    const inBounds = e.in_bounds === 1 || e.in_bounds === true;
    const ret = Number(e.ret);
    const cls = classify(path, inBounds, ret);

    total++;
    windowCount++;
    if (cls.category === "in") {
      allowed++;
    } else if (cls.category === "system") {
      system++; // permitted system path — benign, not an escape
    } else if (cls.leaked) {
      leaked++; // genuine escape that SUCCEEDED — a real leak (audit mode)
    } else {
      blocked++; // genuine escape the kernel refused — the jail working
    }

    if (cls.sensitive) sensitiveHits++;

    // Only genuine escapes go on the leaderboard and the feed's escape rows.
    if (cls.isEscape) {
      const cur = escapeMap.get(path) || { count: 0, sensitive: cls.sensitive, lastVerdict: cls.verdict };
      cur.count++;
      cur.lastVerdict = cls.verdict;
      cur.sensitive = cls.sensitive;
      cur.leaked = cls.leaked;
      escapeMap.set(path, cur);
    }

    // Feed shows in-bounds + escapes; system noise is dropped so the stream
    // stays readable (it's counted in the header tally, just not streamed).
    if (cls.category !== "system") {
      feed.unshift({ path, in_bounds: cls.inBounds, verdict: cls.verdict, sensitive: cls.sensitive, leaked: cls.leaked, ts: ts++ });
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
      allowed, system, blocked, leaked, total, sensitiveHits,
      escapes,
      feed: feed.slice(),
      spark: spark.slice(),
    });
  }, WINDOW_MS);

  return () => { clearInterval(h); sub.then(_.unsubscribe()); };
}, blank());
