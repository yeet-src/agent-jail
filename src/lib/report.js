// Headless reporter — the no-TUI, background-friendly output path. Instead of a
// reactive dashboard, it emits one structured line per *report-worthy* event so
// the run can be piped to a file, a log shipper, or just left running in the
// background. It never touches `tty.*` (which would throw without a PTY), only
// `console.log`, so it's safe to detach.
//
// Report-worthy = escape attempts (out-of-bounds opens), not the in-bounds or
// permitted-system noise. Each line says whether the kernel blocked it or it got
// through ("reached"), and flags sensitive targets. De-dupes by path so a tight
// loop hammering one secret doesn't flood the log — it reports the first hit and
// then a periodic rollup.

// Build a structured record for one escape event. Returns null for non-escapes.
export function reportRecord(ev, { dir, mode }) {
  if (ev.category !== "escape") return null;
  return {
    event: "escape_attempt",
    path: ev.path,
    by: ev.comm,
    // The LSM hook decided this: blocked = it returned -EPERM. In audit mode
    // (jail off) the same reach gets through, so blocked is false = "reached".
    outcome: ev.blocked ? "blocked" : "reached",
    sensitive: ev.sensitive,
    dir,
    mode,
  };
}

// One human-readable line for a record (when --format=text).
export function textLine(r, seq) {
  const tag = r.outcome === "reached" ? "REACHED " : "blocked";
  const fire = r.sensitive ? "🔥 " : "   ";
  return `[${String(seq).padStart(5, "0")}] ${tag} ${fire}${r.path}  (by ${r.by})`;
}

// Start headless reporting. `watch` is probes/watchEscapes; `args` carries the
// flags. De-dupes per path with a periodic rollup so a hot loop on one secret
// reports once, then a count every `rollupMs`. Returns a stop() handle.
export function startReporter(watch, { dir, mode, format = "json", rollupMs = 5000 }) {
  let seq = 0;
  const seen = new Map(); // path -> { count, sensitive, outcome }
  const announced = new Set(); // paths already printed at least once

  const emit = (r) => {
    seq++;
    if (format === "text") console.log(textLine(r, seq));
    else console.log(JSON.stringify({ seq, ...r }));
  };

  const startupLine = format === "text"
    ? `agent-jail headless — ${mode} — watching ${dir} (escape attempts only)`
    : JSON.stringify({ event: "start", mode, dir, watching: "escape_attempts" });
  console.log(startupLine);

  const sub = watch((ev) => {
    const r = reportRecord(ev, { dir, mode });
    if (!r) return; // skip in-bounds + system noise
    const prev = seen.get(r.path) || { count: 0, sensitive: r.sensitive, outcome: r.outcome };
    prev.count++;
    prev.outcome = r.outcome;
    seen.set(r.path, prev);
    // Report the first hit on each path immediately (that's the signal); the
    // periodic rollup below reports repeat volume without per-open spam.
    if (!announced.has(r.path)) {
      announced.add(r.path);
      emit(r);
    }
  });

  // Periodic rollup of repeat counts, so volume is visible without flooding.
  const h = setInterval(() => {
    const hot = [...seen.entries()].filter(([, v]) => v.count > 1);
    if (!hot.length) return;
    if (format === "text") {
      for (const [path, v] of hot) {
        console.log(`[rollup] ${v.outcome === "reached" ? "REACHED" : "blocked"} ${path} ×${v.count}`);
      }
    } else {
      console.log(JSON.stringify({
        event: "rollup",
        window_ms: rollupMs,
        paths: hot.map(([path, v]) => ({ path, count: v.count, outcome: v.outcome, sensitive: v.sensitive })),
      }));
    }
    for (const [, v] of seen) v.count = 0; // reset window counts
  }, rollupMs);

  return () => { clearInterval(h); sub.then?.((u) => u?.unsubscribe?.()); };
}
