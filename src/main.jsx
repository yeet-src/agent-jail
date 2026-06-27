/* agent-jail — watch a Landlock-confined omp and prove the jail holds.
 *
 * This is the WATCHER (the observability half). The `agent-jail` command (the
 * shell wrapper in scripts/) backgrounds this yeet script and runs the C
 * Landlock launcher in the foreground; together they are one tool. This script
 * does not confine anything — it witnesses every file omp opens, classifies it
 * as in-bounds or an escape, and shows the kernel's verdict (EACCES = the jail
 * held; ok = it leaked, which is what you see in --audit mode).
 *
 * Data flow, both directions of yeet's reactive BPF:
 *   user -> kernel : configure() patches the jailed dir + comm into the running
 *                    program's .data section so the kernel tags escapes live.
 *   kernel -> user : probes/fileaccess.js builds `stats` with from() over the
 *                    open-attempt ring buffer — a subscription as a signal.
 *
 * Layout: probes/ (BPF-aware) -> components/ (pure UI) -> lib/ (pure helpers).
 *
 * Args (passed by the wrapper): --dir ABS  jailed directory (required)
 *                               --mode jail|audit   header badge + leak framing
 *                               --home ABS          collapse to ~ in display
 *                               --comm NAME         process comm to match (omp)
 */
import { Box, mount, signal } from "yeet:tui";
import { configure, stats, watchEscapes } from "@/probes/fileaccess.js";
import { layoutFor } from "@/lib/layout.js";
import { buildSummary } from "@/lib/summary.js";
import { startReporter } from "@/lib/report.js";
import Header from "@/components/header.jsx";
import Leaderboard from "@/components/leaderboard.jsx";
import Feed from "@/components/feed.jsx";
import Footer from "@/components/footer.jsx";

const { dir = ".", mode = "jail", home = "", comm = "omp", headless, format } = yeet.args;

// Push the jailed dir + comm into the kernel before we start classifying.
configure(dir, comm, mode === "audit");

// Headless / background mode: no TUI, just structured reports of escape attempts
// to stdout (pipe to a file or log shipper, or leave running detached). Skips
// the screen entirely — never touches tty.*, which would throw without a PTY.
if (headless) {
  startReporter(watchEscapes, { dir, mode, format: format || "json" });
  console.error(`agent-jail: headless ${mode} mode — reporting escape attempts for ${dir}`);
  await new Promise(() => {}); // run until killed
}

// Copy a shareable session summary to the clipboard (OSC 52) and echo it.
function copySummary() {
  const text = buildSummary(stats.get(), { dir, mode, home });
  try { tty.clipboard?.writeText(text); } catch {}
  console.log("\n" + text);
}

// Scroll offset into the escape-attempts list (the top pane). The leaderboard
// shows a window starting here; it clamps internally, so we only need to keep a
// non-negative number and let the view bound it. `pageRows` tracks the current
// pane height so PgUp/PgDn move by a screenful.
// Selected row in the escape list — a highlighted cursor the user moves with
// ↑↓. The leaderboard derives its scroll window from this (keeps the selection
// on screen), so the motion is visible: the highlight tracks each keypress even
// before the list overflows. `selected` is an index into the escape list; the
// view clamps it. `pageRows` tracks the live pane height for PgUp/PgDn.
const selected = signal(0);
let pageRows = 10;
const escapeCount = () => stats.get().escapes.length;
const clampSel = (i) => Math.max(0, Math.min(Math.max(0, escapeCount() - 1), i));
const moveSel = (d) => selected.set(clampSel(selected.get() + d));

tty.on("keydown", (e) => {
  const code = e.code;
  const k = (e.key ?? "").toLowerCase();
  if (code === "Escape" || k === "q") return yeet.exit();
  if (k === "c") return copySummary();
  // Move the highlighted selection through the escape list.
  if (code === "ArrowUp" || k === "k") return moveSel(-1);
  if (code === "ArrowDown" || k === "j") return moveSel(1);
  if (code === "PageUp") return moveSel(-pageRows);
  if (code === "PageDown") return moveSel(pageRows);
  if (e.key === "g") return selected.set(0);                 // top
  if (e.key === "G") return selected.set(clampSel(escapeCount() - 1)); // bottom
});

const panel = (p) => {
  switch (p.kind) {
    case "leaderboard":
      pageRows = p.maxRows; // keep PgUp/PgDn in sync with the live pane height
      return <Leaderboard stats={stats} home={home} maxRows={p.maxRows} width={p.w} selected={selected} />;
    case "feed":
      return <Feed stats={stats} home={home} maxRows={p.maxRows} width={p.w} />;
  }
};

// `Root(size)` gets the terminal's reactive size signal; reading it in the
// body thunk reflows on resize. Fixed header + footer, flex body between; the
// 1fr body absorbs rounding so the footer stays pinned to the last row.
const Root = (size) => (
  <Box>
    <Header stats={stats} mode={mode} dir={home && dir.indexOf(home) === 0 ? "~" + dir.slice(home.length) : dir} />
    <Box height="1fr" overflow="hidden">
      {() => {
        const { mode: m, panels } = layoutFor(size.get());
        const wide = m === "wide";
        // Always return ONE flex container. Returning a bare array of sibling
        // Boxes from this thunk feeds the flex distributor a malformed child
        // list and crashes layout — wrap them. Wide lays panels in a row with a
        // 1-cell gutter between them; stacked lays them in a column (panels
        // self-frame, so no rule needed). Each panel gets a definite size on
        // the axis the parent distributes.
        const kids = [];
        panels.forEach((p, i) => {
          if (i && wide) kids.push(<Box width="1" height="100%" />); // gutter
          kids.push(
            // Fill the body's full height. In a row container the cross axis
            // (height) is NOT flex-distributed, so "1fr" there resolves to ~0
            // and the panel collapses to its content, bottom-anchored — that's
            // the gap. "100%" makes each panel span the parent body height.
            <Box width={`${p.w}`} height="100%" overflow="hidden">
              {panel(p)}
            </Box>,
          );
        });
        return (
          <Box height="1fr" direction={wide ? "row" : "column"} overflow="hidden">
            {kids}
          </Box>
        );
      }}
    </Box>
    <Footer />
  </Box>
);

mount(Root);
await new Promise(() => {}); // keep the script alive; the TUI owns the screen
