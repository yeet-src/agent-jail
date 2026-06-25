/* omp-jail — watch a Landlock-confined omp and prove the jail holds.
 *
 * This is the WATCHER (the observability half). The `omp-jail` command (the
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
import { Box, mount } from "yeet:tui";
import { configure, stats } from "@/probes/fileaccess.js";
import { layoutFor } from "@/lib/layout.js";
import { buildSummary } from "@/lib/summary.js";
import Header from "@/components/header.jsx";
import Leaderboard from "@/components/leaderboard.jsx";
import Feed from "@/components/feed.jsx";
import Footer from "@/components/footer.jsx";

const { dir = ".", mode = "jail", home = "", comm = "omp" } = yeet.args;

// Push the jailed dir + comm into the kernel before we start classifying.
configure(dir, comm);

// Copy a shareable session summary to the clipboard (OSC 52) and echo it.
function copySummary() {
  const text = buildSummary(stats.get(), { dir, mode, home });
  try { tty.clipboard?.writeText(text); } catch {}
  console.log("\n" + text);
}

tty.on("keydown", (e) => {
  const k = (e.key ?? "").toLowerCase();
  if (e.code === "Escape" || k === "q") return yeet.exit();
  if (k === "c") copySummary();
});

const panel = (p) => {
  switch (p.kind) {
    case "leaderboard":
      return <Leaderboard stats={stats} home={home} maxRows={p.maxRows} width={p.w} />;
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
