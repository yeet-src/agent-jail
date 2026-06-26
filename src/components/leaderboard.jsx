// Escape leaderboard — the headline panel. Ranks the paths omp reached for
// OUTSIDE the jailed directory by attempt count. Sensitive targets (keys,
// creds, history) wear a 🔥 and an orange path so they jump out. A verdict
// badge on the right shows what the kernel did — blocked (jail held), leaked
// (it got through, audit mode), or absent (the file wasn't there).
import { Box, Text, bold, fg, bg, idx, C, frameTop, frameBottom } from "@/lib/theme.js";
import { clipPath, fmtCount, lpad, pad, tildify } from "@/lib/format.js";

// A right-aligned verdict badge, ALWAYS exactly 7 display columns so every row
// ends at the same border. "REACHED" keeps the loud inverted fill at 7.
const badge = (e) => {
  if (e.reached) return bold(bg(C.leak)(fg(idx(231))("REACHED")));
  const v = e.lastVerdict;
  if (!v) return fg(C.faint)("   …   ");
  if (v.label === "EACCES" || v.label === "EPERM") return fg(C.safe)("blocked");
  if (v.label === "ENOENT") return fg(C.faint)(" absent");
  return fg(C.textDim)(lpad(v.label, 7));
};

// Title with a scroll indicator: shows the visible window over the total when
// the list is longer than the pane (e.g. " ⤳ escape attempts  4–15 / 37 ↕").
const titleFor = (total, from, count) => {
  const base = "⤳ escape attempts";
  if (total <= count) return base; // everything fits — no indicator
  const lo = from + 1;
  const hi = Math.min(total, from + count);
  return `${base}  ${lo}–${hi} / ${total} ↕`;
};

export default ({ stats, home, maxRows, width, scroll }) => (
  <Box direction="column" width={`${width}`} height="100%">
    <Text height="1">
      {() => {
        const s = stats.get();
        const rows = Math.max(1, maxRows);
        return frameTop(width, titleFor(s.escapes.length, scroll.get(), rows));
      }}
    </Text>
    <Box height="1fr" overflow="hidden">
      <Text break="none">
        {() => {
          const s = stats.get();
          const inner = width - 2;
          const rows = Math.max(1, maxRows);
          const line = (runs) => [fg(C.frame)("│"), runs, fg(C.frame)("│\n")];
          const blank = () => line(" ".repeat(inner));
          const out = [];

          if (!s.escapes.length) {
            out.push(line(fg(C.textDim)(pad("   nothing has reached outside the directory yet.", inner))));
            out.push(line(fg(C.safe)(pad("   ✓ omp is staying in-bounds.", inner))));
          } else {
            // Clamp the scroll offset to a valid window over the current list,
            // so the view stays sane as the list grows/shrinks under it.
            const maxOff = Math.max(0, s.escapes.length - rows);
            const off = Math.min(Math.max(0, scroll.get()), maxOff);
            const rankW = 3, countW = 6;
            const pathW = Math.max(16, inner - rankW - 3 - countW - 8 - 2);
            s.escapes.slice(off, off + rows).forEach((e, i) => {
              const disp = clipPath(tildify(e.path, home), pathW);
              // 🔥 is a double-width glyph, so " 🔥" occupies 3 columns; the
              // non-sensitive marker must also be 3 columns or the right border
              // shifts a cell. Three spaces matches.
              const mark = e.sensitive ? " 🔥" : "   ";
              const nameColor = e.sensitive ? fg(C.fire) : fg(C.text);
              const countColor = e.sensitive ? fg(C.fire) : fg(C.block);
              out.push(line([
                fg(C.faint)(lpad(`${off + i + 1}`, rankW)), mark, " ",
                nameColor(pad(disp, pathW)), " ",
                countColor(lpad(fmtCount(e.count) + "×", countW)), " ",
                badge(e),
              ]));
            });
          }
          // Pad the rest of the panel with bordered blank lines so the frame's
          // side rails run the full height instead of stopping under the data.
          while (out.length < rows) out.push(blank());
          return out;
        }}
      </Text>
    </Box>
    <Text height="1">{() => frameBottom(width)}</Text>
  </Box>
);
