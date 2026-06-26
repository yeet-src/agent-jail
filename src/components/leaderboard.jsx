// Escape leaderboard — the headline panel. Ranks the paths omp reached for
// OUTSIDE the jailed directory by attempt count. Sensitive targets (keys,
// creds, history) wear a 🔥 and an orange path so they jump out. A verdict
// badge on the right shows what the kernel did — blocked (jail held), leaked
// (it got through, audit mode). A reach that didn't get through reads as
// "blocked" whether the kernel refused it or the file wasn't there.
import { Box, Text, bold, fg, bg, idx, C, frameTop, frameBottom } from "@/lib/theme.js";
import { clipPath, fmtCount, lpad, pad, tildify } from "@/lib/format.js";

// A right-aligned verdict badge, ALWAYS exactly 7 display columns so every row
// ends at the same border. "REACHED" keeps the loud inverted fill at 7.
// Two outcomes only: it got through ("reached") or it didn't ("blocked"). An
// out-of-bounds reach that returned no data — kernel refusal (EACCES) or the
// file not existing (ENOENT) — both read as "blocked": it didn't get through.
const badge = (e) => {
  if (e.reached) return bold(bg(C.leak)(fg(idx(231))("REACHED")));
  const v = e.lastVerdict;
  if (!v) return fg(C.faint)("   …   ");
  return fg(C.safe)("blocked");
};

// Title with a position indicator: shows where the selected row sits in the
// list (e.g. " ⤳ escape attempts  7 / 30 ↕"). Always shown once there are
// escapes, so the moving selection has a readable counter beside it.
const titleFor = (total, sel) => {
  const base = "⤳ escape attempts";
  if (total === 0) return base;
  return `${base}  ${sel + 1} / ${total} ↕`;
};

// Given the selected index, list length, and visible rows, compute the scroll
// offset that keeps the selection on screen (scroll only when it would fall off
// the top or bottom edge).
const windowFor = (sel, total, rows) => {
  if (total <= rows) return 0;
  let off = sel - Math.floor(rows / 2); // center the selection when possible
  off = Math.max(0, Math.min(total - rows, off));
  return off;
};

export default ({ stats, home, maxRows, width, selected }) => (
  <Box direction="column" width={`${width}`} height="100%">
    <Text height="1">
      {() => {
        const s = stats.get();
        return frameTop(width, titleFor(s.escapes.length, selected.get()));
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
            const total = s.escapes.length;
            const sel = Math.max(0, Math.min(total - 1, selected.get()));
            const off = windowFor(sel, total, rows);
            // Columns inside the border: cursor(1) rank(3) mark(3) " " path(*)
            // " " count(6) " " badge(7). pathW absorbs the slack.
            const curW = 1, rankW = 3, markW = 3, countW = 6, badgeW = 7;
            const pathW = Math.max(12, inner - curW - rankW - markW - 1 - countW - 1 - badgeW - 1);
            s.escapes.slice(off, off + rows).forEach((e, i) => {
              const idxAbs = off + i;
              const isSel = idxAbs === sel;
              const disp = clipPath(tildify(e.path, home), pathW);
              // 🔥 is double-width, so " 🔥" is 3 cols; the non-sensitive marker
              // must also be 3 cols or the right border shifts.
              const mark = e.sensitive ? " 🔥" : "   ";
              const nameColor = e.sensitive ? fg(C.fire) : fg(C.text);
              const countColor = e.sensitive ? fg(C.fire) : fg(C.block);
              const cursor = isSel ? fg(C.brand)("▸") : " ";
              // Everything after the cursor, exactly inner-1 columns wide.
              const body = [
                fg(C.faint)(lpad(`${idxAbs + 1}`, rankW)), mark, " ",
                nameColor(pad(disp, pathW)), " ",
                countColor(lpad(fmtCount(e.count) + "×", countW)), " ",
                badge(e),
              ];
              // The selected row gets a highlight bar (bg tint) across the full
              // inner width, so the cursor is obvious on camera as ↑↓ moves it.
              if (isSel) {
                out.push([fg(C.frame)("│"), bg(C.railHi)([cursor, ...body]), fg(C.frame)("│\n")]);
              } else {
                out.push([fg(C.frame)("│"), cursor, ...body, fg(C.frame)("│\n")]);
              }
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
