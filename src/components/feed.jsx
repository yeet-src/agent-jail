// Live feed — recent open attempts as they happen, newest on top. A direction
// glyph (in-bounds vs escape), the path, and the kernel verdict. The "it's
// alive" panel; the leaderboard is the summary. Framed to match.
import { Box, Text, bold, fg, bg, idx, C, frameTop, frameBottom } from "@/lib/theme.js";
import { clipPath, lpad, pad, tildify } from "@/lib/format.js";

const badge = (f) => {
  // Every badge is exactly 6 display columns so rows end at the same border.
  if (f.reached) return bold(fg(C.leak)("reachd"));
  const v = f.verdict;
  if (!v) return fg(C.faint)("     …");
  if (v.ok) return fg(C.safe)("    ok");
  if (v.label === "EACCES" || v.label === "EPERM") return fg(C.safe)("blockd");
  if (v.label === "ENOENT") return fg(C.faint)("absent");
  return fg(C.textDim)(lpad(v.label, 6).slice(0, 6));
};

export default ({ stats, home, maxRows, width }) => (
  <Box direction="column" width={`${width}`} height="100%">
    <Text height="1">{() => frameTop(width, "◇ live opens")}</Text>
    <Box height="1fr" overflow="hidden">
      <Text break="none">
        {() => {
          const s = stats.get();
          const inner = width - 2;
          const rows = Math.max(1, maxRows);
          const line = (runs) => [fg(C.frame)("│"), runs, fg(C.frame)("│\n")];
          const blank = () => line(" ".repeat(inner));
          const out = [];

          if (!s.feed.length) {
            out.push(line(fg(C.textDim)(pad("   waiting for omp to open files…", inner))));
          } else {
            const glyphW = 3, badgeW = 7;
            const pathW = Math.max(14, inner - glyphW - badgeW - 1);
            s.feed.slice(0, rows).forEach((f) => {
              const disp = clipPath(tildify(f.path, home), pathW);
              const glyph = f.in_bounds
                ? fg(C.safe)(" ✓ ")
                : f.sensitive
                  ? fg(C.fire)(" 🔥")
                  : fg(C.block)(" ⮌ ");
              const nameColor = f.in_bounds ? fg(C.textDim) : f.sensitive ? fg(C.fire) : fg(C.text);
              out.push(line([glyph, nameColor(pad(disp, pathW)), " ", badge(f)]));
            });
          }
          while (out.length < rows) out.push(blank());
          return out;
        }}
      </Text>
    </Box>
    <Text height="1">{() => frameBottom(width)}</Text>
  </Box>
);
