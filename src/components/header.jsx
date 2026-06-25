// Status masthead — three rails:
//   1. brand + jail state + the directory
//   2. the ROI line: a hero count (escapes blocked) with the jail-held verdict
//   3. the proportion bar + per-category tallies + access-rate sparkline
// All tinted as rails via the container bg for reliable full-width fills.
import { Box, Text, bold, fg, bg, idx, C, sep } from "@/lib/theme.js";
import { fmtCount, fmtRate, sparkline, splitBar } from "@/lib/format.js";

const BAR_W = 30;

// Raised key/value chip on the rail.
const chip = (label, value, color) => [
  bg(C.railHi)(fg(C.textDim)(` ${label} `)),
  bg(C.railHi)(bold(fg(color)(`${value} `))),
];

export default ({ stats, mode, dir }) => (
  <Box direction="column" height="3">
    {/* row 1 — masthead */}
    <Box height="1" direction="row" bg={C.rail}>
      <Text break="none">
        {() => {
          const on = mode === "jail";
          const badge = on
            ? bold(fg(C.safe)(" ⊟ JAILED "))
            : bold(bg(C.leak)(fg(idx(231))(" ⚠ AUDIT · UNCONFINED ")));
          return [
            bold(fg(C.brand)(" ▢ agent-jail")), fg(C.brandDim)(" ⌁ "), badge,
            sep, fg(C.textDim)("confined to "), fg(C.text)(dir),
          ];
        }}
      </Text>
    </Box>

    {/* row 2 — the ROI hero line */}
    <Box height="1" direction="row" bg={C.rail}>
      <Text break="none">
        {() => {
          const s = stats.get();
          const on = mode === "jail";
          if (on && s.blocked > 0 && s.leaked === 0) {
            return [
              " ", bold(fg(C.safe)("✓ ")),
              bold(fg(C.safe)(fmtCount(s.blocked))),
              fg(C.text)(" escape attempts blocked"),
              fg(C.textDim)(" — the jail is holding."),
              s.sensitiveHits > 0
                ? [sep, fg(C.fire)("🔥 "), bold(fg(C.fire)(fmtCount(s.sensitiveHits))), fg(C.textDim)(" at sensitive files")]
                : "",
            ];
          }
          if (s.leaked > 0) {
            return [
              " ", bold(fg(C.leak)("⚠ ")),
              bold(fg(C.leak)(fmtCount(s.leaked))),
              fg(C.text)(" reads escaped the directory"),
              fg(C.textDim)(on ? "" : " — run without --audit to block them."),
            ];
          }
          return [" ", fg(C.textDim)("watching "), fg(C.text)("omp"),
                  fg(C.textDim)(" — no escape attempts yet.")];
        }}
      </Text>
    </Box>

    {/* row 3 — proportion bar + tallies + sparkline */}
    <Box height="1" direction="row" bg={C.rail}>
      <Text break="none">
        {() => {
          const s = stats.get();
          const split = splitBar(s.allowed, s.system || 0, s.blocked, s.leaked, BAR_W);
          const bar = [
            fg(C.safe)("█".repeat(split.a)),
            fg(C.system)("█".repeat(split.s)),
            fg(C.block)("█".repeat(split.b)),
            fg(C.leak)("█".repeat(split.l)),
            fg(C.frame)("░".repeat(split.rest)),
          ];
          const rate = s.spark.length ? s.spark[s.spark.length - 1] : 0;
          return [
            " ", ...bar, "  ",
            bold(fg(C.safe)(fmtCount(s.allowed))), fg(C.textDim)(" in-bounds"), sep,
            bold(fg(C.block)(fmtCount(s.blocked))), fg(C.textDim)(" blocked"),
            s.leaked > 0 ? [sep, bold(fg(C.leak)(fmtCount(s.leaked))), fg(C.leak)(" leaked")] : "",
            sep, fg(C.system)(`${fmtCount(s.system || 0)} system`),
            sep, fg(C.safeDim)(sparkline(s.spark.slice(-20))), fg(C.textDim)(` ${fmtRate(rate)}/s`),
          ];
        }}
      </Text>
    </Box>
  </Box>
);
