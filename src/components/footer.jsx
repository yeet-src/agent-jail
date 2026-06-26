// Key-hint rail + a compact legend so a screenshot is self-explanatory.
// One row tinted via the container bg (reliable full width).
import { Box, Text, bold, fg, bg, idx, C } from "@/lib/theme.js";

const cap = (keys, label) => [
  bg(C.railHi)(bold(fg(C.brand)(` ${keys} `))),
  fg(C.textDim)(` ${label}   `),
];

const swatch = (color, label) => [fg(color)("█ "), fg(C.textDim)(label + "  ")];

export default () => (
  <Box height="1" direction="row" bg={C.rail}>
    <Text break="none">
      {[
        "  ", ...cap("↑↓", "scroll"), ...cap("c", "copy"), ...cap("q", "quit"),
        fg(C.faint)("│   "),
        ...swatch(C.safe, "in-bounds"),
        ...swatch(C.system, "system"),
        ...swatch(C.block, "blocked"),
        ...swatch(C.leak, "reached"),
        fg(C.fire)("🔥 "), fg(C.textDim)("sensitive"),
      ]}
    </Text>
  </Box>
);
