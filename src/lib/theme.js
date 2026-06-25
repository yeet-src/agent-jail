// Central palette + box-drawing helpers — the single place colours and chrome
// live, so the whole dashboard reads as one coherent thing. Components import
// from here instead of hardcoding idx() values.
import { Box, Text, bold, fg, bg, idx } from "yeet:tui";

// ---- palette ----
export const C = {
  brand: idx(214), // gold — brand, accents
  brandDim: idx(136), // muted gold
  safe: idx(78), // green — in-bounds, jail-held verdicts
  safeDim: idx(65), // muted green
  block: idx(203), // red — blocked escape attempts
  leak: idx(199), // magenta — a leak (escape that succeeded)
  fire: idx(208), // orange — sensitive-target highlight (distinct from leak)
  system: idx(241), // dim grey — permitted system reads (the noise)
  text: idx(252), // primary text
  textDim: idx(245), // secondary text
  faint: idx(240), // separators, hints
  rail: idx(235), // status-rail background
  railHi: idx(237), // raised tile on the rail
  frame: idx(238), // panel borders
  frameHi: idx(244), // panel titles
  bgPanel: idx(234), // subtle panel fill (one shade off the default bg)
};

export const sep = fg(C.faint)("  │  ");
export const dot = fg(C.faint)(" · ");

// ---- box-drawing ----
// Light rounded corners for a softer, modern frame.
export const BOX = {
  tl: "╭", tr: "╮", bl: "╰", br: "╯", h: "─", v: "│",
  tee_l: "├", tee_r: "┤",
};

// A horizontal frame line of `n` cells: "╭─── title ───╮"-style when a title is
// given, otherwise a plain rule. Returns styled runs.
export const frameTop = (n, title) => {
  const line = C.frame;
  if (!title) return fg(line)(BOX.tl + BOX.h.repeat(Math.max(0, n - 2)) + BOX.tr);
  const t = ` ${title} `;
  const left = 2;
  const right = Math.max(0, n - 2 - left - t.length);
  return [
    fg(line)(BOX.tl + BOX.h.repeat(left)),
    bold(fg(C.frameHi)(t)),
    fg(line)(BOX.h.repeat(right) + BOX.tr),
  ];
};

export const frameBottom = (n) =>
  fg(C.frame)(BOX.bl + BOX.h.repeat(Math.max(0, n - 2)) + BOX.br);

// Re-export the tui primitives components need, so a component imports one place.
export { Box, Text, bold, fg, bg, idx };
