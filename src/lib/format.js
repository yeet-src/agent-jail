// Pure presentation helpers — strings and color, no signals or BPF.
// Imported by the components through the `@/` alias (resolved at bundle time).
import { idx } from "yeet:tui";

export const pad = (s, n) => (s + " ".repeat(n)).slice(0, n);
export const lpad = (s, n) => (" ".repeat(n) + s).slice(-n);

// A rate as a short human string: 12, 4.2K, 1.1M (per second).
export const fmtRate = (perSec) => {
  if (perSec < 1000) return `${Math.round(perSec)}`;
  if (perSec < 1e6) return `${(perSec / 1e3).toFixed(1)}K`;
  return `${(perSec / 1e6).toFixed(1)}M`;
};

// A count as a short string: 0, 42, 1.2K, 3.4M.
export const fmtCount = (n) => {
  if (n < 1000) return `${n}`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
};

// Collapse the user's home prefix to "~" and clip a long path to `n` cells,
// keeping the meaningful tail (filename) visible: /home/u/.ssh/id_rsa -> …/.ssh/id_rsa.
export const tildify = (path, home) =>
  home && path.indexOf(home) === 0 ? "~" + path.slice(home.length) : path;

export const clipPath = (path, n) => {
  if (path.length <= n) return path;
  return "…" + path.slice(-(n - 1));
};

// Unicode sparkline from a series of values, scaled to its own max.
const BARS = "▁▂▃▄▅▆▇█";
export const sparkline = (series) => {
  const max = series.reduce((m, v) => (v > m ? v : m), 0);
  if (max <= 0) return BARS[0].repeat(series.length);
  let out = "";
  for (const v of series) {
    const f = v / max;
    out += BARS[Math.min(BARS.length - 1, Math.max(0, Math.floor(f * BARS.length)))];
  }
  return out;
};

// A horizontal proportion bar of `width` cells split
// in-bounds | system | blocked | reached. Returns integer cell counts so the
// caller colours each run. System (benign permitted reads) is shown dim so the
// bar reflects reality without making routine system access look alarming.
export const splitBar = (allowed, system, blocked, reached, width) => {
  const total = allowed + system + blocked + reached;
  if (total === 0) return { a: 0, s: 0, b: 0, l: 0, rest: width };
  const a = Math.round((allowed / total) * width);
  const s = Math.round((system / total) * width);
  const l = Math.round((reached / total) * width);
  const b = Math.max(0, width - a - s - l);
  return { a, s, b, l, rest: 0 };
};
