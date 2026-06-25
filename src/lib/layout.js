// Responsive layout model. Pure: given the terminal {cols, rows}, it sizes the
// two body panels (escape leaderboard + live feed) and hands each its exact
// extent so a component never guesses its own width. The app shell is a 3-row
// header (masthead + ROI line + bar) + 1-row footer; the body is the rest.
//
// Wide  : leaderboard | feed, side by side.
// Narrow: leaderboard stacked over feed.

const HEADER_H = 3;
const FOOTER_H = 1;
const MIN_SIDE = 44; // a side panel narrower than this stacks instead

export const layoutFor = ({ cols, rows }) => {
  const body = Math.max(1, rows - HEADER_H - FOOTER_H);

  if (cols >= 2 * MIN_SIDE) {
    // Leaderboard gets the wider half (it's the headline); feed takes the rest.
    // A 1-cell gutter sits between them, so the two widths sum to cols - 1.
    const avail = cols - 1;
    const leftW = Math.round(avail * 0.55);
    const rows = Math.max(1, body - 2); // minus the panel's top+bottom border
    return {
      mode: "wide",
      bodyH: body,
      panels: [
        { kind: "leaderboard", w: leftW, h: body, maxRows: rows },
        { kind: "feed", w: avail - leftW, h: body, maxRows: rows },
      ],
    };
  }

  // Narrow: stack, leaderboard on top. Panels self-frame (top+bottom border),
  // so each panel's content rows are its height minus 2.
  const topH = Math.max(4, Math.ceil(body * 0.5));
  const botH = Math.max(4, body - topH);
  return {
    mode: "stack",
    bodyH: body,
    panels: [
      { kind: "leaderboard", w: cols, h: topH, maxRows: Math.max(1, topH - 2) },
      { kind: "feed", w: cols, h: botH, maxRows: Math.max(1, botH - 2) },
    ],
  };
};
