// Pure summary builder — turns the live stats into a copy-pasteable recap for
// a PR, an issue, or a tweet. No signals, no BPF. The 'c' key copies this via
// OSC 52 and echoes it; main also prints it on a clean exit.
import { tildify } from "@/lib/format.js";

export function buildSummary(s, { dir, mode, home }) {
  const lines = [];
  const jailed = mode === "jail";
  lines.push(`omp-jail session — ${jailed ? "JAILED (Landlock)" : "AUDIT (unconfined)"}`);
  lines.push(`dir: ${tildify(dir, home)}`);
  lines.push(
    `opens: ${s.total}  ·  in-bounds: ${s.allowed}  ·  ` +
      `escapes blocked: ${s.blocked}` +
      (s.leaked ? `  ·  LEAKED: ${s.leaked}` : ""),
  );

  const sensitive = s.escapes.filter((e) => e.sensitive);
  if (sensitive.length) {
    lines.push(`sensitive targets reached for (${sensitive.length}):`);
    sensitive.slice(0, 8).forEach((e) => {
      const verdict = e.leaked ? "LEAKED" : "blocked";
      lines.push(`  • ${tildify(e.path, home)}  ${e.count}×  [${verdict}]`);
    });
  } else if (s.escapes.length) {
    lines.push(`top escape targets:`);
    s.escapes.slice(0, 5).forEach((e) => {
      const verdict = e.leaked ? "LEAKED" : "blocked";
      lines.push(`  • ${tildify(e.path, home)}  ${e.count}×  [${verdict}]`);
    });
  } else {
    lines.push(`no escape attempts — omp stayed in-bounds.`);
  }

  if (jailed && s.blocked > 0 && s.leaked === 0) {
    lines.push(`verdict: jail held — every escape was refused by the kernel.`);
  } else if (!jailed && (s.leaked > 0 || s.escapes.length)) {
    lines.push(`verdict: unconfined — these would have been blocked under --jail.`);
  }
  return lines.join("\n");
}
