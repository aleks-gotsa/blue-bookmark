import type { Detector, Finding } from "../types";
import { uplus } from "../util/text";

const NAMES: Record<number, string> = {
  0x202a: "LRE",
  0x202b: "RLE",
  0x202c: "PDF",
  0x202d: "LRO",
  0x202e: "RLO",
  0x2066: "LRI",
  0x2067: "RLI",
  0x2068: "FSI",
  0x2069: "PDI",
};

export const bidiOverride: Detector = {
  id: "bidi-override",
  category: "bidi-override",
  severity: "high",
  description: "Unicode bidirectional override/embedding/isolate controls (Trojan Source): text renders differently from how it is processed.",
  run(ctx) {
    const s = ctx.input;
    const findings: Finding[] = [];
    const re = /[\u202A-\u202E\u2066-\u2069]+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(s))) {
      const codes = [...m[0]].map((c) => c.codePointAt(0)!);
      const hasOverride = codes.some((c) => c === 0x202d || c === 0x202e);
      const onlyTerminators = codes.every((c) => c === 0x202c || c === 0x2069);
      if (onlyTerminators) continue; // stray PDF/PDI is harmless on its own
      const names = codes.map((c) => `${NAMES[c]} (${uplus(c)})`).join(", ");
      findings.push({
        id: "bidi-override",
        category: "bidi-override",
        severity: hasOverride ? "high" : "medium",
        start: m.index,
        end: m.index + m[0].length,
        excerpt: ctx.helpers.excerpt(m.index, m.index + m[0].length),
        reason: hasOverride
          ? `Bidi override ${names}: following text is displayed reversed, so what a human sees differs from what the model reads`
          : `Bidi embedding/isolate ${names} in content that is not right-to-left`,
        meta: { codes },
      });
    }
    return findings;
  },
};
