import type { Detector, Finding } from "../types";

/**
 * Unicode TAG characters U+E0000–U+E007F mirror ASCII 0x00–0x7F. They are invisible in almost every renderer
 * but tokenizers see them, and many models read them as the ASCII they shadow ("invisible instruction" / ASCII smuggling).
 * Legit use: subdivision flag emoji (🏴 + tag letters + U+E007F CANCEL TAG), e.g. England/Scotland/Wales flags.
 */
export const unicodeTags: Detector = {
  id: "unicode-tags",
  category: "unicode-tags",
  severity: "critical",
  description: "Invisible Unicode TAG characters (U+E0000–U+E007F) that smuggle ASCII text past human readers.",
  run(ctx) {
    const s = ctx.input;
    const findings: Finding[] = [];
    // surrogate pair form: U+E0000..E007F => \u{E0000}..\u{E007F}
    const re = /(?:\uDB40[\uDC00-\uDC7F])+/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(s))) {
      const start = m.index;
      const end = start + m[0].length;
      const cps = [...m[0]].map((c) => c.codePointAt(0)!);
      // Flag sequence: preceded by U+1F3F4 (waving black flag), ends with E007F, all letters a-z, <= 8 chars
      const prevCp = start >= 2 ? s.codePointAt(start - 2) : -1;
      const isFlag =
        prevCp === 0x1f3f4 &&
        cps[cps.length - 1] === 0xe007f &&
        cps.length <= 8 &&
        cps.slice(0, -1).every((c) => c >= 0xe0061 && c <= 0xe007a);
      if (isFlag) continue;

      const decoded = cps
        .filter((c) => c !== 0xe0001 && c !== 0xe007f)
        .map((c) => String.fromCharCode(c - 0xe0000))
        .join("");
      const instr = ctx.helpers.matchInstructions(decoded);
      findings.push({
        id: "unicode-tags",
        category: "unicode-tags",
        severity: cps.length >= 4 ? "critical" : "high",
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end, 12),
        reason:
          `${cps.length} invisible TAG characters decode to ASCII: “${decoded.slice(0, 120)}${decoded.length > 120 ? "…" : ""}”` +
          (instr.length ? ` — contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})` : ""),
        decoded,
        meta: { count: cps.length, instructionMatches: instr.map((i) => i.pattern) },
      });
    }
    return findings;
  },
};
