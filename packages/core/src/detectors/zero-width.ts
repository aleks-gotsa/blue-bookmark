import type { Detector, Finding } from "../types";
import { cpAt, isCJK, isEmojiish, isLatinLetter, uplus } from "../util/text";

const ZW = new Set<number>([0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0x00ad]);

const SNEAKY = new Set<number>([0x2062, 0x2064]);
const MATH_OPS = new Set<number>([0x2061, 0x2062, 0x2063, 0x2064]);
const MATH_LINE = /[0-9=+\-\u00D7\u00F7/^<>\u2264\u2265\u221A\u2211\u222B]/;
const utf8 = (bytes: number[]) => new TextDecoder("utf-8").decode(new Uint8Array(bytes));

// Sneaky Bits: U+2062 INVISIBLE TIMES is 0, U+2064 INVISIBLE PLUS is 1, eight per byte
function sneakyBits(run: string): string {
  const bits: number[] = [...run].map((c) => (c === "\u2064" ? 1 : 0));
  const bytes: number[] = [];
  for (let k = 0; k + 8 <= bits.length; k += 8) bytes.push(bits.slice(k, k + 8).reduce((a, b) => (a << 1) | b, 0));
  return utf8(bytes);
}

// Variation selectors carry one byte each: VS1-VS16 (U+FE00..FE0F) 0-15, VS17-VS256 (U+E0100..E01EF) 16-255
function variationBytes(run: string): string {
  return utf8([...run].map((c) => {
    const cp = c.codePointAt(0)!;
    return cp < 0xe0100 ? cp - 0xfe00 : cp - 0xe0100 + 16;
  }));
}

function isLetterLike(cp: number): boolean {
  // fullwidth Latin letters and digits too: zero-width characters between them split a word the same way (signal 3)
  return isLatinLetter(cp) || (cp >= 0x400 && cp <= 0x52f) || (cp >= 0x370 && cp <= 0x3ff) || (cp >= 0x30 && cp <= 0x39) || (cp >= 0xff10 && cp <= 0xff19) || (cp >= 0xff21 && cp <= 0xff3a) || (cp >= 0xff41 && cp <= 0xff5a);
}

// the quoted word in a reason is cut, so a long interleaved run is not copied whole into the result
const short = (t: string) => (t.length > 120 ? t.slice(0, 120) + "…" : t);

export const zeroWidth: Detector = {
  id: "zero-width",
  category: "zero-width",
  severity: "medium",
  description: "Zero-width and invisible format characters (ZWSP, ZWNJ, ZWJ, WJ, BOM, soft hyphen) in runs or splitting words.",
  run(ctx) {
    const s = ctx.input;
    const findings: Finding[] = [];
    // text decoded from invisible bytes or bits; kept apart so the merge below cannot rewrite its severity
    const decodedRuns: Finding[] = [];
    const smuggled = (start: number, end: number, count: number, carrier: string, decoded: string, strong: boolean) => {
      const instr = ctx.helpers.matchInstructions(decoded);
      decodedRuns.push({
        id: "zero-width",
        category: "zero-width",
        severity: instr.length || strong ? "critical" : "low",
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end, 12),
        reason:
          `${count} invisible ${carrier} decode to text: “${decoded.slice(0, 120)}${decoded.length > 120 ? "…" : ""}”` +
          (instr.length ? ` — contains agent-directed instructions (${instr.map((x) => x.pattern).join(", ")})` : ""),
        decoded,
        meta: { count, carrier, instructionMatches: instr.map((x) => x.pattern) },
      });
    };
    // A base character takes one variation selector (U+2764 U+FE0F, an ideograph + U+E0100); a run of them has no use but carrying bytes.
    // Two or three can be a doubled selector from copy-paste, so only four or more count as smuggled on their own.
    for (const m of s.matchAll(/(?:[\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){2,}/g)) {
      const count = [...m[0]].length;
      smuggled(m.index!, m.index! + m[0].length, count, "variation selectors", variationBytes(m[0]), count >= 4);
    }
    // per-line "has a digit or a math sign", computed once per line; runs come in order, so the line is found by
    // walking forward (lastIndexOf per operator would be quadratic on one long line)
    const lineMath = new Map<number, boolean>();
    let lineStart = 0;
    let nextNl = s.indexOf("\n");
    const formula = (start: number, end: number, prev: number, next: number): boolean => {
      const near = s.slice(Math.max(0, start - 4), start - 1) + s.slice(end + 1, end + 4);
      if ([...near].some((c) => ZW.has(c.codePointAt(0)!))) return false;
      const before = start >= 2 ? s.codePointAt(start - 2)! : -1;
      const after = end + 1 < s.length ? s.codePointAt(end + 1)! : -1;
      if (isLetterLike(before) || isLetterLike(after)) return false;
      if (/^(ai|ki|\u0448\u0456)$/i.test(String.fromCodePoint(prev, next))) return false;
      while (nextNl >= 0 && nextNl < start) {
        lineStart = nextNl + 1;
        nextNl = s.indexOf("\n", lineStart);
      }
      let math = lineMath.get(lineStart);
      if (math === undefined) {
        math = MATH_LINE.test(s.slice(lineStart, nextNl < 0 ? s.length : nextNl));
        lineMath.set(lineStart, math);
      }
      return math;
    };
    let i = 0;
    let total = 0;
    while (i < s.length) {
      const { cp, len } = cpAt(s, i);
      if (!ZW.has(cp)) {
        i += len;
        continue;
      }
      // collect run
      const start = i;
      const kinds = new Set<number>();
      let j = i;
      let count = 0;
      while (j < s.length) {
        const c = cpAt(s, j);
        if (!ZW.has(c.cp)) break;
        kinds.add(c.cp);
        count++;
        j += c.len;
      }
      const end = j;
      i = end;
      total += count;

      // BOM at position 0 is normal
      if (start === 0 && count === 1 && kinds.has(0xfeff)) continue;
      // Sneaky Bits: only invisible times / invisible plus, at least two bytes' worth
      if (count >= 16 && [...kinds].every((k) => SNEAKY.has(k))) {
        smuggled(start, end, count, "operators (U+2062 / U+2064)", sneakyBits(s.slice(start, end)), true);
        continue;
      }

      const prev = start > 0 ? cpAt(s, start - (s.charCodeAt(start - 1) >= 0xdc00 && s.charCodeAt(start - 1) <= 0xdfff && start >= 2 ? 2 : 1)).cp : -1;
      const next = end < s.length ? cpAt(s, end).cp : -1;

      // single ZWJ (U+200D) / VS inside emoji sequence
      if (count === 1 && kinds.has(0x200d) && (isEmojiish(prev) || isEmojiish(next))) continue;
      // single ZWNJ/ZWSP adjacent to CJK or Indic/Arabic/Persian text is legitimate shaping/segmentation
      if (count === 1 && (kinds.has(0x200b) || kinds.has(0x200c) || kinds.has(0x200d))) {
        // fullwidth Latin letters and digits sit in the CJK forms block but are no CJK text to shape (signal 3)
        const shaping = (cp: number) => (isCJK(cp) && !(cp >= 0xff10 && cp <= 0xff19) && !(cp >= 0xff21 && cp <= 0xff3a) && !(cp >= 0xff41 && cp <= 0xff5a)) || (cp >= 0x600 && cp <= 0x6ff) || (cp >= 0x900 && cp <= 0xdff) || (cp >= 0xe00 && cp <= 0xe7f);
        if (shaping(prev) || shaping(next)) continue;
      }
      // single soft hyphen between letters is legitimate hyphenation hint
      if (count === 1 && kinds.has(0x00ad) && isLetterLike(prev) && isLetterLike(next)) continue;
      // A single invisible math operator between one-character operands, with no other invisible character nearby, in
      // a line with a digit or a math sign is a formula (a\u2062b, 2\u20641/2), not a split word. Chains (i\u2062g\u2062n...)
      // are not isolated, and a split two-letter context word ("A\u2062I") still counts.
      if (count === 1 && MATH_OPS.has(cp) && isLetterLike(prev) && isLetterLike(next) && formula(start, end, prev, next)) continue;
      // single ZWSP next to whitespace/punctuation only (e.g. from copy-paste) is low noise -> info
      const splitsWord = isLetterLike(prev) && isLetterLike(next);

      if (count >= 3 || splitsWord || count >= 2) {
        const names = [...kinds].map(uplus).join(", ");
        const severity = count >= 8 ? "high" : count >= 3 || splitsWord ? "medium" : "low";
        findings.push({
          id: "zero-width",
          category: "zero-width",
          severity,
          start,
          end,
          excerpt: ctx.helpers.excerpt(start, end),
          reason: splitsWord
            ? `${count} invisible character${count > 1 ? "s" : ""} (${names}) splitting a word — a classic way to defeat keyword filters`
            : `Run of ${count} invisible characters (${names})`,
          meta: { count, chars: [...kinds] },
        });
      } else {
        findings.push({
          id: "zero-width",
          category: "zero-width",
          severity: "info",
          start,
          end,
          excerpt: ctx.helpers.excerpt(start, end),
          reason: `Stray invisible character ${[...kinds].map(uplus).join(", ")}`,
          meta: { count, chars: [...kinds] },
        });
      }
    }
    // Merge adjacent word-splitting findings (e.g. "I\u200bg\u200bn\u200bo\u200br\u200be") into one span per word/phrase.
    // Text fields are built once per merged group: rebuilding them on every merge made long interleaved runs quadratic.
    const merged: Finding[] = [];
    const groups: { f: Finding; chars: Set<number>; count: number; parts: number; allInfo: boolean }[] = [];
    for (const f of findings) {
      const g = groups[groups.length - 1];
      if (g && f.start - g.f.end <= 2) {
        g.f.end = f.end;
        for (const c of f.meta?.chars as number[]) g.chars.add(c);
        g.count += (f.meta?.count as number) ?? 1;
        g.parts++;
        g.allInfo = g.allInfo && f.severity === "info";
        continue;
      }
      groups.push({ f, chars: new Set(f.meta?.chars as number[]), count: (f.meta?.count as number) ?? 1, parts: 1, allInfo: f.severity === "info" });
    }
    for (const g of groups) {
      const f = g.f;
      if (g.parts > 1) {
        const chars = [...g.chars];
        f.meta = { ...f.meta, count: g.count, chars };
        f.reason = `${g.count} invisible characters (${chars.map(uplus).join(", ")}) interleaved through “${short(s.slice(f.start, f.end).replace(/[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]/g, ""))}”`;
        f.excerpt = ctx.helpers.excerpt(f.start, f.end);
        f.severity = g.count >= 8 ? "high" : g.count >= 3 ? "medium" : g.allInfo ? "low" : f.severity;
      }
      merged.push(f);
    }
    findings.length = 0;
    // a loop, not push(...spread): hundreds of thousands of findings overflow the call stack
    for (const f of merged) findings.push(f);
    for (const f of decodedRuns) findings.push(f);
    // Many scattered invisible chars across the doc -> steganographic channel (e.g. ZWSP/ZWNJ binary)
    if (total >= 24 && findings.length >= 8) {
      findings.push({
        id: "zero-width",
        category: "zero-width",
        severity: "high",
        start: findings[0].start,
        end: findings[findings.length - 1].end,
        excerpt: `${total} invisible characters across the document`,
        reason: `${total} invisible characters scattered through the text — consistent with a zero-width steganographic payload`,
        meta: { total },
      });
    }
    return findings;
  },
};
