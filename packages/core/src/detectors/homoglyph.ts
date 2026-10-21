import type { Detector, Finding } from "../types";
import { CONFUSABLE_TO_ASCII } from "../data/confusables";
import { foldText, insideClosedFence } from "../patterns";
import { insideCode } from "./role-spoofing";
import { isCyrillicLetter, isGreekLetter, isLatinLetter, uplus, wordTokens } from "../util/text";

// A non-Latin letter counts as a lookalike when UTS #39 confuses it with one ASCII letter or digit: Cyrillic and
// Greek as before, and Armenian, Cherokee, math alphanumerics, fullwidth and the rest of the table.
const lookalike = (cp: number): string | undefined => (isLatinLetter(cp) ? undefined : CONFUSABLE_TO_ASCII.get(cp));
// a word written wholly in math alphanumerics or fullwidth Latin letters
const FANCY = (cp: number) => (cp >= 0x1d400 && cp <= 0x1d7ff) || (cp >= 0xff21 && cp <= 0xff3a) || (cp >= 0xff41 && cp <= 0xff5a);

/** Inside inline code on its line, a closed code fence, or <code> / <pre>: a command or an identifier. */
function inCode(s: string, start: number, end: number): boolean {
  const before = s.slice(Math.max(0, start - 300), start);
  const line = before.slice(before.lastIndexOf("\n") + 1);
  const after = s.slice(end, end + 300);
  const rest = after.slice(0, after.indexOf("\n") < 0 ? after.length : after.indexOf("\n"));
  const inline = ((line.match(/`/g) ?? []).length % 2 === 1 && rest.includes("`"));
  return inline || insideClosedFence(s, start, end) || insideCode(s, start);
}

const STEPS: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];

export const homoglyph: Detector = {
  id: "homoglyph",
  category: "homoglyph",
  severity: "medium",
  description: "Mixed-script tokens: Cyrillic/Greek letters that look Latin, inside an otherwise Latin word (or vice versa).",
  run(ctx) {
    const findings: Finding[] = [];
    const s = ctx.input;
    let fancySeen = false;
    for (const tok of wordTokens(s)) {
      const text = tok.text;
      // two-letter words count too: "\u0456n"
      if (text.length < 2) continue;
      let latin = 0,
        cyr = 0,
        greek = 0,
        other = 0;
      for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        if (isLatinLetter(cp)) latin++;
        else if (isCyrillicLetter(cp)) cyr++;
        else if (isGreekLetter(cp)) greek++;
        else if (/\p{L}/u.test(ch)) other++;
      }
      // letters of other scripts count only when they pass for Latin (a Japanese word next to a Latin one does not)
      let otherLookalikes = 0;
      if (other) for (const ch of text) if (!isCyrillicLetter(ch.codePointAt(0)!) && !isGreekLetter(ch.codePointAt(0)!) && lookalike(ch.codePointAt(0)!)) otherLookalikes++;
      const foreign = cyr + greek + otherLookalikes;
      // a word of 3+ fancy letters and nothing else: "\u{1D5E1}\u{1D5F2}\u{1D604}"; read with suspicion, never a block alone
      if (latin === 0 && cyr === 0 && greek === 0 && otherLookalikes >= 3 && otherLookalikes === other && [...text].every((ch) => FANCY(ch.codePointAt(0)!) || !/\p{L}/u.test(ch))) {
        // one medium per text: a whole newsletter in a fancy font is review, never a block by adding up
        const first = !fancySeen;
        fancySeen = true;
        findings.push({
          id: "homoglyph",
          category: "homoglyph",
          severity: first ? "medium" : "info",
          start: tok.start,
          end: tok.end,
          excerpt: ctx.helpers.excerpt(tok.start, tok.end),
          reason: `Word written in lookalike letters “${text}” reads as “${foldText(text)?.folded ?? text}”`,
          meta: { fancy: true, latin, other },
        });
        continue;
      }
      if (latin === 0 || foreign === 0) continue; // whole-word Cyrillic/Greek is fine (a Ukrainian sentence)
      // Latin-dominated word with a few confusable foreign letters — or foreign-dominated with latin confusables
      const minority = Math.min(latin, foreign);
      const confusables: string[] = [];
      for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        const ascii = lookalike(cp);
        if (ascii && latin >= foreign) confusables.push(`${ch} (${uplus(cp)}) → ${ascii}`);
        else if (isLatinLetter(cp) && foreign > latin && /[aeopcyxiBKMHTX]/.test(ch)) confusables.push(`${ch} (${uplus(cp)}) looks Cyrillic`);
      }
      // Legit mixed tokens: hyphenated compounds like "n8n-нода", "API-ключ": split on hyphen/underscore/dot and re-check each part
      const parts = text.split(/[-_./]/).filter(Boolean);
      if (parts.length > 1) {
        let mixedPart = false;
        for (const p of parts) {
          let l = 0,
            f = 0;
          for (const ch of p) {
            const cp = ch.codePointAt(0)!;
            if (isLatinLetter(cp)) l++;
            else if (isCyrillicLetter(cp) || isGreekLetter(cp)) f++;
          }
          if (l && f) mixedPart = true;
        }
        if (!mixedPart) continue;
      }
      if (confusables.length === 0) {
        // Mixed script with non-confusable letters (e.g. "Ukrainian suffix on Latin stem": "Telegram'і", "GitHub-у") — info only
        if (minority <= 2 && /['’]/.test(text)) continue;
        if (minority <= 2 && foreign <= 2 && /[ауюіиеєяїо]$/i.test(text) && latin >= 3) continue; // "GitHub\u0443" style case endings
        findings.push({
          id: "homoglyph",
          category: "homoglyph",
          severity: "info",
          start: tok.start,
          end: tok.end,
          excerpt: ctx.helpers.excerpt(tok.start, tok.end),
          reason: `Mixed-script token “${text}” (${latin} Latin, ${foreign} Cyrillic/Greek)`,
          meta: { latin, cyr, greek, other },
        });
        continue;
      }
      // a foreign letter in a command or an identifier is the spoof itself, not a language habit
      const code = inCode(s, tok.start, tok.end);
      const severity = code ? "high" : minority >= 2 || text.length <= 6 ? "medium" : "low";
      findings.push({
        id: "homoglyph",
        category: "homoglyph",
        severity,
        start: tok.start,
        end: tok.end,
        excerpt: ctx.helpers.excerpt(tok.start, tok.end),
        reason: `Mixed-script word “${text}” contains confusable letters: ${confusables.join("; ")}`,
        meta: { confusables, latin, cyr, greek, ...(code ? { code } : {}) },
      });
    }
    // several different mixed words in one text add up, in any language: 2 make one of them high, 3 or more make all critical; fancy-font
    // words join the count only next to an ordinary mixed word
    const mixed = findings.filter((f) => f.meta?.confusables);
    const words = new Set(mixed.map((f) => s.slice(f.start, f.end).toLowerCase()));
    if (words.size) for (const f of findings) if (f.meta?.fancy) words.add(s.slice(f.start, f.end).toLowerCase());
    if (words.size >= 2) {
      const lift: Finding["severity"] = words.size >= 3 ? "critical" : "high";
      // two words lift one finding, so the pair reads as one high (review); two highs would add up to a block
      const lifted = [...mixed, ...findings.filter((x) => x.meta?.fancy && x.severity !== "info")].sort((x, y) => STEPS.indexOf(y.severity) - STEPS.indexOf(x.severity));
      for (const f of words.size >= 3 ? lifted : lifted.slice(0, 1)) {
        if (STEPS.indexOf(f.severity) < STEPS.indexOf(lift)) {
          f.severity = lift;
          f.reason += ` — one of ${words.size} words in lookalike letters`;
        }
      }
    }
    for (const f of obfuscatedAddresses(s)) findings.push({ id: "homoglyph", category: "homoglyph", ...f, excerpt: ctx.helpers.excerpt(f.start, f.end) });
    return findings;
  },
};

// an email address written in lookalike letters (fullwidth, Cyrillic, math...), often with zero-width
// characters between them, so that it reads as an address to a model but not to a filter. Only addresses whose letters
// are lookalikes count: a fullwidth at sign next to ASCII letters is a Japanese anti-scraping habit, and Latin letters
// with diacritics (m\u00FCller@, m\u00FCnchen.de) are not lookalikes.
const AT = /[@\uFF20\uFE6B]/g;
const STOP = /[\s<>"'(),;:[\]{}]/;
const INVISIBLE = /[\u00AD\u200B-\u200D\u2060\uFEFF]/g;
const ADDRESS = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

function obfuscatedAddresses(s: string): { start: number; end: number; severity: "high" | "critical"; reason: string; meta: Record<string, unknown> }[] {
  const out: { start: number; end: number; severity: "high" | "critical"; reason: string; meta: Record<string, unknown> }[] = [];
  let lastEnd = -1;
  AT.lastIndex = 0;
  for (let m: RegExpExecArray | null; (m = AT.exec(s)); ) {
    if (m.index < lastEnd) continue;
    // the token around the at sign, at most 254 chars each way (the longest address), so long runs stay linear
    let a = m.index;
    while (a > 0 && m.index - a < 254 && !STOP.test(s[a - 1])) a--;
    let b = m.index + 1;
    while (b < s.length && b - m.index < 254 && !STOP.test(s[b])) b++;
    const raw = s.slice(a, b);
    if (!/[^\x00-\x7F]/.test(raw)) continue;
    const zw = (raw.match(INVISIBLE) || []).length;
    const visible = raw.replace(INVISIBLE, "");
    const folded = (foldText(visible)?.folded ?? visible).replace(/[.,;:!?]+$/, "");
    if (!ADDRESS.test(folded)) continue;
    let lookalikes = 0;
    for (const ch of visible) {
      const cp = ch.codePointAt(0)!;
      if (cp >= 0x80 && !isLatinLetter(cp) && /\p{L}|\p{N}/u.test(ch) && /^[A-Za-z0-9]$/.test(foldText(ch)?.folded ?? "")) lookalikes++;
    }
    if (lookalikes < 2) continue;
    lastEnd = b;
    out.push({
      start: a,
      end: b,
      severity: zw ? "critical" : "high",
      reason: `Address written in ${lookalikes} lookalike letters${zw ? ` with ${zw} invisible characters between them` : ""}: reads as ${folded}`,
      meta: { address: folded, lookalikes, invisible: zw },
    });
  }
  return out;
}
