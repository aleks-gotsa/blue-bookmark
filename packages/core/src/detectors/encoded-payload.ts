import type { Detector, Finding, Severity } from "../types";
import { enclosedInQuotes, insideClosedFence } from "../patterns";
import { base64Blobs, htmlToTextMap, maxSeverity, mostlyPrintable, NOT_BASE64, rot13, tryBase64, tryHex } from "../util/text";

// carrier-rating: an encoded payload is rated as a carrier, not by the phrasing of
// what it carries; readable text is medium, high with an address or URL, critical when the visible text points at it
const POINTER = /\b(?:decode[ds]?|decoding|base\s?-?64|b64|encoded|encoding|decipher|rot-?13|hex(?:adecimal)?|binary|base\s?-?32|reversed?|backwards?|(?:url|percent)-?encoded|code\s?points?|escaped|escapes)\b/i;
const BLOB_OR_MIME = /[A-Za-z0-9+/_=-]{20,}|^Content-[\w-]+:.*$/gim;
// bounded parts: an unbounded local part makes the search quadratic on a long word with no at sign
const ADDRESS = /[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,}|https?:\/\/\S+/i;

const NAMES: Record<string, string> = { hex: "Hex", base64: "Base64", binary: "Binary", percent: "Percent-encoded", escape: "Escape-sequence", entity: "Character-reference", codepoint: "Code-point", base32: "Base32", reversed: "Reversed" };

// decoders-extra: more encodings, each a run of 4+ units, rated like hex
const utf8 = (bytes: number[]) => new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
// built in chunks: spreading a long run into one call overflows the stack
const fromCodes = (cs: number[]) => {
  if (!cs.every((c) => c >= 0 && c <= 0x10ffff)) return "";
  let out = "";
  for (let i = 0; i < cs.length; i += 8192) out += String.fromCodePoint(...cs.slice(i, i + 8192));
  return out;
};
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
interface Decoder {
  encoding: string;
  re: RegExp;
  decode: (run: string) => string | null;
}
const DECODERS: Decoder[] = [
  { encoding: "binary", re: /(?<![01])(?:[01]{8}[ \t,]?){4,}/g, decode: (r) => utf8(r.match(/[01]{8}/g)!.map((b) => parseInt(b, 2))) },
  {
    encoding: "percent",
    re: /(?:%[0-9A-Fa-f]{2}){2,}(?:[\w.~-]{0,3}(?:%[0-9A-Fa-f]{2})+)*/g,
    decode: (r) => ((r.match(/%/g) ?? []).length < 4 ? null : utf8([...r.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))].map((c) => c.charCodeAt(0) & 0xff))),
  },
  {
    encoding: "escape",
    re: /(?:(?:\\u\{[0-9a-fA-F]{1,6}\}|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}) ?){4,}/g,
    decode: (r) => {
      const units = [...r.matchAll(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g)];
      // \x alone is bytes (UTF-8); \u is UTF-16 code units, so surrogate pairs join
      if (units.every((u) => u[3])) return utf8(units.map((u) => parseInt(u[3], 16)));
      return units.map((u) => (u[1] ? fromCodes([parseInt(u[1], 16)]) : String.fromCharCode(parseInt(u[2] ?? u[3], 16)))).join("");
    },
  },
  { encoding: "entity", re: /(?:&#(?:[xX][0-9a-fA-F]{1,6}|\d{1,7});[ \t]?){4,}/g, decode: (r) => fromCodes([...r.matchAll(/&#([xX][0-9a-fA-F]+|\d+);/g)].map((m) => (m[1][0] === "x" || m[1][0] === "X" ? parseInt(m[1].slice(1), 16) : +m[1]))) },
  // Unicode tag characters written as text (U+E0041) stand for the ASCII they mirror
  { encoding: "codepoint", re: /(?:U\+[0-9A-Fa-f]{4,6}[ \t,;]{0,2}){4,}/g, decode: (r) => fromCodes(r.match(/U\+[0-9A-Fa-f]{4,6}/g)!.map((u) => parseInt(u.slice(2), 16)).map((c) => (c >= 0xe0000 && c <= 0xe007f ? c - 0xe0000 : c))) },
  {
    encoding: "base32",
    re: /(?<![A-Za-z0-9])[A-Z2-7]{16,}={0,6}(?![A-Za-z0-9=])/g,
    decode: (r) => {
      if (!/[2-7]/.test(r) && !r.endsWith("=")) return null;
      const bytes: number[] = [];
      let acc = 0, n = 0;
      for (const c of r.replace(/=+$/, "")) {
        acc = ((acc << 5) | B32.indexOf(c)) & 0xffff;
        n += 5;
        if (n >= 8) bytes.push((acc >> (n -= 8)) & 0xff);
      }
      return utf8(bytes);
    },
  },
];

/** A run that is part of a URL: links encode addresses and paths all the time. */
function inUrl(s: string, start: number, end: number): boolean {
  let a = start;
  while (a > Math.max(0, start - 300) && !/\s/.test(s[a - 1])) a--;
  return s.slice(a, Math.min(s.length, end + 1)).includes("://") || /[?=&/]/.test(s[start - 1] ?? "");
}

/** The runs of every extra decoder in s that decode to printable text. */
function extraRuns(s: string, html: boolean): { start: number; end: number; encoding: string; txt: string }[] {
  const out: { start: number; end: number; encoding: string; txt: string }[] = [];
  for (const d of DECODERS) {
    if (html && d.encoding === "entity") continue; // the HTML reader decodes references; they are what a reader sees
    d.re.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = d.re.exec(s)); ) {
      const run = m[0].trimEnd();
      if (d.encoding === "percent" && inUrl(s, m.index, m.index + run.length)) continue;
      const txt = d.decode(run);
      if (txt && mostlyPrintable(txt)) out.push({ start: m.index, end: m.index + run.length, encoding: d.encoding, txt });
    }
  }
  return out;
}

/** One nested pass: what a decoded text decodes to in turn, by base64, hex or an extra decoder. */
function nested(txt: string): { encoding: string; txt: string }[] {
  const out: { encoding: string; txt: string }[] = [];
  for (const b of base64Blobs(txt)) {
    if (b.compact.length < 16) continue;
    const t = tryBase64(b.compact);
    if (t) out.push({ encoding: "base64", txt: t });
  }
  const hex = txt.match(/(?:(?:\\x|0x)?[0-9a-fA-F]{2}[\s:,-]?){16,}/g) ?? [];
  for (const h of hex) {
    const t = tryHex(h);
    if (t) out.push({ encoding: "hex", txt: t });
  }
  for (const r of extraRuns(txt, false)) out.push({ encoding: r.encoding, txt: r.txt });
  return out;
}

// split-payload: pieces of one payload with only glue between them, joined in order
const PIECE = /[A-Za-z0-9+/]{3,}={0,2}/g;
const LABEL_WORD = /^(?:part|chunk|piece|segment|fragment|step)$/i;
// glue: spaces, quotes, commas, "+", brackets, a typed "\n", list numbering, "part 2:" labels; at most 30 characters
const GLUE = /^(?:[\s"'`,+()[\];|]|\\n|\d{1,3}[.):]|[-*\u2022]|(?:part|chunk|piece|segment|fragment|step)\s*#?\d{1,3}\s*[:=-]?)*$/i;
const words3 = (t: string) => (t.match(/\p{L}{2,}/gu) ?? []).length >= 3;

/** Chains of 2+ pieces, 2+ of them not plain words, that decode to readable text only when joined in order. */
function splitChains(t: string): { start: number; end: number; pieces: number; txt: string; encoding: string }[] {
  const out: { start: number; end: number; pieces: number; txt: string; encoding: string }[] = [];
  let cur: { start: number; end: number; parts: string[]; hard: number } | null = null;
  const close = () => {
    if (!cur || cur.parts.length < 2 || cur.hard < 2) return;
    const joined = cur.parts.join("");
    if (joined.length < 20) return;
    let txt = tryBase64(joined), encoding = "base64";
    if (!(txt && words3(txt)) && /^[0-9a-fA-F]+$/.test(joined)) [txt, encoding] = [tryHex(joined), "hex"];
    if (txt && words3(txt)) out.push({ start: cur.start, end: cur.end, pieces: cur.parts.length, txt, encoding });
  };
  PIECE.lastIndex = 0;
  for (let m: RegExpExecArray | null; (m = PIECE.exec(t)); ) {
    const piece = m[0];
    if (LABEL_WORD.test(piece)) continue; // "part" in "part 2:" is glue
    const word = NOT_BASE64.test(piece.replace(/=+$/, "")) || /^\d+$/.test(piece);
    const glue = cur ? t.slice(cur.end, m.index) : "";
    // a plain word joins only across glue that is more than spaces, so ordinary prose never forms a chain
    // padding ends a payload: two padded blobs in a row are two payloads, not pieces of one
    if (cur && !cur.parts[cur.parts.length - 1].endsWith("=") && glue.length <= 30 && GLUE.test(glue) && (!word || /\S/.test(glue))) {
      cur.parts.push(piece);
      cur.end = m.index + piece.length;
      if (!word) cur.hard++;
      continue;
    }
    close();
    cur = { start: m.index, end: m.index + piece.length, parts: [piece], hard: word ? 0 : 1 };
  }
  close();
  return out;
}

// piece-decode: one short blob per word, each decoded on its own first and the
// decoded text joined in order. Joining the raw pieces cannot read it: every "=" padding ends a base64 payload.
const PIECE_MAX = 64;
const RANK: Severity[] = ["info", "low", "medium", "high", "critical"];
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64encode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "") + (i + 2 < bytes.length ? B64[n & 63] : "");
  }
  return out;
}
/** A piece's text: base64 only when it encodes back to the same piece (so a random ID that happens to decode is not
 * text), else even-length hex; printable, with a letter. */
function pieceText(p: string): string | null {
  const bare = p.replace(/=+$/, "");
  if (p.length > PIECE_MAX || NOT_BASE64.test(bare) || LABEL_WORD.test(bare)) return null;
  let txt = tryBase64(p);
  if (txt !== null && b64encode(new TextEncoder().encode(txt)) !== bare) txt = null;
  if (txt === null && p.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(p)) txt = tryHex(p);
  if (txt === null || !/\p{L}/u.test(txt) || !/^[\p{L}\p{M}\p{N}\p{P}\p{S} ]+$/u.test(txt)) return null;
  // Latin letters with letters of another script in one short piece are bytes that happened to decode: CSS "24px" is
  // valid base64 for an Arabic letter and "q"; a word in one script, Latin or not, is text
  return /[A-Za-z]/.test(txt) && /[^\P{L}A-Za-z]/u.test(txt) ? null : txt;
}
function pieceRuns(t: string): { start: number; end: number; parts: string[]; at: [number, number][] }[] {
  const out: { start: number; end: number; parts: string[]; at: [number, number][] }[] = [];
  let cur: { start: number; end: number; parts: string[]; at: [number, number][] } | null = null;
  const close = () => {
    if (cur && cur.parts.length >= 2 && words3(cur.parts.join(" "))) out.push(cur);
    cur = null;
  };
  for (const m of t.matchAll(PIECE)) {
    const txt = pieceText(m[0]);
    if (txt === null) {
      close();
      continue;
    }
    const glue = cur ? t.slice(cur.end, m.index) : "";
    if (cur && glue.length <= 30 && GLUE.test(glue)) {
      cur.parts.push(txt);
      cur.at.push([m.index, m.index + m[0].length]);
      cur.end = m.index + m[0].length;
      continue;
    }
    close();
    cur = { start: m.index, end: m.index + m[0].length, parts: [txt], at: [[m.index, m.index + m[0].length]] };
  }
  close();
  return out;
}

function once<T>(f: () => T): () => T {
  let done = false, v: T;
  return () => (done ? v : ((done = true), (v = f())));
}

/** Inside a closed code fence, or an open <code> / <pre> that closes after it (both looked for within 200 chars). */
function shownAsCode(s: string, start: number, end: number): boolean {
  const before = s.slice(Math.max(0, start - 200), start).toLowerCase();
  const inCode = Math.max(before.lastIndexOf("<code"), before.lastIndexOf("<pre")) > Math.max(before.lastIndexOf("</code"), before.lastIndexOf("</pre")) && /<\/(?:code|pre)>/i.test(s.slice(end, end + 200));
  return inCode || insideClosedFence(s, start, end);
}

// separated-tokens: 5+ single characters with the same separator between each
// (1–2 punctuation characters, optionally spaced), or 6+ with a space or a line break
const SEPARATED = /(?<![\p{L}\p{N}])[\p{L}\p{N}@.](\s?[|/\\_*~+:;,-]{1,2}\s?|\r?\n| )(?:[\p{L}\p{N}@.]\1){3,}[\p{L}\p{N}@.](?![\p{L}\p{N}])/gu;

/** Words spelled with a separator between every character, collapsed and read in place. */
function separatedWords(ctx: Parameters<Detector["run"]>[0], findings: Finding[]): void {
  const s = ctx.input;
  for (const m of s.matchAll(SEPARATED)) {
    const sep = m[1];
    const parts = m[0].split(sep);
    const spaced = /^\s+$/.test(sep);
    if (spaced && parts.length < 6) continue;
    const col = parts.join("");
    // digits and dots: dates, versions, IP addresses, phone numbers
    if (/^[\d.]+$/.test(col)) continue;
    const start = m.index!, end = start + m[0].length;
    // read the collapsed word in its context (200 chars each way, so many runs stay linear)
    const w0 = Math.max(0, start - 200);
    const around = s.slice(w0, start) + col + s.slice(end, Math.min(s.length, end + 200));
    const at = start - w0;
    const instr = ctx.helpers.matchInstructions(around).filter((h) => h.start < at + col.length && h.end > at);
    const address = /[\w.+-]{1,64}@[\w-]{1,63}\.[a-z]{2,}/i.test(col);
    let severity: Severity | null = instr.length ? "critical" : address ? "high" : !spaced && (col.match(/\p{L}/gu) ?? []).length >= 5 ? "medium" : null;
    if (!severity) continue;
    if (shownAsCode(s, start, end)) severity = "info";
    findings.push({
      id: "encoded-payload",
      category: "encoded-payload",
      severity,
      start,
      end,
      excerpt: ctx.helpers.excerpt(start, end, 6),
      reason: `Text spelled with ${JSON.stringify(sep)} between every character${instr.length ? ` reads as agent-directed instructions (${instr.map((h) => h.pattern).join(", ")})` : address ? " hides an email address" : ""}: “${col.slice(0, 80)}”`,
      decoded: col,
      meta: { encoding: "separated", separator: sep, ...(instr.length ? { patterns: instr.map((h) => h.pattern) } : {}) },
    });
  }
}

/** How a readable decoded blob is rated, or null when it is not a carrier (binary, a URL token, a JWT). */
function rateCarrier(s: string, start: number, end: number, txt: string, encoding: string, pointer: () => boolean, quotesShow = true): Omit<Finding, "excerpt"> | null {
  if ((txt.match(/\p{L}{2,}/gu) ?? []).length < 3) return null;
  // the non-space token around the blob: tracking and unsubscribe links encode the recipient's address, a JWT the user
  // (read at most 300 chars each way, so many blobs inside one long token stay linear)
  let a = start, b = end;
  while (a > Math.max(0, start - 300) && !/\s/.test(s[a - 1])) a--;
  while (b < Math.min(s.length, end + 300) && !/\s/.test(s[b])) b++;
  const token = s.slice(a, b);
  if (token.includes("://") || /[?=&]/.test(s[start - 1] ?? "") || /eyJ[\w-]*\.[\w-]+\./.test(token)) return null;
  // shown, not hidden: inside a closed code fence, enclosing quotes, or <code> / <pre>
  const shown = shownAsCode(s, start, end) || (quotesShow && enclosedInQuotes(s, start, end));
  const mime = /Content-Transfer-Encoding:\s*base64/i.test(s.slice(Math.max(0, start - 400), start).split("\n").slice(-6).join("\n"));
  const address = ADDRESS.test(txt);
  let severity: Severity = shown ? "info" : address ? (pointer() && !mime ? "critical" : "high") : "medium";
  if (mime && severity !== "info") severity = "medium";
  const what = address ? "readable text with an address or URL" : "readable text";
  return {
    id: "encoded-payload",
    category: "encoded-payload",
    severity,
    start,
    end,
    reason: `${NAMES[encoding] ?? encoding} blob hides ${what}${severity === "critical" ? ", and the visible text points at decoding it" : ""}${shown ? " (shown as code or a quote)" : ""}: “${txt.slice(0, 80).replace(/\s+/g, " ")}${txt.length > 80 ? "…" : ""}”`,
    decoded: txt,
    meta: { encoding, carrier: true, address, shown, mime },
  };
}

export const encodedPayload: Detector = {
  id: "encoded-payload",
  category: "encoded-payload",
  severity: "high",
  description: "Base64 / hex / ROT13 blobs that decode to agent-directed instructions.",
  run(ctx) {
    const s = ctx.input;
    const findings: Finding[] = [];
    const decode = ctx.options.decodeBase64 !== false;
    // does the visible text, outside the blobs and MIME header lines, name the encoding or ask for decoding?
    const pointer = once(() => POINTER.test(s.replace(BLOB_OR_MIME, " ")));

    // --- base64 (allow line-wrapped blobs) ---
    let m: RegExpExecArray | null;
    for (const { start, end, compact } of base64Blobs(s)) {
      if (compact.length < 20) continue;
      // skip obvious non-payloads: long words, hex-only, all-digit, url slugs with no mixed case
      if (/^[a-z]+$/.test(compact) || /^[A-Z]+$/.test(compact) || /^[0-9a-f]+$/i.test(compact) || /^\d+$/.test(compact)) continue;
      if (compact.length < 40) {
        // a short blob (20–39 chars) is read only when it has base64 shape and decodes to an instruction;
        // readable short text alone is not a finding
        if (!decode || !((/[A-Z]/.test(compact) && /[a-z0-9]/.test(compact)) || compact.endsWith("="))) continue;
        const txt = tryBase64(compact);
        const instr = txt ? ctx.helpers.matchInstructions(txt) : [];
        if (!instr.length) continue;
        const severity = instr.map((h) => h.severity).reduce(maxSeverity);
        findings.push({
          id: "encoded-payload",
          category: "encoded-payload",
          severity,
          start,
          end,
          excerpt: ctx.helpers.excerpt(start, end, 6),
          reason: `Short base64 blob decodes to agent-directed content (${instr.map((h) => h.pattern).join(", ")}): “${txt!.slice(0, 100).replace(/\s+/g, " ")}”`,
          decoded: txt!,
          meta: { encoding: "base64", patterns: instr.map((h) => h.pattern) },
        });
        continue;
      }
      // a data: URI image body, a JWT, a sha — skip when clearly binary/known format unless it decodes to instructions
      const before = s.slice(Math.max(0, start - 30), start);
      const isImageData = /data:image\/[a-z+]+;base64,$/i.test(before);
      if (!decode) {
        if (!isImageData)
          findings.push({ id: "encoded-payload", category: "encoded-payload", severity: "low", start, end, excerpt: ctx.helpers.excerpt(start, end, 6), reason: `Base64-looking blob of ${compact.length} chars (decoding disabled)` });
        continue;
      }
      const txt = tryBase64(compact);
      if (!txt) {
        if (!isImageData && compact.length >= 120 && /[A-Z]/.test(compact) && /[a-z]/.test(compact) && /\d/.test(compact))
          findings.push({ id: "encoded-payload", category: "encoded-payload", severity: "info", start, end, excerpt: ctx.helpers.excerpt(start, end, 6), reason: `Base64 blob of ${compact.length} chars did not decode to text (binary or key material)` });
        continue;
      }
      const instr = ctx.helpers.matchInstructions(txt);
      // nested base64 (double encoding)
      let inner = /^[A-Za-z0-9+/=\s]{40,}$/.test(txt.trim()) ? tryBase64(txt.trim()) : null;
      let innerInstr = inner ? ctx.helpers.matchInstructions(inner) : [];
      if (!instr.length && !innerInstr.length) {
        // one nested pass through the extra decoders too: base64 of a %xx string
        for (const n of extraRuns(txt, false)) {
          const hit = ctx.helpers.matchInstructions(n.txt);
          if (hit.length) [inner, innerInstr] = [n.txt, hit];
        }
      }
      if (instr.length || innerInstr.length) {
        const decoded = innerInstr.length ? inner! : txt;
        const hits = innerInstr.length ? innerInstr : instr;
        findings.push({
          id: "encoded-payload",
          category: "encoded-payload",
          severity: "critical",
          start,
          end,
          excerpt: ctx.helpers.excerpt(start, end, 6),
          reason: `Base64 blob decodes to agent-directed instructions (${hits.map((h) => h.pattern).join(", ")})${innerInstr.length ? " after double decoding" : ""}: “${decoded.slice(0, 100).replace(/\s+/g, " ")}${decoded.length > 100 ? "…" : ""}”`,
          decoded,
          meta: { encoding: "base64", patterns: hits.map((h) => h.pattern), nested: innerInstr.length > 0 },
        });
      } else if (!isImageData) {
        const f = rateCarrier(s, start, end, txt, "base64", pointer);
        if (f) findings.push({ ...f, excerpt: ctx.helpers.excerpt(start, end, 6) });
      }
    }

    // spelled-apart words are not an encoding the option turns off: nothing has to be decoded to read them
    separatedWords(ctx, findings);

    if (!decode) return findings;

    // --- hex (\x41\x42, 0x41 0x42, or a long run of hex pairs) ---
    const hexRe = /(?:(?:\\x|0x)?[0-9a-fA-F]{2}[\s:,-]?){24,}/g;
    while ((m = hexRe.exec(s))) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      // avoid hashes / uuids: must decode to text with instructions
      const txt = tryHex(raw);
      if (!txt) continue;
      const instr = ctx.helpers.matchInstructions(txt);
      if (!instr.length) {
        const f = rateCarrier(s, start, end, txt, "hex", pointer);
        if (f) findings.push({ ...f, excerpt: ctx.helpers.excerpt(start, end, 6) });
        continue;
      }
      findings.push({
        id: "encoded-payload",
        category: "encoded-payload",
        severity: "critical",
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end, 6),
        reason: `Hex-encoded text contains agent-directed instructions (${instr.map((h) => h.pattern).join(", ")}): “${txt.slice(0, 100)}”`,
        decoded: txt,
        meta: { encoding: "hex", patterns: instr.map((h) => h.pattern) },
      });
    }

    // --- extra decoders: binary, %xx, escapes, &#, U+ notation, base32 ---
    const taken = findings.filter((f) => f.meta?.encoding !== "separated").map((f) => [f.start, f.end] as const).sort((a, b) => a[0] - b[0]);
    // the furthest end among the spans that start at or before each one, so one binary search answers "overlaps?"
    const reach: number[] = [];
    taken.forEach(([, e], i) => reach.push(Math.max(e, i ? reach[i - 1] : 0)));
    const overlaps = (a: number, b: number) => {
      let lo = 0, hi = taken.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (taken[mid][0] < b) lo = mid + 1;
        else hi = mid;
      }
      return lo > 0 && reach[lo - 1] > a;
    };
    const rate = (start: number, end: number, txt: string, encoding: string, extra: Record<string, unknown> = {}) => {
      let decoded = txt, enc = encoding;
      let instr = ctx.helpers.matchInstructions(txt);
      if (!instr.length) {
        for (const n of nested(txt)) {
          const hit = ctx.helpers.matchInstructions(n.txt);
          if (hit.length) [decoded, enc, instr] = [n.txt, `${encoding}+${n.encoding}`, hit];
        }
      }
      if (instr.length) {
        findings.push({
          id: "encoded-payload",
          category: "encoded-payload",
          severity: "critical",
          start,
          end,
          excerpt: ctx.helpers.excerpt(start, end, 6),
          reason: `${NAMES[encoding]} text contains agent-directed instructions (${instr.map((h) => h.pattern).join(", ")}): “${decoded.slice(0, 100).replace(/\s+/g, " ")}”`,
          decoded,
          meta: { encoding: enc, patterns: instr.map((h) => h.pattern), ...extra },
        });
        return;
      }
      // the quotes around split pieces are glue, not a sign that the payload is only shown
      const f = rateCarrier(s, start, end, txt, encoding, pointer, !extra.split);
      if (f) findings.push({ ...f, excerpt: ctx.helpers.excerpt(start, end, 6), meta: { ...f.meta, ...extra } });
    };
    for (const r of extraRuns(s, ctx.contentType === "html")) if (!overlaps(r.start, r.end)) rate(r.start, r.end, r.txt, r.encoding);

    // --- split payloads: in the text, and in HTML also in the reader's text, where tags and comments are gone ---
    const views: { text: string; map: number[] | null }[] = [{ text: s, map: null }];
    if (ctx.contentType === "html") views.push(htmlToTextMap(s));
    // Linear on many chains: the spans taken and the findings made before this step are kept sorted
    // and found by binary search, and the findings a chain replaces are removed in one pass at the end. A chain's own
    // finding cannot lie inside a later chain's span without the two spans overlapping, unless its span is inverted (a
    // reader map out of source order); those few are checked one by one.
    const byStart = (list: Finding[], pos: number) => {
      let lo = 0, hi = list.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (list[mid].start < pos) lo = mid + 1;
        else hi = mid;
      }
      return lo;
    };
    const before = findings.slice().sort((x, y) => x.start - y.start);
    const byDecoded = new Map<string, Finding[]>();
    for (const f of before) if (f.decoded !== undefined) (byDecoded.get(f.decoded) ?? byDecoded.set(f.decoded, []).get(f.decoded)!).push(f);
    const removed = new Set<Finding>();
    const inside = (f: Finding, a: number, b: number) => !removed.has(f) && f.start >= a && f.end <= b;
    const spans: [number, number][] = []; // taken, disjoint, sorted by start
    const oddSpans: [number, number][] = [];
    const oddFound: Finding[] = [];
    const spanBefore = (pos: number, list = spans) => {
      let lo = 0, hi = list.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (list[mid][0] < pos) lo = mid + 1;
        else hi = mid;
      }
      return lo;
    };
    for (const v of views) {
      for (const c of splitChains(v.text)) {
        const start = v.map ? v.map[c.start] : c.start;
        const end = v.map ? Math.min(s.length, v.map[c.end - 1] + 1) : c.end;
        // disjoint sorted spans: of those starting before `end`, the last one reaches furthest
        const k = spanBefore(end);
        if ((k > 0 && spans[k - 1][1] > start) || oddSpans.some(([a, b]) => start < b && a < end)) continue;
        // the same text already found as one blob inside the span: nothing new to join
        const same = byDecoded.get(c.txt) ?? [];
        let dup = oddFound.some((f) => f.decoded === c.txt && inside(f, start, end));
        for (let i = byStart(same, start); !dup && i < same.length && same[i].start <= end; i++) dup = inside(same[i], start, end);
        if (dup) continue;
        if (end > start) spans.splice(spanBefore(start), 0, [start, end]);
        else oddSpans.push([start, end]);
        // the joined payload replaces what its pieces gave on their own
        for (let i = byStart(before, start); i < before.length && before[i].start <= end; i++) if (before[i].meta?.encoding !== "separated" && inside(before[i], start, end)) removed.add(before[i]);
        for (const f of oddFound) if (f.meta?.encoding !== "separated" && inside(f, start, end)) removed.add(f);
        const made = findings.length;
        rate(start, end, c.txt, c.encoding, { split: true, pieces: c.pieces });
        for (let i = made; i < findings.length; i++) if (!(findings[i].end > findings[i].start)) oddFound.push(findings[i]);
      }
    }
    if (removed.size) {
      let w = 0;
      for (const f of findings) if (!removed.has(f)) findings[w++] = f;
      findings.length = w;
      removed.clear();
    }

    // --- piece-decode: each short piece decoded first, the decoded text joined in order ---
    // A finding wholly inside a run is replaced by the run's reading, as split-payload does; a finding that reaches
    // outside it is another reading of the same text, and the run is left alone. Runs of one view are disjoint, so each
    // finding is visited once per view.
    const known = findings.slice().sort((x, y) => x.start - y.start);
    const reachTo: number[] = [];
    known.forEach((f, i) => reachTo.push(Math.max(f.end, i ? reachTo[i - 1] : 0)));
    const tight = (t: string) => ctx.helpers.matchInstructions(t).length * 2 + (ADDRESS.test(t) ? 1 : 0);
    // split-payload's joined chains are findings like any other here; only the runs already read are skipped
    const runs: [number, number][] = [];
    for (const v of views) {
      for (const r of pieceRuns(v.text)) {
        const start = v.map ? v.map[r.start] : r.start;
        const end = v.map ? Math.min(s.length, v.map[r.end - 1] + 1) : r.end;
        if (!(end > start)) continue;
        const k = spanBefore(end, runs);
        if (k > 0 && runs[k - 1][1] > start) continue;
        const i0 = byStart(known, start);
        if (i0 > 0 && reachTo[i0 - 1] > start) continue;
        // every piece already read as a blob of its own: the run adds nothing
        const read = (a: number, b: number) => {
          const i = byStart(known, a + 1) - 1;
          return i >= 0 && reachTo[i] >= b;
        };
        if (r.at.every(([a, b]) => (v.map ? read(v.map[a], v.map[b - 1] + 1) : read(a, b)))) continue;
        let outside = false;
        for (let i = i0; i < known.length && known[i].start < end && !outside; i++) outside = known[i].end > end;
        if (outside) continue;
        runs.splice(spanBefore(start, runs), 0, [start, end]);
        // two readings, fixed: words with spaces, and an address cut inside a word without them
        const spaced = r.parts.join(" "), joined = r.parts.join("");
        const txt = tight(joined) > tight(spaced) ? joined : spaced;
        const made = findings.length;
        rate(start, end, txt, "base64", { split: "decoded", pieces: r.parts.length });
        // the run's reading replaces what is inside it only when it rates higher than all of that, so it never lowers one
        const inside: Finding[] = [];
        for (let i = i0; i < known.length && known[i].start < end; i++) inside.push(known[i]);
        const top = inside.reduce((m, f) => Math.max(m, RANK.indexOf(f.severity)), -1);
        if (findings.length > made && RANK.indexOf(findings[made].severity) > top) for (const f of inside) removed.add(f);
        else findings.length = made;
      }
    }
    if (removed.size) {
      let w = 0;
      for (const f of findings) if (!removed.has(f)) findings[w++] = f;
      findings.length = w;
    }

    // --- reversed lines: only when the reversal shows an address or an instruction the line does not ---
    const lineRe = /[^\n]{20,}/g;
    while ((m = lineRe.exec(s))) {
      const line = m[0];
      if (!/\p{L}{2,}/u.test(line)) continue;
      const back = [...line].reverse().join("");
      const addr = ADDRESS.test(back) && !ADDRESS.test(line);
      const instr = ctx.helpers.matchInstructions(back);
      if (!addr && !(instr.length && !ctx.helpers.matchInstructions(line).length)) continue;
      if (instr.length) {
        findings.push({
          id: "encoded-payload",
          category: "encoded-payload",
          severity: "critical",
          start: m.index,
          end: m.index + line.length,
          excerpt: ctx.helpers.excerpt(m.index, m.index + line.length, 0),
          reason: `Reversed text contains agent-directed instructions (${instr.map((h) => h.pattern).join(", ")}): “${back.slice(0, 100)}”`,
          decoded: back,
          meta: { encoding: "reversed", patterns: instr.map((h) => h.pattern) },
        });
      } else {
        const f = rateCarrier(s, m.index, m.index + line.length, back, "reversed", pointer);
        if (f) findings.push({ ...f, excerpt: ctx.helpers.excerpt(m.index, m.index + line.length, 0) });
      }
    }

    // --- ROT13: run on each paragraph; only report if decoded text matches and original did not ---
    const paraRe = /[^\n]{20,}/g;
    while ((m = paraRe.exec(s))) {
      const para = m[0];
      if (!/[a-zA-Z]{4,}/.test(para)) continue;
      // cheap pre-check: ROT13 text has unusual letter frequency; just decode and test
      const dec = rot13(para);
      const instr = ctx.helpers.matchInstructions(dec);
      if (!instr.length) continue;
      if (ctx.helpers.matchInstructions(para).length) continue;
      findings.push({
        id: "encoded-payload",
        category: "encoded-payload",
        // critical like base64 and hex: an instruction a reader cannot read is the same carrier in any encoding
        severity: "critical",
        start: m.index,
        end: m.index + para.length,
        excerpt: ctx.helpers.excerpt(m.index, m.index + para.length, 0),
        reason: `ROT13-encoded text contains agent-directed instructions (${instr.map((h) => h.pattern).join(", ")}): “${dec.slice(0, 100)}”`,
        decoded: dec,
        meta: { encoding: "rot13", patterns: instr.map((h) => h.pattern) },
      });
    }
    return findings;
  },
};
