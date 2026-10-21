import type { Severity } from "../types";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 2,
  low: 6,
  medium: 18,
  high: 32,
  critical: 48,
};

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

/** Render a code point as U+XXXX */
export function uplus(cp: number): string {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

/** Make invisible characters visible for excerpts. */
export function reveal(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (
      (cp >= 0x200b && cp <= 0x200f) ||
      (cp >= 0x2060 && cp <= 0x2064) ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      cp === 0xfeff ||
      cp === 0x00ad ||
      (cp >= 0xe0000 && cp <= 0xe007f)
    ) {
      out += "⟨" + uplus(cp) + "⟩";
    } else if (cp === 0x0a) out += "⏎";
    else if (cp === 0x09) out += "⇥";
    else out += ch;
  }
  return out;
}

export function makeExcerpt(input: string, start: number, end: number, pad = 24, max = 160): string {
  const s = Math.max(0, start - pad);
  const e = Math.min(input.length, end + pad);
  let core = input.slice(s, e);
  if (core.length > max) core = core.slice(0, max) + "…";
  return (s > 0 ? "…" : "") + reveal(core) + (e < input.length ? "…" : "");
}

/** Unicode script classes we care about for homoglyph detection */
export function isLatinLetter(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0xc0 && cp <= 0x24f && cp !== 0xd7 && cp !== 0xf7)
  );
}
export function isCyrillicLetter(cp: number): boolean {
  return (cp >= 0x400 && cp <= 0x4ff) || (cp >= 0x500 && cp <= 0x52f);
}
export function isGreekLetter(cp: number): boolean {
  return cp >= 0x370 && cp <= 0x3ff;
}
export function isCJK(cp: number): boolean {
  return (
    (cp >= 0x3040 && cp <= 0x30ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xac00 && cp <= 0xd7af) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xff00 && cp <= 0xffef)
  );
}
export function isEmojiish(cp: number): boolean {
  return (
    (cp >= 0x1f000 && cp <= 0x1faff) ||
    (cp >= 0x2600 && cp <= 0x27bf) ||
    (cp >= 0x2300 && cp <= 0x23ff) ||
    (cp >= 0x2b00 && cp <= 0x2bff) ||
    cp === 0x2764 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0x1f3fb && cp <= 0x1f3ff) ||
    (cp >= 0xe0020 && cp <= 0xe007f) // tag chars used in flag sequences follow a 🏴 base
  );
}

/** Code point at UTF-16 index, with its length in code units. */
export function cpAt(s: string, i: number): { cp: number; len: number } {
  const cp = s.codePointAt(i)!;
  return { cp, len: cp > 0xffff ? 2 : 1 };
}

/** Iterate over "tokens" of a string: maximal runs of letters/digits/apostrophes/hyphens. */
export function* wordTokens(s: string): Generator<{ start: number; end: number; text: string }> {
  const re = /[\p{L}\p{M}\p{N}'’\-_.]+/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    yield { start: m.index, end: m.index + m[0].length, text: m[0] };
  }
}

/** Decode base64 (std + url-safe) to a UTF-8 string. Returns null on failure or if result is not mostly printable. */
export function tryBase64(s: string): string | null {
  let b = s.replace(/[-_]/g, (c) => (c === "-" ? "+" : "/")).replace(/\s+/g, "");
  if (b.length % 4 === 1) return null;
  while (b.length % 4) b += "=";
  try {
    const bytes = b64decode(b);
    if (!bytes) return null;
    const txt = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return mostlyPrintable(txt) ? txt : null;
  } catch {
    return null;
  }
}

// A base64-looking run: 4-char groups with at most one space or line break between them (line-wrapped blobs).
const BASE64_RUN = /(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/_-]{4}[\r\n ]?){5,}(?:[A-Za-z0-9+/_-]{2,4}={0,2})?(?![A-Za-z0-9+/=])/g;
// segments that are never part of a blob: a run of one repeated character (separator lines), a plain word, a short
// all-caps word; the run regex accepts them because of url-safe "-" / "_" and the gaps between groups
export const NOT_BASE64 = /^(?:(.)\1*|[A-Z]?[a-z]+[.,:;!?]?|[A-Z]{1,12}[.,:;!?]?)$/;

/**
 * Base64 blobs in a text: each run is split at its whitespace, and separator lines and plain words are dropped, so a
 * dashed line before a blob or the words after it do not join it. Offsets are into s.
 */
export function base64Blobs(s: string): { start: number; end: number; compact: string }[] {
  const out: { start: number; end: number; compact: string }[] = [];
  BASE64_RUN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BASE64_RUN.exec(s))) {
    const base = m.index;
    let start = -1, end = -1, compact = "";
    const flush = () => {
      if (start >= 0) out.push({ start, end, compact });
      start = -1;
      compact = "";
    };
    for (const seg of m[0].matchAll(/\S+/g)) {
      if (NOT_BASE64.test(seg[0])) {
        flush();
        continue;
      }
      if (start < 0) start = base + seg.index!;
      end = base + seg.index! + seg[0].length;
      compact += seg[0];
    }
    flush();
  }
  return out;
}

export function tryHex(s: string): string | null {
  const clean = s.replace(/[\s:,-]/g, "").replace(/0x/gi, "").replace(/\\x/gi, "");
  if (clean.length < 2 || clean.length % 2) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    const v = parseInt(clean.slice(i, i + 2), 16);
    if (Number.isNaN(v)) return null;
    bytes[i / 2] = v;
  }
  const txt = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return mostlyPrintable(txt) ? txt : null;
}

export function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function mostlyPrintable(txt: string): boolean {
  if (!txt.length) return false;
  let bad = 0;
  for (let i = 0; i < txt.length; i++) {
    const c = txt.charCodeAt(i);
    if (c === 0xfffd || (c < 0x20 && c !== 0x0a && c !== 0x0d && c !== 0x09)) bad++;
  }
  return bad / txt.length < 0.05;
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

/** Strip HTML tags to text while keeping a map from text offset → original offset. */
// Character references that decode to ASCII or to whitespace: what CSS keywords and instruction words can be
// spelled with. The full table (2,000+ names) is not shipped; a name outside it stays as written.
const NAMED_REFS: Record<string, string> = {
  Tab: "\t", NewLine: "\n", excl: "!", quot: '"', QUOT: '"', num: "#", dollar: "$", percnt: "%", amp: "&", AMP: "&",
  apos: "'", lpar: "(", rpar: ")", ast: "*", midast: "*", plus: "+", comma: ",", period: ".", sol: "/", colon: ":",
  semi: ";", lt: "<", LT: "<", equals: "=", gt: ">", GT: ">", quest: "?", commat: "@", lsqb: "[", lbrack: "[",
  bsol: "\\", rsqb: "]", rbrack: "]", Hat: "^", lowbar: "_", UnderBar: "_", grave: "`", DiacriticalGrave: "`",
  lcub: "{", lbrace: "{", verbar: "|", vert: "|", VerticalLine: "|", rcub: "}", rbrace: "}", nbsp: "\u00A0",
  NonBreakingSpace: "\u00A0",
};
// decoded without ";" too, as the browser does for these legacy names (but not before a letter, digit or "=" in a value)
const LEGACY_REFS = new Set(["amp", "AMP", "lt", "LT", "gt", "GT", "quot", "QUOT", "nbsp"]);
const REF = /&(?:#[xX]([0-9a-fA-F]{1,8})|#([0-9]{1,9})|([A-Za-z][A-Za-z0-9]{0,31}))(;?)/y;

/** The character reference at s[i] === "&": its decoded text and its end, or undefined if it is not one. */
export function readCharRef(s: string, i: number, inAttribute: boolean): { text: string; end: number } | undefined {
  REF.lastIndex = i;
  const m = REF.exec(s);
  if (!m) return undefined;
  const end = i + m[0].length;
  if (m[1] !== undefined || m[2] !== undefined) {
    const cp = m[1] !== undefined ? parseInt(m[1], 16) : parseInt(m[2], 10);
    // null, surrogates and values past Unicode read as U+FFFD, as in the browser
    const ok = cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff);
    return { text: ok ? String.fromCodePoint(cp) : "\uFFFD", end };
  }
  const name = m[3];
  if (m[4] === ";") return name in NAMED_REFS ? { text: NAMED_REFS[name], end } : undefined;
  if (!LEGACY_REFS.has(name) || (inAttribute && /[A-Za-z0-9=]/.test(s[end] ?? ""))) return undefined;
  return { text: NAMED_REFS[name], end };
}

/** Decodes the character references in an attribute value (or, with `inAttribute` false, in text). */
export function decodeAttrValue(v: string, inAttribute = true): string {
  if (!v.includes("&")) return v;
  let out = "";
  let last = 0;
  for (let i = v.indexOf("&"); i >= 0; i = v.indexOf("&", i + 1)) {
    const r = readCharRef(v, i, inAttribute);
    if (!r) continue;
    out += v.slice(last, i) + r.text;
    last = r.end;
    i = r.end - 1;
  }
  return out + v.slice(last);
}

export function htmlToTextMap(html: string): { text: string; map: number[] } {
  const text: string[] = [];
  const map: number[] = [];
  // Same tokens as /<!--[\s\S]*?-->|<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<[^>]+>/gi, found with forward
  // searches whose results are reused: the regex re-scanned to the end of the input for every unclosed "<!--" or "<script".
  const finder = (re: RegExp) => {
    let at = -2;
    let found = -1;
    return (from: number): number => {
      // reuse the last answer only for a search that starts at or after the last one
      if (at !== -2 && at <= from && (found === -1 || found >= from)) return found;
      re.lastIndex = from;
      const m = re.exec(html);
      at = from;
      found = m ? m.index : -1;
      return found;
    };
  };
  const commentEnd = finder(/-->/g);
  const scriptEnd = finder(/<\/script>/gi);
  const styleEnd = finder(/<\/style>/gi);
  const tagEnd = finder(/>/g);
  const tokenEnd = (i: number): number => {
    if (html.startsWith("<!--", i)) {
      const c = commentEnd(i + 4);
      if (c >= 0) return c + 3;
    }
    const head = html.slice(i, i + 7).toLowerCase();
    if (head === "<script") {
      const c = scriptEnd(i + 7);
      if (c >= 0) return c + 9;
    }
    if (head.startsWith("<style")) {
      const c = styleEnd(i + 6);
      if (c >= 0) return c + 8;
    }
    // a tag opens only before a letter, "/", "!" or "?"; "<|im_start|>" and "a < b" are text, as in the browser
    if (i + 1 < html.length && /[A-Za-z/!?]/.test(html[i + 1])) {
      const c = tagEnd(i + 1);
      if (c >= 0) return c + 1;
    }
    return -1;
  };
  let last = 0;
  // text runs: character references are decoded, each decoded character mapped to the start of its reference
  const push = (from: number, to: number) => {
    for (let i = from; i < to; i++) {
      if (html[i] === "&") {
        const r = readCharRef(html, i, false);
        if (r && r.end <= to) {
          // one entry per UTF-16 unit, like the rest of the map
          for (let k = 0; k < r.text.length; k++) {
            text.push(r.text[k]);
            map.push(i);
          }
          i = r.end - 1;
          continue;
        }
      }
      text.push(html[i]);
      map.push(i);
    }
  };
  for (let i = html.indexOf("<"); i >= 0; ) {
    const end = tokenEnd(i);
    if (end < 0) {
      i = html.indexOf("<", i + 1);
      continue;
    }
    push(last, i);
    // tags act as whitespace; map that space to the END of the tag so a match starting right after it lands on real text
    text.push(" ");
    map.push(end);
    last = end;
    // after <plaintext> the rest of the document is shown as written: no tags, no references
    if (/^<plaintext[\t\n\f\r />]/i.test(html.slice(i, i + 11))) {
      for (let k = end; k < html.length; k++) {
        text.push(html[k]);
        map.push(k);
      }
      return { text: text.join(""), map };
    }
    i = html.indexOf("<", end);
  }
  push(last, html.length);
  return { text: text.join(""), map };
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64decode(b: string): Uint8Array | null {
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < b.length; i++) {
    const ch = b[i];
    if (ch === "=") break;
    const v = B64.indexOf(ch);
    if (v < 0) return null;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}
