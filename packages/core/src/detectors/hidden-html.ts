import type { Detector, Finding, Severity } from "../types";
import { enclosedInQuotes, insideClosedFence } from "../patterns";
import { buildTree } from "../html-tree";
import { decodeAttrValue } from "../util/text";
import { registerScanCache } from "../util/caches";

const VOID = new Set(["br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr"]);

interface HiddenReason {
  reason: string;
  severity: Severity;
}

// CSS comments are dropped and escapes decoded before a value is read, as the browser does: display:/**/none and
// display:n\one are display:none. indexOf, not a lazy regex, so many unclosed "/*" stay linear.
function cssText(css: string): string {
  let out = "";
  let i = 0;
  for (let c = css.indexOf("/*"); c >= 0; c = css.indexOf("/*", i)) {
    out += css.slice(i, c) + " ";
    const e = css.indexOf("*/", c + 2);
    if (e < 0) return out; // an unclosed comment runs to the end
    i = e + 2;
  }
  out += css.slice(i);
  if (!out.includes("\\")) return out;
  return out.replace(/\\([0-9a-fA-F]{1,6})[\t\n\f\r ]?|\\([^\n0-9a-fA-F])/g, (_m, hex: string | undefined, ch: string | undefined) => {
    if (ch !== undefined) return ch;
    const cp = parseInt(hex!, 16);
    return cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? "\uFFFD" : String.fromCodePoint(cp);
  });
}

function hiddenByStyle(style: string): HiddenReason | null {
  const st = cssText(style).toLowerCase().replace(/\s+/g, " ");
  if (/display\s*:\s*none/.test(st)) return { reason: "display:none", severity: "high" };
  if (/visibility\s*:\s*hidden/.test(st)) return { reason: "visibility:hidden", severity: "high" };
  if (/font-size\s*:\s*0(\.0+)?(px|pt|em|rem|%)?\b/.test(st)) return { reason: "font-size:0", severity: "high" };
  // a font a reader cannot read: at most 1px / 1pt, or a tenth of an em (Talos hidden-text salting)
  if (/font-size\s*:\s*(?:0?\.\d+|1)(?:px|pt)\b|font-size\s*:\s*0?\.0\d*r?em\b/.test(st)) return { reason: "font too small to read", severity: "high" };
  if (/opacity\s*:\s*(?:0|0?\.0*[0-4]?)(?![.\d])/.test(st)) return { reason: "opacity:0", severity: "high" };
  if (/transform\s*:[^;]*\bscale[xy]?\(\s*0(?:\.0+)?\s*[,)]/.test(st)) return { reason: "transform:scale(0)", severity: "high" };
  if (/(?:^|;)\s*(?:left|top|right|bottom)\s*:\s*-\d{3,}/.test(st) || /text-indent\s*:\s*-\d{3,}/.test(st)) return { reason: "positioned off-screen", severity: "high" };
  if (/clip\s*:\s*rect\(\s*0(px)?\s*,?\s*0(px)?\s*,?\s*0(px)?\s*,?\s*0(px)?\s*\)/.test(st) || /clip-path\s*:\s*inset\(\s*(100%|50%)/.test(st)) return { reason: "clipped to zero size", severity: "high" };
  const overflowHidden = /overflow\s*:\s*hidden/.test(st);
  // zero-size box, also as max-height / max-width and with !important (Outlook-safe hiding)
  if (overflowHidden && /(?:^|;)\s*(?:max-)?(?:width|height)\s*:\s*0(?:px|em|rem|%)?\s*(?:!important)?\s*(?:;|$)/.test(st)) return { reason: "zero-size overflow:hidden box", severity: "high" };
  if (overflowHidden && /(?:^|;)\s*line-height\s*:\s*0(?:px)?\s*(?:!important)?\s*(?:;|$)/.test(st)) return { reason: "line-height:0 overflow:hidden", severity: "high" };
  // a 1px box: screen-reader labels and pixels use it too, so it rates lower; instructions inside still block
  if (overflowHidden && /(?:^|;)\s*width\s*:\s*1px/.test(st) && /(?:^|;)\s*height\s*:\s*1px/.test(st)) return { reason: "1px overflow:hidden box", severity: "medium" };
  // color matches background
  const color = /(?:^|;)\s*color\s*:\s*([^;]+)/.exec(st)?.[1]?.trim();
  const bgValue = /background(?:-color)?\s*:\s*([^;]+)/.exec(st)?.[1]?.trim();
  // the shorthand holds an image, a position and a colour; take the colour
  const bg = bgValue && (/#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|\b(?:white|black|transparent)\b/.exec(bgValue)?.[0] ?? bgValue);
  if (color && bg && normalizeColor(color) === normalizeColor(bg)) return { reason: `text colour equals background (${color})`, severity: "high" };
  if (color && !bg && /^(#ffffff|transparent|rgba\([^)]*,0\))$/.test(normalizeColor(color)))
    return { reason: `white/transparent text (${color})`, severity: "medium" };
  // hidden in Outlook only, visible elsewhere: a known salting trick, and the usual way to ship an Outlook fallback
  if (/mso-hide\s*:\s*all/.test(st)) return { reason: "mso-hide:all (hidden in Outlook)", severity: "medium" };
  return null;
}

function normalizeColor(c: string): string {
  c = c.trim().toLowerCase().replace(/\s*!important$/, "").replace(/\s+/g, "");
  if (/^#[0-9a-f]{3}$/.test(c)) c = "#" + c[1] + c[1] + c[2] + c[2] + c[3] + c[3];
  if (c === "white") c = "#ffffff";
  if (c === "black") c = "#000000";
  // rgb(255,255,255) and rgba(255,255,255,1) are #ffffff; percentages too
  const rgb = /^rgba?\(([\d.]+%?),([\d.]+%?),([\d.]+%?)(?:,([\d.]+%?))?\)$/.exec(c);
  if (rgb && (rgb[4] === undefined || parseFloat(rgb[4]) >= 1)) {
    const v = rgb.slice(1, 4).map((x) => Math.round(x.endsWith("%") ? parseFloat(x) * 2.55 : parseFloat(x)));
    if (v.every((n) => n >= 0 && n <= 255)) c = "#" + v.map((n) => n.toString(16).padStart(2, "0")).join("");
  }
  return c;
}

// Tags are read with the browser's tokenizer states (WHATWG HTML §13.2.5, start/end tag and attribute states):
// a '>' inside a quoted value does not end the tag, '=' where a name should start is part of the name,
// comments are skipped, and script/style/title/textarea content is raw text, not tags. One pass, linear.
// noembed, noframes and iframe content is raw text that is never rendered
// noscript too: with scripting on, as in a browser, its content is raw text (tags inside it are text)
const RAW_TEXT = new Set(["script", "style", "title", "textarea", "xmp", "noembed", "noframes", "iframe", "noscript"]);
const WS = /[\t\n\f\r ]/;

interface Span {
  openStart: number;
  openEnd: number;
  end: number;
}

export interface Tag {
  start: number;
  end: number;
  name: string;
  closing: boolean;
  text: string;
  /** read as raw text by the tokenizer (not inside svg/math) */
  raw?: boolean;
}

/** Reads the tag that starts at `s[i] === "<"`. Returns its end (after '>') or -1 if the input ends inside it. */
function readTag(s: string, i: number, attrs?: Map<string, string>): number {
  const n = s.length;
  let k = i + (s[i + 1] === "/" ? 2 : 1);
  while (k < n && !WS.test(s[k]) && s[k] !== "/" && s[k] !== ">") k++; // tag name
  let state: "beforeName" | "name" | "afterName" | "beforeValue" | "dq" | "sq" | "unq" = "beforeName";
  let name = "";
  let nameStart = 0;
  let valueStart = 0;
  const done = (value: string) => {
    const key = name.toLowerCase();
    if (attrs && key && !attrs.has(key)) attrs.set(key, value);
    name = "";
  };
  for (; k < n; k++) {
    const c = s[k];
    switch (state) {
      case "beforeName":
        if (c === ">") return k + 1;
        if (!WS.test(c) && c !== "/") {
          state = "name";
          nameStart = k;
        }
        break;
      case "name":
        if (WS.test(c) || c === "/" || c === ">" || c === "=") {
          name = s.slice(nameStart, k);
          if (c === "=") state = "beforeValue";
          else if (c === ">") {
            done("");
            return k + 1;
          } else if (c === "/") {
            done("");
            state = "beforeName";
          } else state = "afterName";
        }
        break;
      case "afterName":
        if (c === "=") state = "beforeValue";
        else if (c === ">") {
          done("");
          return k + 1;
        } else if (c === "/") {
          done("");
          state = "beforeName";
        } else if (!WS.test(c)) {
          done("");
          state = "name";
          nameStart = k;
        }
        break;
      case "beforeValue":
        if (c === '"') {
          state = "dq";
          valueStart = k + 1;
        } else if (c === "'") {
          state = "sq";
          valueStart = k + 1;
        } else if (c === ">") {
          done("");
          return k + 1;
        } else if (!WS.test(c)) {
          state = "unq";
          valueStart = k;
        }
        break;
      case "dq":
      case "sq": {
        const close = s.indexOf(state === "dq" ? '"' : "'", k);
        if (close < 0) return -1;
        done(s.slice(valueStart, close));
        k = close;
        state = "beforeName";
        break;
      }
      case "unq":
        if (WS.test(c) || c === ">") {
          done(s.slice(valueStart, k));
          if (c === ">") return k + 1;
          state = "beforeName";
        }
        break;
    }
  }
  return -1;
}

export interface Comment {
  start: number;
  bodyStart: number;
  bodyEnd: number;
  end: number;
  /** inside script/style/textarea/xmp/title text: bounded by that element, never "hides the rest of the document" */
  inRawText?: boolean;
}

export type TagScan = { tags: Tag[]; comments: Comment[]; closeOf: Map<number, { start: number; end: number }>; unterminatedAt: number };
let tagCache: ({ html: string } & TagScan) | undefined;
registerScanCache(() => (tagCache = undefined), () => tagCache !== undefined);
export function tagsOf(html: string): TagScan {
  if (tagCache?.html === html) return tagCache;
  const tags: Tag[] = [];
  const comments: Comment[] = [];
  const n = html.length;
  let unterminatedAt = -1;
  // next "-->" / "--!>" at or after a position; results are reused so many comments stay linear
  const finder = (needle: string) => {
    let from = -1;
    let found = -1;
    return (at: number): number => {
      if (from >= 0 && from <= at && (found < 0 || found >= at)) return found;
      from = at;
      found = html.indexOf(needle, at);
      return found;
    };
  };
  const dashEnd = finder("-->");
  const bangEnd = finder("--!>");
  const commentOpen = finder("<!--");
  const gtEnd = finder(">");
  let foreign = 0; // inside <svg> / <math>, style/script/title are ordinary elements, not raw text
  // inside <select> the tree drops these start tags, so the tokenizer never switches to raw text for them
  let inSelect = false;
  const selectOutside: boolean[] = []; // a <template> inside a <select> starts fresh: tags are not dropped in it
  // an HTML element that ends svg / math content when it starts inside it (same list as the tree, src/html-tree.ts)
  const breakout = /^(b|big|blockquote|body|br|center|code|dd|div|dl|dt|em|embed|h[1-6]|head|hr|i|img|li|listing|menu|meta|nobr|ol|p|pre|ruby|s|small|span|strong|strike|sub|sup|table|tt|u|ul|var)$/;
  for (let i = html.indexOf("<"); i >= 0 && i < n; ) {
    if (html.startsWith("<!--", i)) {
      // the browser ends a comment at "-->" or "--!>"; "<!-->" and "<!--->" are complete empty comments
      const b = i + 4;
      let bodyEnd: number;
      let end: number;
      if (html[b] === ">") [bodyEnd, end] = [b, b + 1];
      else if (html.startsWith("->", b)) [bodyEnd, end] = [b, b + 2];
      else {
        const d = dashEnd(b);
        const x = bangEnd(b);
        if (d < 0 && x < 0) [bodyEnd, end] = [n, n]; // an unclosed comment runs to the end of the document
        else if (x < 0 || (d >= 0 && d < x)) [bodyEnd, end] = [d, d + 3];
        else [bodyEnd, end] = [x, x + 4];
      }
      comments.push({ start: i, bodyStart: b, bodyEnd, end });
      if (end >= n) break;
      i = html.indexOf("<", end);
      continue;
    }
    // bogus comments, as the browser's tokenizer reads them: "<!x …>" (not a doctype, not CDATA in svg/math),
    // "<?x …>", "</ x …>"; each runs to the next ">", or to the end of the document
    const second = html[i + 1] ?? "";
    const bogus =
      (second === "!" && !/^<!doctype/i.test(html.slice(i, i + 9)) && !(foreign > 0 && html.startsWith("<![CDATA[", i))) ||
      second === "?" ||
      (second === "/" && i + 2 < n && !/[a-zA-Z>]/.test(html[i + 2]));
    if (bogus) {
      const g = gtEnd(i + 2);
      const [bodyEnd, end] = g < 0 ? [n, n] : [g, g + 1];
      comments.push({ start: i, bodyStart: i + 2, bodyEnd, end });
      if (end >= n) break;
      i = html.indexOf("<", end);
      continue;
    }
    const closing = html[i + 1] === "/";
    const first = html[i + (closing ? 2 : 1)] ?? "";
    if (!/[a-zA-Z]/.test(first)) {
      i = html.indexOf("<", i + 1);
      continue;
    }
    const end = readTag(html, i);
    if (end < 0) {
      unterminatedAt = i; // the input ends inside a tag: the browser drops it and everything after it
      break;
    }
    const nameEnd = html.slice(i + (closing ? 2 : 1), end).search(/[\t\n\f\r />]/);
    const name = html.slice(i + (closing ? 2 : 1), i + (closing ? 2 : 1) + nameEnd).toLowerCase();
    tags.push({ start: i, end, name, closing, text: html.slice(i, end) });
    if (!closing && foreign > 0 && breakout.test(name)) foreign = 0;
    if (name === "template" && !closing) {
      selectOutside.push(inSelect);
      inSelect = false;
    } else if (name === "template" && closing && selectOutside.length) inSelect = selectOutside.pop()!;
    else if (name === "select") inSelect = !closing && !inSelect;
    else if (!closing && (name === "input" || name === "keygen" || name === "textarea")) inSelect = false;
    const dropped = inSelect && name !== "script" && name !== "select";
    // everything after <plaintext> is text the reader sees: no more tags or comments
    if (!closing && foreign === 0 && name === "plaintext" && !dropped) break;
    if (name === "svg" || name === "math") {
      if (!closing && html[end - 2] !== "/") foreign++;
      else if (closing && foreign > 0) foreign--;
    }
    if (!closing && foreign === 0 && RAW_TEXT.has(name) && !dropped) {
      tags[tags.length - 1].raw = true;
      const re = new RegExp(`</${name}[\\t\\n\\f\\r />]`, "gi");
      re.lastIndex = end;
      const m = re.exec(html);
      const rawEnd = m ? m.index : n; // raw text runs to its close tag, or to the end of the document
      // Not a comment to the browser, but script/style text is never rendered and old pages wrap it in <!-- -->:
      // a "comment" here still hides text from the reader. It ends at the raw text's end at the latest.
      for (let c = commentOpen(end); c >= 0 && c < rawEnd; ) {
        const b = c + 4;
        const d = dashEnd(b);
        const x = bangEnd(b);
        const stop = [d >= 0 ? [d, d + 3] : null, x >= 0 ? [x, x + 4] : null].filter((v): v is number[] => v !== null && v[0] < rawEnd).sort((u, v) => u[0] - v[0])[0];
        const [bodyEnd, cEnd] = stop ?? [rawEnd, rawEnd];
        comments.push({ start: c, bodyStart: b, bodyEnd, end: cEnd, inRawText: true });
        c = commentOpen(cEnd);
      }
      if (!m) break;
      i = m.index;
      continue;
    }
    i = html.indexOf("<", end);
  }
  // Matching close tag for every opening tag, with a stack per tag name (same pairing as counting depth forward)
  const closeOf = new Map<number, { start: number; end: number }>();
  const open = new Map<string, number[]>();
  for (const t of tags) {
    const stack = open.get(t.name) ?? [];
    open.set(t.name, stack);
    if (!t.closing) {
      if (!t.text.endsWith("/>")) stack.push(t.start);
    } else if (stack.length) closeOf.set(stack.pop()!, { start: t.start, end: t.end });
  }
  tagCache = { html, tags, comments, closeOf, unterminatedAt };
  return tagCache;
}

// Attributes of one opening tag, read the way a browser reads them; the first occurrence of a name wins.
let attrCache: { tag: string; attrs: Map<string, string> } | undefined;
registerScanCache(() => (attrCache = undefined), () => attrCache !== undefined);
function parseAttrs(tag: string): Map<string, string> {
  if (attrCache?.tag === tag) return attrCache.attrs;
  const raw = new Map<string, string>();
  readTag(tag, 0, raw);
  // character references are decoded before a value is read, as the browser does: display&colon;none hides
  const attrs = new Map<string, string>();
  for (const [k, v] of raw) attrs.set(k, decodeAttrValue(v));
  attrCache = { tag, attrs };
  return attrs;
}

export function attr(tag: string, name: string): string | undefined {
  return parseAttrs(tag).get(name.toLowerCase());
}

function elementEnd(html: string, openStart: number, openEnd: number, name: string): number {
  if (VOID.has(name)) return openEnd;
  if (html[openEnd - 2] === "/") return openEnd; // self-closing
  return tagsOf(html).closeOf.get(openStart)?.end ?? Math.min(html.length, openEnd + 2000);
}

// CSS rules as `selector { body }`, same pairs as /([^{}]+)\{([^}]*)\}/g but without that regex's quadratic retries
function cssRules(css: string): { selector: string; body: string }[] {
  const rules: { selector: string; body: string }[] = [];
  let segStart = 0;
  for (let j = 0; j < css.length; j++) {
    const c = css[j];
    if (c === "}") segStart = j + 1;
    else if (c === "{") {
      if (j === segStart) {
        segStart = j + 1;
        continue;
      }
      const k = css.indexOf("}", j + 1);
      if (k < 0) break;
      rules.push({ selector: css.slice(segStart, j), body: css.slice(j + 1, k) });
      segStart = k + 1;
      j = k;
    }
  }
  return rules;
}

// Same result as html.replace(/<[^>]+>/g, " "), without that regex re-scanning to the end for every "<" when no ">" follows
function stripTags(h: string): string {
  let out = "";
  let i = 0;
  for (let lt = h.indexOf("<"); lt >= 0; ) {
    // "<" opens a tag only before a letter, "/", "!" or "?" (WHATWG tag open state); "<|im_start|>" and "a < b" are text
    if (!/[A-Za-z/!?]/.test(h[lt + 1] ?? "")) {
      lt = h.indexOf("<", lt + 1);
      continue;
    }
    const gt = h.indexOf(">", lt + 1);
    if (gt < 0) break; // no ">" anywhere after: nothing further is a tag
    out += h.slice(i, lt) + " ";
    i = gt + 1;
    lt = h.indexOf("<", i);
  }
  return out + h.slice(i);
}

function innerText(html: string): string {
  return stripTags(html).replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/\s+/g, " ").trim();
}

export const hiddenHtml: Detector = {
  id: "hidden-html",
  category: "hidden-html",
  severity: "high",
  description: "HTML content invisible to a human reader but visible to a parser: comments, display:none / zero-size / off-screen / same-colour elements, aria-hidden, meta/title/alt stashes, non-executed <script> blocks.",
  run(ctx) {
    if (ctx.contentType !== "html") return [];
    const html = ctx.input;
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const push = (start: number, end: number, severity: Severity, reason: string, text: string, extra?: Record<string, unknown>) => {
      const key = `${start}:${end}`;
      if (seen.has(key)) return;
      seen.add(key);
      // a fragment in a code fence, inline code or a real quotation is HTML shown to the reader, not hidden from them
      const shown = ctx.fragment === true && (insideClosedFence(html, start, start + 1) || enclosedInQuotes(html, start, start + 1));
      findings.push({
        id: "hidden-html",
        category: "hidden-html",
        severity: shown ? "info" : severity,
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end, 8),
        reason: shown ? `${reason} — shown as code or quoted, likely discussion` : reason,
        decoded: text.slice(0, 300),
        meta: ctx.fragment ? { ...extra, fragment: true, ...(shown ? { shown: true } : {}) } : extra,
      });
    };

    const classify = (text: string, where: string, baseSeverity: Severity, start: number, end: number, extra?: Record<string, unknown>, lines?: string, alt?: string) => {
      const t = text.trim();
      if (!t) return;
      const instr = lines === undefined ? ctx.helpers.matchInstructions(t) : instructionsIn({ text: t, lines, alt });
      const imperative = /^(please\s+)?(ignore|disregard|you|assistant|ai|system|note|important|when|if|do|don'?t|never|always|respond|reply|send|forward|call|run|execute|tell|say|output|include|add)\b/i.test(t) || /\b(you\s+(must|should|are|need|have\s+to)|the\s+(ai|assistant|agent|model)\s+(must|should|will))\b/i.test(t);
      if (instr.length) {
        const top = instr.reduce((a, b) => (rank(b.severity) > rank(a.severity) ? b : a));
        push(start, end, rank(top.severity) >= rank("high") ? "critical" : "high", `${where} contains agent-directed instructions: ${top.reason.toLowerCase()} (${instr.map((i) => i.pattern).join(", ")})`, t, { ...extra, patterns: instr.map((i) => i.pattern) });
      } else if (imperative && t.length > 12) {
        push(start, end, baseSeverity, `${where} contains imperative text a reader never sees`, t, extra);
      } else if (t.length > 80) {
        push(start, end, rank(baseSeverity) >= rank("medium") ? "low" : "info", `${where} contains ${t.length} characters of hidden prose`, t, extra);
      }
    };

    // Nested elements re-read their parent's content, which is quadratic for deep nesting. A top-level region is
    // always read in full, so a nested one inside an already-read region adds no new text; such nested elements are
    // skipped only once one pass has read several times the document's length. No new text is not no new lines:
    // read on its own, a nested element's text starts a line, so `reader` keeps those line starts in the parent's read.
    const readGuard = () => {
      let left = 4 * html.length + 200_000;
      let coveredUntil = -1;
      return (openStart: number, end: number): boolean => {
        const len = end - openStart;
        // skip only an element that lies entirely inside the region already read
        if (end <= coveredUntil && len > left) return false;
        left -= len;
        if (end > coveredUntil) coveredUntil = end;
        return true;
      };
    };
    // `alt`: raw text with its markup removed (a <title> that is never closed holds the rest of the document as text,
    // and an instruction there can be broken by an <a> inside it); matched too, the literal text is what is reported
    const instructionsIn = (r: { text: string; lines: string; alt?: string }) => {
      let found = ctx.helpers.matchInstructions(r.text);
      if (r.alt && r.alt !== r.text) {
        const have = new Set(found.map((m) => m.pattern));
        found = found.concat(ctx.helpers.matchInstructions(r.alt).filter((m) => !have.has(m.pattern)));
      }
      if (r.lines === r.text) return found;
      const have = new Set(found.map((m) => m.pattern));
      // only line breaks differ, so only the patterns anchored at line starts can find more
      return found.concat(ctx.helpers.matchInstructions(r.lines, true).filter((m) => !have.has(m.pattern)));
    };

    // 1. Comments (indexOf instead of a lazy regex, which re-scanned to the end for every unclosed "<!--")
    // comments come from the tag scan, so "<!--" inside raw text or an attribute value is not a comment
    for (const c of tagsOf(html).comments) {
      const text = innerText(html.slice(c.bodyStart, c.bodyEnd));
      // template/build conventions (<!--[if ...]-->, <!-- ko ...-->, <!--#include-->) are noise, unless they carry instructions
      const convention = /^\[if\s|^\s*\/?\s*(ko|googleoff|googleon|htmlmin|#|\$|@)/i.test(html.slice(c.bodyStart, c.bodyEnd).trim());
      const instr = ctx.helpers.matchInstructions(text);
      if (convention && !instr.length) continue;
      const where = c.inRawText ? "Comment inside never-rendered raw text" : c.bodyEnd === html.length ? "Unclosed HTML comment (hides the rest of the document)" : "HTML comment";
      // a comment is never shown, so any instruction in it is critical, whatever the pattern's own severity
      if (instr.length) push(c.start, c.end, "critical", `${where} contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})`, text, { patterns: instr.map((i) => i.pattern) });
      else classify(text, where, "medium", c.start, c.end);
    }

    // 1b. A tag the input ends inside (an unclosed attribute quote): the browser drops it and the rest of the document
    const { tags, closeOf, unterminatedAt } = tagsOf(html);
    // in a fragment a stray "<" in prose ("x < y") is not a broken tag
    if (unterminatedAt >= 0 && !ctx.fragment) {
      const text = innerText(html.slice(unterminatedAt));
      const instr = ctx.helpers.matchInstructions(text);
      const where = "Unterminated tag (the browser drops the rest of the document)";
      // never shown, so any instruction is critical, as in a comment
      if (instr.length) push(unterminatedAt, html.length, "critical", `${where} contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})`, text, { patterns: instr.map((i) => i.pattern) });
      else classify(text, where, "medium", unterminatedAt, html.length);
    }

    // 2. Elements hidden by their own attributes or by a stylesheet rule, then the tree
    // One budget per kind of read: skipping a nested script or style is sound only inside a region read by the same analysis.
    const readScript = readGuard();
    const readStyleText = readGuard();
    // 3. <style> rules that hide classes used in the document (approximate): find selectors with display:none etc. and elements with those classes/ids
    const hiddenSelectors: string[] = [];
    const addRules = (css: string) => {
      // CSS ignores the "<!--" / "-->" tokens that old pages and emails wrap their style blocks in
      // nested <style> / </style> tags are dropped too: a parent <style> inside <svg> holds its nested styles as markup and its
      // text content is what applies; any other "<" (content:"<", a[title="<"]) is ordinary CSS and stays
      for (const rule of cssRules(cssText(css.replace(/<!--|-->|<\/?style\b[^<>]{0,200}>/gi, " ")))) {
        if (hiddenByStyle(rule.body)) {
          for (const sel of rule.selector.split(",")) {
            const s = sel.trim();
            const simple = /^[.#][\w-]+$/.exec(s);
            if (simple) hiddenSelectors.push(simple[0]);
          }
        }
      }
    };
    const readStyles = readGuard(); // nested <style> elements inside <svg> would re-read their parent's rules
    let inTemplate = 0; // a stylesheet inside a <template> is never applied
    for (const t of tags) {
      if (t.name === "template" && !t.raw) inTemplate = Math.max(0, inTemplate + (t.closing ? -1 : 1));
      if (t.closing || t.name !== "style" || inTemplate > 0) continue;
      // style content is raw text up to its close tag, or to the end of the document if it is never closed
      // Unclosed: an HTML <style> is raw text to the end of the document (the tag scan stops there, so it is the last
      // tag); an unclosed <style> inside <svg>/<math> is an ordinary element whose text stops at the next tag.
      const close = closeOf.get(t.start)?.start;
      const next = html.indexOf("<", t.end);
      const cssEnd = close ?? (t === tags[tags.length - 1] || next < 0 ? html.length : next);
      if (!readStyles(t.start, cssEnd)) continue;
      addRules(html.slice(t.end, cssEnd));
    }
    // Outlook applies <style> blocks inside conditional comments (<!--[if mso]>…<![endif]-->), so their rules count too
    for (const c of tagsOf(html).comments) {
      const body = html.slice(c.bodyStart, c.bodyEnd);
      if (!/^\[if\s/i.test(body)) continue;
      const open = /<style\b[^>]{0,1000}>/gi;
      const close = /<\/style/gi;
      let o: RegExpExecArray | null;
      while ((o = open.exec(body))) {
        close.lastIndex = o.index + o[0].length;
        const k = close.exec(body);
        addRules(body.slice(o.index + o[0].length, k ? k.index : body.length));
        if (!k) break;
        open.lastIndex = k.index;
      }
    }
    const selectorIndex = new Map<string, number>();
    hiddenSelectors.forEach((sel, i) => {
      if (!selectorIndex.has(sel)) selectorIndex.set(sel, i);
    });
    // why each opening tag hides its subtree: its own style or attributes first, else the earliest matching stylesheet
    // selector (a map of classes and ids keeps this O(tags), not O(tags x selectors))
    const own = new Map<number, { hidden: HiddenReason; cls: string; sel?: string }>();
    for (const t of tags) {
      if (t.closing) continue;
      const tag = t.text;
      const name = t.name;
      const openStart = t.start;
      const openEnd = t.end;
      if (name === "script" || name === "style" || name === "noscript" || name === "template" || name === "noembed" || name === "noframes" || name === "iframe" || name === "head" || name === "html" || name === "body") {
        if (name === "script") {
          const type = (attr(tag, "type") || "").toLowerCase();
          const end = elementEnd(html, openStart, openEnd, name);
          if (!readScript(openStart, end)) continue;
          // closed: up to "</script>"; unclosed: to the end of the document in HTML (then it is the last tag), or to the next tag inside <svg>
          const next = html.indexOf("<", openEnd);
          const body = html.slice(openEnd, closeOf.get(openStart)?.start ?? (t === tags[tags.length - 1] || next < 0 ? html.length : next));
          if (type && !/javascript|ecmascript|module|^$/.test(type) && !/json/.test(type)) {
            classify(body, `<script type="${type}"> stash (never executed, never rendered)`, "high", openStart, end);
          } else if (!/json/.test(type)) {
            // JavaScript is never rendered: instructions written into it (comments, strings) are hidden from the reader
            const instr = ctx.helpers.matchInstructions(body);
            // critical like style text: a reader never sees it, whatever the pattern's own severity
            if (instr.length) push(openStart, end, "critical", `<script> block contains agent-directed instructions that are never rendered (${instr.map((i) => i.pattern).join(", ")})`, body);
          } else if (/json/.test(type)) {
            const instr = ctx.helpers.matchInstructions(body);
            if (instr.length) push(openStart, end, "high", `JSON <script> block contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})`, body);
          }
        } else if (name === "style") {
          // style text is never rendered: instructions written into it are hidden from the reader
          // unclosed: raw to the end of the document in HTML (then it is the last tag); inside <svg> its text stops at the next tag
          const next = html.indexOf("<", openEnd);
          const bodyEnd = closeOf.get(openStart)?.start ?? (t === tags[tags.length - 1] || next < 0 ? html.length : next);
          const end = closeOf.get(openStart)?.end ?? bodyEnd;
          if (!readStyleText(openStart, end)) continue; // own budget: nested svg styles must not use up the one for hidden elements
          const body = html.slice(openEnd, bodyEnd);
          const instr = ctx.helpers.matchInstructions(body);
          if (instr.length) push(openStart, end, "critical", `<style> block contains agent-directed instructions that are never rendered (${instr.map((i) => i.pattern).join(", ")})`, body);
        }
        // template, noscript, noembed, noframes and iframe content is read from the tree below
        continue;
      }

      // meta / title / img alt
      if (name === "meta") {
        const content = attr(tag, "content");
        const key = attr(tag, "name") || attr(tag, "property") || attr(tag, "http-equiv") || "meta";
        if (content) classify(content, `<meta ${key}>`, "medium", openStart, openEnd, { field: key });
        continue;
      }
      if (name === "title") continue; // read from the tree below
      // a hidden form field never shows its value; a token or an id is normal, a sentence is a carrier
      if (name === "input" && /^\s*hidden\s*$/i.test(attr(tag, "type") ?? "")) {
        const value = innerText(attr(tag, "value") ?? "");
        if (proseWords(value) >= 5) {
          const instr = ctx.helpers.matchInstructions(value);
          push(openStart, openEnd, instr.length ? "critical" : "high", `Hidden form field value holds ${proseWords(value)} words of prose${instr.length ? ` with agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})` : ""}`, value, { field: attr(tag, "name") ?? "", patterns: instr.map((i) => i.pattern) });
        }
        continue;
      }
      const alt = attr(tag, "alt") ?? attr(tag, "title") ?? attr(tag, "aria-label") ?? attr(tag, "placeholder");
      if (alt && alt.length > 20) classify(alt, `${name} alt/title/aria-label attribute`, "medium", openStart, openEnd);
      const dataAttrs = tag.match(/\bdata-[\w-]+\s*=\s*("[^"]{30,}"|'[^']{30,}')/gi);
      if (dataAttrs) for (const d of dataAttrs) classify(d.replace(/^[^=]+=\s*["']|["']$/g, ""), `${name} data attribute`, "low", openStart, openEnd);

      let hidden: HiddenReason | null = null;
      const style = attr(tag, "style");
      if (style) hidden = hiddenByStyle(style);
      // read from the parsed attributes, never from the raw tag text (a value or a decoy name must not count)
      const cls = attr(tag, "class") ?? "";
      if (!hidden && parseAttrs(tag).has("hidden")) hidden = { reason: "hidden attribute", severity: "high" };
      if (!hidden && /^\s*true/i.test(attr(tag, "aria-hidden") ?? "")) hidden = { reason: 'aria-hidden="true"', severity: "medium" };
      if (!hidden && /\b(sr-only|visually-hidden|screen-reader-only|hidden|d-none|invisible|offscreen)\b/i.test(cls)) hidden = { reason: "hidden via utility class", severity: "medium" };
      if (!hidden && (name === "font" || name === "span") && /^\s*0/.test(attr(tag, "size") ?? "")) hidden = { reason: "font size 0", severity: "high" };
      if (!hidden && selectorIndex.size) {
        let best = -1;
        for (const c of cls.split(/\s+/)) {
          const at = c ? selectorIndex.get("." + c) : undefined;
          if (at !== undefined && (best < 0 || at < best)) best = at;
        }
        const id = attr(tag, "id");
        const idAt = id ? selectorIndex.get("#" + id) : undefined;
        if (idAt !== undefined && (best < 0 || idAt < best)) best = idAt;
        if (best >= 0) {
          own.set(openStart, { hidden: { reason: `stylesheet rule ${hiddenSelectors[best]}`, severity: "medium" }, cls, sel: hiddenSelectors[best] });
          continue;
        }
      }
      if (hidden) own.set(openStart, { hidden, cls });
    }

    // Every text run belongs to the outermost element that hides it: one finding per such element, rated on all its
    // text, with the hidden elements nested in it listed. Each run is read once.
    const tree = buildTree(html, tagsOf(html), (t) => own.get(t.start)?.hidden.reason);
    const groups = new Map<number, number[]>();
    const order: number[] = [];
    let shownLetters = 0; // letters a reader may see: not hidden in a way no theme or screen undoes, and not code
    tree.runs.forEach((r, i) => {
      const el = r.el >= 0 ? tree.elements[r.el] : undefined;
      if (el && (el.name === "script" || el.name === "style")) return; // code, rated by its own rules above
      if (r.hider < 0) {
        shownLetters += letters(html.slice(r.start, r.end));
        return;
      }
      let g = groups.get(r.hider);
      if (!g) {
        groups.set(r.hider, (g = []));
        order.push(r.hider);
      }
      g.push(i);
    });
    const nested = new Map<number, { reason: string }[]>();
    tree.elements.forEach((e, i) => {
      if (e.hider < 0 || e.hider === i || !e.reason || !own.has(e.start)) return;
      let list = nested.get(e.hider);
      if (!list) nested.set(e.hider, (list = []));
      if (list.length < 20) list.push({ reason: e.reason });
    });
    // the text of a group: runs joined by spaces, and `lines`: the same with a line break where a line starts in the
    // rendered text, so a line-anchored pattern ("assistant:" alone in a block) matches as it would read alone
    const textOf = (runs: number[]) => {
      let text = "";
      let lines = "";
      let alt = "";
      let raw = false;
      runs.forEach((ri, k) => {
        const r = tree.runs[ri];
        const piece = decodeAttrValue(html.slice(r.start, r.end), false).replace(/\0/g, "\uFFFD");
        const inRaw = r.el >= 0 && RAW_TEXT.has(tree.elements[r.el].name);
        raw ||= inRaw;
        alt += (k ? " " : "") + (inRaw ? stripTags(piece) : piece);
        text += (k ? " " : "") + piece;
        lines += (k ? (r.breakBefore || runs[k - 1] !== ri - 1 ? "\n" : " ") : "") + piece;
      });
      return { text: text.replace(/\s+/g, " ").trim(), lines: lines.replace(/[^\S\n]+/g, " ").replace(/ *\n[\s]*/g, "\n").trim(), alt: raw ? alt.replace(/\s+/g, " ").trim() : undefined };
    };
    // top-level elements hidden in a way no theme or screen size undoes, for the all-hidden rule
    const plainHidden: { start: number; end: number; letters: number }[] = [];
    for (const h of order) {
      const e = tree.elements[h];
      const r = textOf(groups.get(h)!);
      if (!r.text) continue;
      const { start, end } = e;
      const nest = nested.get(h);
      const extra = nest ? { nested: nest } : {};
      const o = own.get(e.start);
      if (!o) {
        // not rendered: template, noscript, noembed, noframes, iframe, title
        classify(r.text, e.name === "title" ? "<title>" : `<${e.name}> content (not rendered)`, "medium", start, end, nest ? extra : undefined, r.lines, r.alt);
        continue;
      }
      const text = r.text;
      const instr = instructionsIn(r);
      if (o.sel) {
        const sel = o.sel;
        if (instr.length) push(start, end, "critical", `Element hidden by stylesheet rule ${sel} contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})`, text, { hiddenBy: sel, patterns: instr.map((i) => i.pattern), ...extra });
        else if (/\b(preheader|preview-text|email-preview)\b/.test(sel)) push(start, end, "info", `Email preheader (hidden by convention): “${text.slice(0, 80)}”`, text, { hiddenBy: sel, ...extra });
        else if (text.length >= 20) push(start, end, text.length >= 300 ? "medium" : "low", `Element hidden by stylesheet rule ${sel} with ${text.length} characters of text`, text, { hiddenBy: sel, ...extra });
        continue;
      }
      const { hidden, cls } = o;
      shownLetters += UNAMBIGUOUS.has(hidden.reason) ? 0 : letters(text);
      if (UNAMBIGUOUS.has(hidden.reason)) plainHidden.push({ start, end, letters: letters(text) });
      if (instr.length) {
        push(start, end, "critical", `Hidden element (${hidden.reason}) contains agent-directed instructions: ${instr[0].reason.toLowerCase()} (${instr.map((i) => i.pattern).join(", ")})`, text, { hiddenBy: hidden.reason, patterns: instr.map((i) => i.pattern), ...extra });
      } else if (/\b(preheader|preview-text|email-preview)\b/i.test(cls)) {
        push(start, end, "info", `Email preheader (hidden by convention): “${text.slice(0, 80)}”`, text, { hiddenBy: hidden.reason, ...extra });
      } else if (text.length >= 20) {
        push(start, end, text.length >= 300 ? hidden.severity : "low", `Hidden element (${hidden.reason}) with ${text.length} characters of text a human does not see`, text, { hiddenBy: hidden.reason, ...extra });
      } else {
        push(start, end, "info", `Hidden element (${hidden.reason}): “${text}”`, text, { hiddenBy: hidden.reason, ...extra });
      }
    }

    // 2b. All-hidden message: the hidden prose is the message and almost nothing is left to see. An image counts
    // as something to see (an image-only newsletter keeps its preheader hidden).
    const hiddenLetters = plainHidden.reduce((n, h) => n + h.letters, 0);
    const imgSrc = new Set(tags.filter((t) => !t.closing && t.name === "img" && attr(t.text, "src")).map((t) => t.start));
    if (hiddenLetters >= 40 && shownLetters < 20 && !tree.elements.some((e) => e.name === "img" && e.hider < 0 && imgSrc.has(e.start))) {
      const top = plainHidden.reduce((a, h) => (h.letters > a.letters ? h : a));
      const f = findings.find((x) => x.start === top.start && x.end === top.end);
      if (f && !f.meta?.shown && f.severity !== "critical") {
        f.severity = "critical";
        f.reason = `Whole message hidden: ${hiddenLetters} letters of hidden prose, under 20 visible. ${f.reason}`;
      }
    }

    return findings;
  },
};

// hiding that no theme, breakpoint or screen reader undoes; colour and utility classes wait for the tree reader
const UNAMBIGUOUS = new Set(["display:none", "visibility:hidden", "hidden attribute", "font-size:0", "font size 0", "opacity:0", "positioned off-screen"]);
const letters = (s: string) => (s.match(/[\p{L}\p{N}]/gu) || []).length;
// words: tokens of letters and punctuation with two or more letters; "a8f9c2e1" is a token, not a word. One character
// class per test, so a long run cannot make the regex backtrack.
const proseWords = (s: string) => s.split(/\s+/).filter((w) => /^[\p{L}\p{P}]+$/u.test(w) && (w.match(/\p{L}/gu) || []).length >= 2).length;

function rank(s: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}
