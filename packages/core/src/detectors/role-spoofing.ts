import type { Detector, Finding, Severity } from "../types";
import { CUE_BEFORE, enclosedInQuotes, insideClosedFence } from "../patterns";
import { registerScanCache } from "../util/caches";

// content that pretends to be part of a chat conversation. Structure only:
// what the fake turn asks for is never judged here.
export const TOKEN = /<\|[^|<>\n]{1,40}\|>|\[\/?INST\]|<<\/?SYS>>|<\/?(?:start|end)_of_turn>/gi;
// "|end tool output|": pipes around a start/end word and a role or turn word, outside markdown table rows
const BARE = /(?<![|\w])\|[ \t]*(?:end|start|begin)[ \t]+(?:of[ \t]+)?(?:tool|user|system|assistant|model|turn|prompt|output|input|context|conversation)[^|\n]{0,30}\|(?!\|)/gi;
export const ROLE_TAG = /<[ \t]*(\/?)[ \t]*(user|assistant|system|tool|tool_output|tool_result|tool_call|function_results|human|model|developer)[ \t]*>/gi;
// ">>>>admin<<<<:", "[[system]]:": a label wrapped in a decoration run, then a colon.
// The lookbehind starts a match only at the start of a decoration run, so a long run is tried once.
const DECORATED = /(?<![<>[\]=*#])(?:[<>]{2,}|\[{2,}|={2,}|\*{3,}|#{2,})[ \t]*([\p{L}\p{N}][\p{L}\p{N} ._-]{1,19}?)[ \t]*(?:[<>]{2,}|\]{2,}|={2,}|\*{3,}|#{2,})[ \t]*:/gu;
// "gm: …" / "user: …" lines; header labels are never speakers
const LABEL_LINE = /^[ \t>]*([A-Za-z][\w-]{0,15})[ \t]*:([^\n]*)/gm;
const SPEAKER_ROLE = /^(?:user|human|assistant|system|admin|ai|bot|agent|model|gm)$/i;
const HEADER_LABEL = /^(?:subject|from|to|date|cc|bcc|sent|re|fw|fwd|note|ps|tel|phone|fax|email|e-mail|mail|address|web|url|http|https)$/i;
const UNTERMINATED_ROLES = new Set(["user", "assistant", "system", "human", "model", "developer"]);
// a tag alone on its line: "<note>", "</note>"
const LONE_TAG = /^[ \t]*<(\/?)([a-z][\w-]{1,30})>[ \t]*$/gim;
export const HTML_ELEMENTS = new Set("a abbr address area article aside audio b base bdi bdo blockquote body br button canvas caption center cite code col colgroup data datalist dd del details dfn dialog div dl dt em embed fieldset figcaption figure font footer form h1 h2 h3 h4 h5 h6 head header hr html i iframe img input ins kbd label legend li link main map mark menu meta meter nav noscript object ol optgroup option output p param picture pre progress q rp rt ruby s samp script search section select slot small source span strong style sub summary sup svg table tbody td template textarea tfoot th thead time title tr track u ul var video wbr xml".split(" "));
const STEPS: Severity[] = ["info", "low", "medium", "high", "critical"];
const rank = (s: Severity) => STEPS.indexOf(s);

interface Marker {
  start: number;
  end: number;
  text: string;
  kind: "token" | "tag" | "wrapper";
  severity: Severity;
  reason: string;
}

export const roleSpoofing: Detector = {
  id: "role-spoofing",
  category: "role-spoofing",
  severity: "critical",
  description: "Fake conversation structure: chat-template turn tokens and pseudo-XML role tags inside content.",
  run(ctx) {
    const s = ctx.input;
    const markers: Marker[] = [];
    for (const re of [TOKEN, BARE]) {
      re.lastIndex = 0;
      for (let m: RegExpExecArray | null; (m = re.exec(s)); ) {
        if (re === BARE && isTableRow(s, m.index)) continue;
        markers.push({ start: m.index, end: m.index + m[0].length, text: m[0], kind: "token", severity: "high", reason: "Chat-template turn token" });
      }
    }
    DECORATED.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = DECORATED.exec(s)); ) markers.push({ start: m.index, end: m.index + m[0].length, text: m[0], kind: "token", severity: "high", reason: "Decorated role label" });
    const tags: { start: number; end: number; text: string; closing: boolean; role: string }[] = [];
    ROLE_TAG.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = ROLE_TAG.exec(s)); ) tags.push({ start: m.index, end: m.index + m[0].length, text: m[0], closing: m[1] === "/", role: m[2].toLowerCase() });
    // a pair is the next closing tag of the same role; one pass with a pending opener per role keeps it linear
    const open = new Map<string, number>();
    const pairEnd = new Map<number, number>();
    tags.forEach((t, i) => {
      if (!t.closing) open.set(t.role, i);
      else if (open.has(t.role)) {
        pairEnd.set(open.get(t.role)!, i);
        open.delete(t.role);
      }
    });
    const switchOpeners = new Set<number>();
    tags.forEach((t, i) => {
      let severity: Severity = "low";
      let reason = "Pseudo-XML role tag";
      const close = pairEnd.get(i);
      if (!t.closing && close !== undefined) {
        const words = prose(s.slice(t.end, tags[close].start));
        if (words >= 8) [severity, reason] = ["critical", "Role tag around a long fake turn"];
        else if (words >= 3) [severity, reason] = ["high", "Role tag around a fake turn"];
      }
      // a role switch: a closing role tag, then an opening one of another role, with a turn after it
      const next = tags[i + 1];
      if (t.closing && next && !next.closing && next.role !== t.role && /^\s{0,40}$/.test(s.slice(t.end, next.start))) {
        const nextClose = pairEnd.get(i + 1);
        if (prose(s.slice(next.end, nextClose !== undefined ? tags[nextClose].start : Math.min(s.length, next.end + 500))) >= 3) {
          [severity, reason] = ["critical", `Role switch ${t.text}${next.text}`];
          switchOpeners.add(i + 1);
        }
      }
      if (switchOpeners.has(i)) [severity, reason] = ["critical", "Role switch"];
      // an opening role tag that is never closed, at a line start or right after another tag: rated by the turn after it
      if (!t.closing && close === undefined && UNTERMINATED_ROLES.has(t.role) && (atLineStart(s, t.start) || /[>\]]\s*$/.test(lineBefore(s, t.start)))) {
        const stop = Math.min(next ? next.start : s.length, t.end + 500);
        const after = s.slice(t.end, stop);
        const lt = after.indexOf("<");
        const words = prose(lt < 0 ? after : after.slice(0, lt));
        if (words >= 8) [severity, reason] = ["critical", "Unclosed role tag before a long fake turn"];
        else if (words >= 3) [severity, reason] = ["high", "Unclosed role tag before a fake turn"];
      }
      markers.push({ start: t.start, end: t.end, text: t.text, kind: "tag", severity, reason });
    });
    // a visible transcript: a user or human turn line and an assistant turn line, each followed by a sentence
    const userTurn = /^[ \t>]*(?:user|human)[ \t]*:[ \t]*\S[^\n]*?(?:\s\S+){2,}/im.exec(s);
    const assistantTurn = /^[ \t>]*assistant[ \t]*:[ \t]*\S[^\n]*?(?:\s\S+){2,}/im.exec(s);
    if (userTurn && assistantTurn) {
      const first = userTurn.index < assistantTurn.index ? userTurn : assistantTurn;
      markers.push({ start: first.index, end: first.index + first[0].length, text: first[0].trim().slice(0, 40), kind: "tag", severity: "medium", reason: "User and assistant turn lines" });
    }
    // a chat log: speakers that alternate, one of them a role; the user/assistant transcript rule already covers its own
    if (!(userTurn && assistantTurn)) {
      const speakers: { label: string; at: number; end: number }[] = [];
      LABEL_LINE.lastIndex = 0;
      for (let m: RegExpExecArray | null; (m = LABEL_LINE.exec(s)); ) {
        if (HEADER_LABEL.test(m[1]) || m[2].trim().split(/\s+/).length < 3) continue;
        speakers.push({ label: m[1].toLowerCase(), at: m.index, end: m.index + m[0].length });
      }
      const count = new Map<string, number>();
      let switches = 0;
      speakers.forEach((x, i) => {
        count.set(x.label, (count.get(x.label) ?? 0) + 1);
        if (i > 0 && speakers[i - 1].label !== x.label) switches++;
      });
      if (speakers.length >= 3 && count.size >= 2 && switches >= 2 && [...count.values()].some((n) => n >= 2) && [...count.keys()].some((k) => SPEAKER_ROLE.test(k))) {
        const first = speakers[0];
        markers.push({ start: first.at + (s.slice(first.at, first.end).length - s.slice(first.at, first.end).trimStart().length), end: first.end, text: s.slice(first.at, first.end).trim().slice(0, 40), kind: "tag", severity: "medium", reason: "Chat-log speaker lines" });
      }
    }
    // a made-up tag alone on its line around prose: the tag name is never judged
    // one finding per tag name: five <rule> blocks are one structure, not five
    const pending = new Map<string, number>();
    const wrapped = new Set<string>();
    LONE_TAG.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = LONE_TAG.exec(s)); ) {
      const name = m[2].toLowerCase();
      if (HTML_ELEMENTS.has(name) || ROLE_NAMES.has(name)) continue;
      const lead = m[0].length - m[0].trimStart().length;
      if (m[1] !== "/") {
        pending.set(name, m.index + m[0].length);
        continue;
      }
      const from = pending.get(name);
      if (from === undefined || wrapped.has(name)) continue;
      pending.delete(name);
      const startTag = s.lastIndexOf("<", from);
      if (prose(s.slice(from, m.index)) >= 3 && wrapped.add(name)) markers.push({ start: startTag, end: m.index + lead + name.length + 3, text: `<${name}>`, kind: "wrapper", severity: "medium", reason: "Made-up tag around a block of text" });
    }
    if (!markers.length) return [];
    markers.sort((a, b) => a.start - b.start);

    // next to another marker (only whitespace between): the turn shape attacks use; a tag next to a token is critical
    const adjacent = markers.map(() => false);
    for (let i = 0; i + 1 < markers.length; i++) {
      if (/^\s{0,40}$/.test(s.slice(markers[i].end, markers[i + 1].start))) {
        adjacent[i] = adjacent[i + 1] = true;
        if (markers[i].kind !== markers[i + 1].kind) markers[i].severity = markers[i + 1].severity = "critical";
      }
    }
    // two distinct structural markers in one document, or a pair of tokens: critical
    const strong = new Set(markers.filter((m) => rank(m.severity) >= rank("high")).map((m) => m.text.toLowerCase().replace(/\s+/g, "")));
    if (strong.size >= 2) for (const m of markers) if (m.severity === "high") m.severity = "critical";

    const findings: Finding[] = [];
    // at most MAX findings are written out (the strongest, then the first); the score reads only the top 12 of a
    // category, so the rest changes nothing but the size of the result and the time to build it
    const keep = markers.length > MAX ? new Set([...markers.keys()].sort((a, b) => rank(markers[b].severity) - rank(markers[a].severity) || a - b).slice(0, MAX)) : undefined;
    for (let i = 0; i < markers.length; i++) {
      const m = markers[i];
      if (keep && !keep.has(i)) continue;
      let severity = m.severity;
      let note = "";
      if (insideClosedFence(s, m.start, m.end) || enclosedInQuotes(s, m.start, m.end) || insideCode(s, m.start)) {
        severity = "info";
        note = " — quoted or inside code, likely discussion";
      } else if (!adjacent[i] && !atLineStart(s, m.start) && CUE_BEFORE.test(s.slice(Math.max(0, m.start - 200), m.start))) {
        // a cue word ("like", "example") is attacker-controlled: one step down for an inline marker, never below medium
        severity = STEPS[Math.max(rank("medium"), rank(severity) - 1)];
        if (rank(m.severity) < rank("medium")) severity = m.severity;
        note = " — inline after a discussion cue";
      }
      findings.push({
        id: "role-spoofing",
        category: "role-spoofing",
        severity,
        start: m.start,
        end: m.end,
        excerpt: ctx.helpers.excerpt(m.start, m.end),
        reason: `${m.reason}: ${m.text}${note}`,
        meta: { kind: m.kind, marker: m.text, discussion: note !== "" },
      });
    }
    if (keep) {
      const rest = markers.filter((_, i) => !keep.has(i));
      const top = rest.reduce((a, m) => (rank(m.severity) > rank(a) ? m.severity : a), "info" as Severity);
      findings.push({ id: "role-spoofing", category: "role-spoofing", severity: top, start: rest[0].start, end: rest[rest.length - 1].end, excerpt: ctx.helpers.excerpt(rest[0].start, rest[0].end), reason: `${rest.length} more role markers, not listed one by one`, meta: { more: rest.length } });
    }
    return findings;
  },
};

const MAX = 200;
const ROLE_NAMES = new Set(["user", "assistant", "system", "tool", "tool_output", "tool_result", "tool_call", "function_results", "human", "model", "developer"]);

/** Words of prose in a fake turn; nested elements mean a data export, not a turn. */
function prose(inner: string): number {
  if (/<[A-Za-z/]/.test(inner)) return 0;
  return (inner.match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) || []).length;
}

// Line context is read within 200 chars on each side, so many markers on one long line stay linear.
function lineBefore(s: string, at: number): string {
  const w = s.slice(Math.max(0, at - 200), at);
  return w.slice(w.lastIndexOf("\n") + 1);
}

/** Only whitespace or reply-quote marks before it on its line. */
function atLineStart(s: string, at: number): boolean {
  return at === 0 || /^[\s>]*$/.test(lineBefore(s, at)) && (at < 200 || s.slice(at - 200, at).includes("\n"));
}

function isTableRow(s: string, at: number): boolean {
  const after = s.slice(at, at + 200);
  const nl = after.indexOf("\n");
  const line = lineBefore(s, at) + (nl < 0 ? after : after.slice(0, nl));
  return /^\s*\|/.test(line) && (line.match(/\|/g) || []).length >= 3;
}

// Positions of <code>, <pre> and <kbd> tags in the last text asked about, found once
let codeCache: { s: string; at: number[]; opens: boolean[] } | undefined;
registerScanCache(() => (codeCache = undefined), () => codeCache !== undefined);
/** Inside an HTML code, pre or kbd element: an example shown to the reader. */
export function insideCode(s: string, at: number): boolean {
  if (codeCache?.s !== s) {
    const pos: number[] = [];
    const opens: boolean[] = [];
    const re = /<(\/?)(?:code|pre|kbd)\b/gi;
    for (let m: RegExpExecArray | null; (m = re.exec(s)); ) {
      pos.push(m.index);
      opens.push(m[1] !== "/");
    }
    codeCache = { s, at: pos, opens };
  }
  let lo = 0;
  let hi = codeCache.at.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (codeCache.at[mid] < at) lo = mid + 1;
    else hi = mid;
  }
  return lo > 0 && codeCache.opens[lo - 1];
}
