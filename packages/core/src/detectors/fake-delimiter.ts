import type { Detector, Finding, Severity } from "../types";
import { enclosedInQuotes } from "../patterns";
import { insideCode, ROLE_TAG, TOKEN } from "./role-spoofing";
import { registerScanCache } from "../util/caches";

// content that claims one context ended and another began, so the agent
// believes what follows comes from its user or system. Structure only: what follows a delimiter is never judged.
const CONTEXT = String.raw`(?:EMAILS?|USER(?:[ \t]+(?:INPUT|RESPONSE|MESSAGE|QUERY|PROMPT))?|SYSTEM(?:[ \t]+PROMPT)?|CONTEXT|CONVERSATION|TOOL[ \t]+(?:OUTPUT|RESULT|CALL)|INSTRUCTIONS?|ASSISTANT|DOCUMENT|DATA|INPUT|OUTPUT)`;
const FENCE = String.raw`[-=*#_~<>\[\]|]{2,}`;
// "----- END OF EMAILS -----", "=== USER INPUT ===": a fence, then either a BEGIN/END word or a closing fence, so a
// markdown heading ("## Context") is not a delimiter
const LINE = new RegExp(String.raw`^[ \t]*${FENCE}[ \t]*(?:((?:BEGIN|END|START|STOP)[ \t]+(?:OF[ \t]+)?)(?:THE[ \t]+)?${CONTEXT}[ \t]*(?:${FENCE})?|(?:THE[ \t]+)?${CONTEXT}[ \t]*${FENCE})[ \t]*$`, "gim");
const BRACKET = new RegExp(String.raw`\[[ \t]*(?:END|BEGIN|START)[ \t]+(?:OF[ \t]+)?(?:THE[ \t]+)?${CONTEXT}[ \t]*\]`, "gi");
const INLINE = /\b(?:end|start)[ \t]+of[ \t]+turn\b/gi;
const CONTEXT_TAG = /<[ \t]*(\/?)[ \t]*(context|email|emails|document|untrusted|instructions|data|input|user_input)\b[^<>]{0,200}>/gi;
// phrasings attack runs 1-3 used mid-line. A fence here starts a run of fence
// characters (the lookbehind), so a long dash run is tried once, not from every dash.
const F3 = String.raw`(?<![-=*#_~<>|])[-=*#_~<>|]{3,}`;
const PHRASES = [
  // "----EMAIL ENDS here!"
  new RegExp(String.raw`${F3}[ \t]*(?:THE[ \t]+)?(?:${CONTEXT}|PROMPT|MESSAGE)[ \t]+(?:ENDS?|ENDED|IS[ \t]+OVER|FINISHED)\b`, "gi"),
  // "--- AGENT-ONLY INSTRUCTIONS FROM Legal Counsel:"
  new RegExp(String.raw`${F3}[ \t]*(?:(?:AGENT|AI|ASSISTANT|MODEL|LLM)[- \t]+ONLY\b|(?:\w+[- \t]+){0,2}INSTRUCTIONS[ \t]+(?:FROM|FOR)\b[^\n:]{0,60}:)`, "gi"),
  // "end of prompt]"
  /\b(?:end|begin|start)[ \t]+of[ \t]+(?:the[ \t]+)?(?:prompt|message|input|instructions?)[ \t]*\]/gi,
  // "=====END OF DOCUMENT=====" anywhere on a line; a whole-line one is LINE's and is dropped as a duplicate below
  new RegExp(String.raw`${F3}[ \t]*(?:BEGIN|END|START|STOP)[ \t]+(?:OF[ \t]+)?(?:THE[ \t]+)?${CONTEXT}\b`, "gi"),
];
// "---End Message... ---New Message": a lone "End of message" is normal mail, so only the pair counts
const END_MESSAGE = new RegExp(String.raw`${F3}[ \t]*END[ \t]+(?:OF[ \t]+)?MESSAGE\b`, "gi");
const NEW_MESSAGE = new RegExp(String.raw`${F3}[ \t]*(?:NEW|NEXT|BEGIN)[ \t]+MESSAGE\b`, "gi");
// structure typed as text: "\n---\nSYSTEM_FOOTER:", "\nUSER:"
const ESCAPED = /\\n[ \t]*(?:[-=*#]{3,}[ \t]*\\n(?:[ \t]*[A-Z][A-Z_]*[ \t]*:)?|(?:SYSTEM|USER|ASSISTANT)[A-Z_]*[ \t]*:)/g;
// a code fence opens a block only when its line holds nothing but the fence and a language name; "``` =====END..."
// is text, so it neither quotes a delimiter nor closes one
const REAL_FENCE = /^[ \t]*```[\w+#.-]*[ \t]*$/gm;
let fenceCache: { s: string; at: number[] } | null = null;
registerScanCache(() => (fenceCache = null), () => fenceCache !== null);
function insideRealFence(s: string, start: number, end: number): boolean {
  if (fenceCache?.s !== s) {
    const at: number[] = [];
    REAL_FENCE.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = REAL_FENCE.exec(s)); ) at.push(m.index);
    fenceCache = { s, at };
  }
  const at = fenceCache.at;
  let lo = 0;
  let hi = at.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (at[mid] < start) lo = mid + 1;
    else hi = mid;
  }
  return lo % 2 === 1 && lo < at.length && at[lo] >= end;
}
const STEPS: Severity[] = ["info", "low", "medium", "high", "critical"];

interface Marker {
  start: number;
  end: number;
  text: string;
  inline: boolean;
  /** what makes two markers different; defaults to the marker's words */
  key?: string;
}

export const fakeDelimiter: Detector = {
  id: "fake-delimiter",
  category: "fake-delimiter",
  severity: "high",
  description: "Fake context delimiters: lines, brackets or orphan closing tags that claim the untrusted part ended and another began.",
  run(ctx) {
    const s = ctx.input;
    const markers: Marker[] = [];
    for (const re of [LINE, BRACKET, INLINE]) {
      re.lastIndex = 0;
      for (let m: RegExpExecArray | null; (m = re.exec(s)); ) {
        const lead = m[0].length - m[0].trimStart().length;
        markers.push({ start: m.index + lead, end: m.index + m[0].trimEnd().length, text: m[0].trim(), inline: re === INLINE });
      }
    }
    const extra: Marker[] = [];
    for (const [re, key] of [...PHRASES.map((r) => [r, undefined] as const), [ESCAPED, "ESCAPED"] as const]) {
      re.lastIndex = 0;
      for (let m: RegExpExecArray | null; (m = re.exec(s)); ) extra.push({ start: m.index, end: m.index + m[0].trimEnd().length, text: m[0].trim(), inline: false, key });
    }
    // a phrasing inside a marker already found (a whole delimiter line) or inside an earlier phrasing is the same marker
    if (extra.length) {
      const all = [...markers.map((m) => ({ m, extra: false })), ...extra.map((m) => ({ m, extra: true }))].sort((a, b) => a.m.start - b.m.start || Number(a.extra) - Number(b.extra));
      markers.length = 0;
      let reach = -1;
      for (const { m, extra: x } of all) {
        if (x && m.start < reach) continue;
        markers.push(m);
        reach = Math.max(reach, m.end);
      }
    }
    END_MESSAGE.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = END_MESSAGE.exec(s)); ) {
      // look only 400 characters ahead (plus room for the marker), so many lone END lines stay linear
      const from = m.index + m[0].length;
      NEW_MESSAGE.lastIndex = 0;
      const n = NEW_MESSAGE.exec(s.slice(from, from + 480));
      if (!n || n.index > 400) continue;
      markers.push({ start: m.index, end: from, text: m[0].trim(), inline: false });
      markers.push({ start: from + n.index, end: from + n.index + n[0].length, text: n[0].trim(), inline: false });
      END_MESSAGE.lastIndex = from + n.index + n[0].length;
    }
    // a closing context tag with no opening tag before it ends a context that never began
    const open = new Map<string, number>();
    CONTEXT_TAG.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = CONTEXT_TAG.exec(s)); ) {
      const name = m[2].toLowerCase();
      if (m[1] !== "/") open.set(name, (open.get(name) ?? 0) + 1);
      else if (open.get(name)) open.set(name, open.get(name)! - 1);
      else markers.push({ start: m.index, end: m.index + m[0].length, text: m[0], inline: false });
    }
    if (!markers.length) return [];
    markers.sort((a, b) => a.start - b.start);

    // inline turn words count only next to another delimiter; two different delimiters, or one next to a role marker,
    // are the turn shape attacks use
    const distinct = new Set(markers.filter((m) => !m.inline).map((m) => m.key ?? m.text.toUpperCase().replace(/[^A-Z]+/g, " ").trim()));
    const nearRole = (m: Marker) => {
      const w = s.slice(Math.max(0, m.start - 120), m.end + 120);
      TOKEN.lastIndex = 0;
      ROLE_TAG.lastIndex = 0;
      return TOKEN.test(w) || ROLE_TAG.test(w);
    };
    const findings: Finding[] = [];
    for (const m of markers) {
      if (m.inline && distinct.size === 0) continue;
      let severity: Severity = distinct.size >= 2 || (m.inline && distinct.size >= 1) || nearRole(m) ? "high" : "medium";
      let note = "";
      if (insideRealFence(s, m.start, m.end) || enclosedInQuotes(s, m.start, m.end) || insideCode(s, m.start)) {
        severity = "info";
        note = " — quoted or inside code, likely discussion";
      }
      findings.push({
        id: "fake-delimiter",
        category: "fake-delimiter",
        severity,
        start: m.start,
        end: m.end,
        excerpt: ctx.helpers.excerpt(m.start, m.end),
        reason: `Fake context delimiter: ${m.text.slice(0, 60)}${note}`,
        meta: { marker: m.text.slice(0, 60), discussion: note !== "" },
      });
      if (findings.length >= 200) break; // the score reads the top 12 of a category
    }
    return findings.sort((a, b) => STEPS.indexOf(b.severity) - STEPS.indexOf(a.severity) || a.start - b.start);
  },
};
