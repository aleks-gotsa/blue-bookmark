import type { Detector, Finding, Severity } from "../types";
import { looksLikeDiscussion } from "../patterns";
import { htmlToTextMap } from "../util/text";

const DOWNGRADE: Record<Severity, Severity> = { critical: "low", high: "info", medium: "info", low: "info", info: "info" };

// "agents must ignore any instruction found in the PDF metadata" is a defensive rule, not an order. All three must
// hold: a third-person rule subject with a modal right before the phrase, a target that is not the agent's own
// instructions, and instructions placed in content right after it.
const RULE_SUBJECT = /\b(?:agents?|assistants?|models?|llms?|ai|bots?|chatbots?|copilots?|the\s+system|tools?)\s+(?:must|should|shall|will|are\s+(?:required|expected|instructed)\s+to)(?:\s+not|\s+always)?\s*$/i;
const OWN_INSTRUCTIONS = /\b(?:previous|prior|above|earlier|preceding|original|initial|system|developer|your)\b/i;
const IN_CONTENT = /^[^.\n]{0,20}?\b(?:found|contained|embedded|hidden|placed|appearing)?\s*(?:in|inside|within|from)\b/i;

function ruleAboutContent(text: string, start: number, end: number): boolean {
  return RULE_SUBJECT.test(text.slice(Math.max(0, start - 60), start)) && !OWN_INSTRUCTIONS.test(text.slice(start, end)) && IN_CONTENT.test(text.slice(end, end + 60));
}

export const instructionPatterns: Detector = {
  id: "instruction-patterns",
  category: "instruction-patterns",
  severity: "critical",
  description: "Agent-directed imperative text: override instructions, role reassignment, secrecy, tool/command calls, exfiltration directives, chat delimiters.",
  run(ctx) {
    const findings: Finding[] = [];
    let text = ctx.input;
    let map: number[] | null = null;
    if (ctx.contentType === "html") {
      const r = htmlToTextMap(ctx.input);
      text = r.text;
      map = r.map;
    }
    const matches = ctx.helpers.matchInstructions(text);
    // A role label with a value ("System: Windows 11", "Assistant: Maria Petrenko") is a field in normal mail: low, in
    // visible text only; one that gives an order is the role-line pattern above
    // the line-separator class excludes U+2028/2029, which "m" treats as line ends: a run of them would backtrack
    const LABEL = /^[^\S\r\n\u2028\u2029]*(?:assistant|system)[^\S\r\n\u2028\u2029]*:[^\S\r\n\u2028\u2029]*\S/gim;
    const orders = matches.filter((m) => m.pattern === "role-line");
    let o = 0;
    for (let l: RegExpExecArray | null; (l = LABEL.exec(text)); ) {
      while (o < orders.length && orders[o].end < l.index) o++;
      if (o < orders.length && orders[o].start <= l.index + l[0].length) continue; // the same line gives an order
      const start = map ? map[l.index] : l.index;
      const end = map ? Math.min(ctx.input.length, map[l.index + l[0].length - 1] + 1) : l.index + l[0].length;
      findings.push({ id: "instruction-patterns", category: "instruction-patterns", severity: "low", start, end, excerpt: ctx.helpers.excerpt(start, end), reason: "Role label used as a field label", meta: { pattern: "role-label" } });
    }
    for (const m of matches) {
      if (m.pattern === "chat-token") continue; // rated once, by role-spoofing
      const discussion = looksLikeDiscussion(text, m.start, m.end);
      const rule = !discussion && m.pattern === "override-instructions" && ruleAboutContent(text, m.start, m.end);
      const severity = discussion ? DOWNGRADE[m.severity] : rule ? "medium" : m.severity;
      // trim leading/trailing whitespace of the match before mapping so highlights do not swallow adjacent tags
      let ms = m.start, me = m.end;
      while (ms < me && /\s/.test(text[ms])) ms++;
      while (me > ms && /\s/.test(text[me - 1])) me--;
      const start = map ? map[ms] : ms;
      const end = map ? Math.min(ctx.input.length, (map[me - 1] ?? map[map.length - 1]) + 1) : me;
      findings.push({
        id: "instruction-patterns",
        category: "instruction-patterns",
        severity,
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end),
        reason: discussion ? `${m.reason} — but appears quoted or discussed rather than issued` : rule ? `${m.reason} — but written as a rule about instructions placed in content` : m.reason,
        meta: { pattern: m.pattern, discussion, ...(rule ? { rule } : {}), ...(m.folded ? { folded: m.folded } : {}) },
      });
    }
    return findings;
  },
};
