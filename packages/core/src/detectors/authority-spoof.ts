import type { Detector, Finding, Severity } from "../types";
import { contextFinder, enclosedInQuotes, foldText, insideClosedFence, unicodeBoundary } from "../patterns";

interface P {
  re: RegExp;
  severity: Severity;
  reason: string;
}

const PATTERNS: P[] = [
  {
    re: /\b(this\s+(message|note|instruction|document|email|text|section)\s+(is|comes|was\s+sent)\s+(from|by)|(message|note|notice|instruction)\s+from)\s+(the\s+)?(system|admin(istrator)?|developer|operator|security\s+team|it\s+(team|department)|n8n\s+team|anthropic|openai|google|microsoft|meta|the\s+model\s+provider|your\s+(creator|developer|operator|owner))s?\b/i,
    severity: "high",
    reason: "Claims to come from the system / admin / vendor",
  },
  {
    re: /\b(system|admin(istrator)?|developer|operator|root|sudo|anthropic|openai|security)\s*(override|notice|alert|directive|instruction|command|update|message)\s*[:\-—]/i,
    severity: "high",
    reason: "Formatted as an authority directive",
  },
  {
    re: /\b(note|message|instructions?|attention|notice|hint|memo)\s+(to|for)\s+(the\s+)?(ai|a\.i\.|assistant|agent|model|llm|bot|chatgpt|claude|gpt|gemini|copilot|language\s+model|automated\s+(reader|system)s?)\s*[:\-—]?/i,
    severity: "high",
    reason: "Explicit note addressed to the AI",
  },
  {
    re: /\b(примітка|нотатка|повідомлення|інструкці[яї]|увага)\s+(для|до)\s+(ші|штучного\s+інтелекту|асистента|агента|бота|моделі|llm|ai)\b/iu,
    severity: "high",
    reason: "Explicit note addressed to the AI (Ukrainian)",
  },
  {
    re: /\b(hinweis|nachricht|anweisung|notiz|achtung)\s+(an|für)\s+(die|den|das)?\s*(ki|ai|assistenten?|agenten?|bot|sprachmodell|llm)\b/iu,
    severity: "high",
    reason: "Explicit note addressed to the AI (German)",
  },
  {
    re: /\b(повідомлення|лист|інструкція)\s+від\s+(системи|адміністратора|адміна|розробника|команди\s+безпеки|anthropic|openai|n8n)\b/iu,
    severity: "high",
    reason: "Claims to come from the system / admin (Ukrainian)",
  },
  {
    re: /\b(nachricht|hinweis|anweisung)\s+(vom|von\s+der|von\s+dem|des)\s+(system|administrator|admin|entwickler|sicherheitsteam|anthropic|openai)\b/iu,
    severity: "high",
    reason: "Claims to come from the system / admin (German)",
  },
  {
    re: /^[^\S\r\n\u2028\u2029]*(\*{0,2}|#+\s*)?(IMPORTANT|URGENT|CRITICAL|WARNING|ATTENTION|SYSTEM|ADMIN|OVERRIDE|PRIORITY|MANDATORY|ВАЖЛИВО|УВАГА|ТЕРМІНОВО|WICHTIG|ACHTUNG|DRINGEND)\s*(\*{0,2})\s*[:!]/imu,
    severity: "low",
    reason: "Shouted priority marker",
  },
  {
    re: /\b(authorized|authorised|verified|approved|signed)\s+by\s+(the\s+)?(system|admin(istrator)?|developer|security|anthropic|openai|n8n|your\s+operator)\b/i,
    severity: "medium",
    reason: "Self-asserted authorization",
  },
  {
    re: /\b(i\s+am|this\s+is|we\s+are)\s+(your|the)\s+(developer|creator|operator|administrator|admin|owner|system|security\s+team)\b/i,
    severity: "high",
    reason: "Impersonates the operator/developer",
  },
  {
    re: /\b(я|це|ми)\s+[—-]?\s*(твій|ваш|твоя)\s+(розробник|адміністратор|оператор|власник|творець)\b/iu,
    severity: "high",
    reason: "Impersonates the operator/developer (Ukrainian)",
  },
  {
    re: /\b(ich\s+bin|wir\s+sind|das\s+ist)\s+(dein|euer|der)\s+(entwickler|administrator|betreiber|besitzer|ersteller)\b/iu,
    severity: "high",
    reason: "Impersonates the operator/developer (German)",
  },
  {
    re: /\b(trusted|privileged|elevated|admin|root|developer)\s+(mode|access|level|context)\s+(enabled|granted|activated|on)\b/i,
    severity: "high",
    reason: "Claims elevated privilege",
  },
];

const AGENT_CONTEXT = /\b(ai|assistant|agent|model|llm|bot|system\s+prompt|instructions?|ші|асистент|агент|ki|assistent)\b/i;

export const authoritySpoof: Detector = {
  id: "authority-spoof",
  category: "authority-spoof",
  severity: "high",
  description: "Text claiming to speak with system/admin/vendor authority, or explicitly addressed to the AI.",
  run(ctx) {
    const findings: Finding[] = [];
    // the original text, then its folded view ("\uFF29\uFF2D\uFF30\uFF2F\uFF32\uFF34\uFF21\uFF2E\uFF34" reads as IMPORTANT); offsets
    // from the folded pass point back into the original
    const read = (s: string, from?: Int32Array, to?: Int32Array) => {
      const inContext = contextFinder(s, AGENT_CONTEXT);
      for (const p of PATTERNS) {
        const re = unicodeBoundary(p.re);
        let m: RegExpExecArray | null;
        // at most 100 accepted matches; markers rejected for lack of context do not count
        let accepted = 0;
        while (accepted < 100 && (m = re.exec(s))) {
          if (!m[0].length) {
            re.lastIndex++;
            continue;
          }
          const start = m.index;
          const end = start + m[0].length;
          let severity = p.severity;
          // "IMPORTANT:" alone is nothing; only count when near agent context
          if (p.severity === "low") {
            if (!inContext(start, Math.min(s.length, end + 220))) continue;
            severity = "medium";
          }
          // Quoted/discussed? (same simple heuristic as instruction patterns)
          const quoted = enclosedInQuotes(s, start, end) || insideClosedFence(s, start, end);
          if (quoted) severity = severity === "high" ? "low" : "info";
          accepted++;
          findings.push({
            id: "authority-spoof",
            category: "authority-spoof",
            severity,
            start: from ? from[start] : start,
            end: to ? to[end - 1] : end,
            excerpt: ctx.helpers.excerpt(from ? from[start] : start, to ? to[end - 1] : end),
            reason: quoted ? `${p.reason} — quoted or inside code, likely discussion` : p.reason,
          meta: { discussion: quoted },
          });
        }
      }
    };
    read(ctx.input);
    const folded = foldText(ctx.input);
    if (folded) read(folded.folded, folded.from, folded.to);
    findings.sort((a, b) => a.start - b.start);
    // dedupe overlaps
    const out: Finding[] = [];
    for (const f of findings) {
      const last = out[out.length - 1];
      if (last && f.start < last.end) continue;
      out.push(f);
    }
    return out;
  },
};
