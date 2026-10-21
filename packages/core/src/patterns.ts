import { CONFUSABLE_TO_ASCII } from "./data/confusables";
import type { InstructionMatch, Severity } from "./types";
import { registerScanCache } from "./util/caches";

interface PatternDef {
  name: string;
  re: RegExp;
  severity: Severity;
  reason: string;
  /** If true, the pattern alone is a finding; otherwise requires agent-addressed context nearby. */
  standalone?: boolean;
}

/**
 * Agent-directed instruction patterns. English + Ukrainian + German + Russian variants where cheap.
 * Mood matters: "ignore previous instructions" is a hit; "the paper discusses prompt injection" is not.
 */
export const INSTRUCTION_PATTERNS: PatternDef[] = [
  {
    name: "override-instructions",
    re: /\b(ignore|disregard|forget|override|bypass|skip|discard)\b[^.\n"“”`]{0,25}?\b(all\s+)?(the\s+)?(previous|prior|above|earlier|preceding|original|initial|system|developer|any|your)\b[^.\n"“”`]{0,20}?\b(instructions?|prompts?|rules?|guidelines?|directives?|constraints?|context)\b/i,
    severity: "critical",
    reason: "Attempts to override prior/system instructions",
    standalone: true,
  },
  {
    name: "override-instructions-uk",
    re: /\b(ігноруй(те)?|проігноруй(те)?|забудь(те)?|не\s+зважай(те)?\s+на|відкинь(те)?|знехтуй(те)?)\b[^.\n"“”`]{0,25}?\b(попередні|усі|всі|системні|вищезазначені|наведені\s+вище|початкові)\b[^.\n"“”`]{0,20}?\b(інструкці[їй]|вказівк[иу]|правил[а]?|налаштування|промпт)/iu,
    severity: "critical",
    reason: "Attempts to override prior instructions (Ukrainian)",
    standalone: true,
  },
  {
    name: "override-instructions-ru",
    re: /\b(игнорируй(те)?|проигнорируй(те)?|забудь(те)?|отбрось(те)?)\b[^.\n"“”`]{0,25}?\b(предыдущие|все|системные|вышеуказанные)\b[^.\n"“”`]{0,20}?\b(инструкции|указания|правила)/iu,
    severity: "critical",
    reason: "Attempts to override prior instructions (Russian)",
    standalone: true,
  },
  {
    name: "override-instructions-de",
    re: /\b(ignoriere?n?|vergiss|missachte|übergehe?)\b[^.\n"“”`]{0,25}?\b(alle|die|deine|sämtliche)?\s*(vorherigen|bisherigen|obigen|früheren|system-?)\s*(anweisungen|instruktionen|regeln|vorgaben)/iu,
    severity: "critical",
    reason: "Attempts to override prior instructions (German)",
    standalone: true,
  },
  {
    name: "new-instructions",
    re: /\b(new|updated|revised|real|actual|true)\s+(instructions?|system\s+prompt|rules|directive)s?\s*(:|are|follow|below)/i,
    severity: "high",
    reason: "Introduces replacement instructions",
    standalone: true,
  },
  {
    name: "role-reassign",
    re: /\byou\s+are\s+now\s+(a|an|the|in|no\s+longer|free|unrestricted|DAN|operating)\b/i,
    severity: "high",
    reason: "Reassigns the assistant's role",
    standalone: true,
  },
  {
    name: "role-reassign-uk",
    re: /\b(тепер\s+ти|відтепер\s+ти|ти\s+тепер)\s+[—-]?\s*\S/iu,
    severity: "high",
    reason: "Reassigns the assistant's role (Ukrainian)",
  },
  {
    name: "role-reassign-de",
    re: /\b(du\s+bist\s+(jetzt|ab\s+sofort|nun))\b/iu,
    severity: "high",
    reason: "Reassigns the assistant's role (German)",
  },
  {
    name: "system-prompt-ref",
    re: /\b(system\s*prompt|developer\s+message|system\s+message|hidden\s+prompt|reveal\s+your\s+(prompt|instructions))\b/i,
    severity: "medium",
    reason: "References the system prompt / developer message",
  },
  {
    name: "secrecy",
    re: /\b(do\s+not|don'?t|never|без\s+того\s+щоб|не)\s+(tell|inform|mention|reveal|disclose|show|alert|warn|повідомляй(те)?|кажи|говори|показуй)\b[^.\n]{0,30}\b(user|human|operator|anyone|them|користувач[ау]?|людині|нікому)\b/iu,
    severity: "high",
    reason: "Instructs the agent to hide actions from the user",
    standalone: true,
  },
  {
    name: "secrecy-de",
    re: /\b(sag|erzähl|verrate|erwähne)\s+(es\s+)?(dem\s+)?(nutzer|benutzer|user|niemandem)\s+nicht\b|\bnicht\s+(dem\s+)?(nutzer|benutzer)\s+(sagen|mitteilen|verraten)\b/iu,
    severity: "high",
    reason: "Instructs the agent to hide actions from the user (German)",
    standalone: true,
  },
  {
    name: "as-an-ai",
    re: /\b(as\s+an?\s+(ai|llm|language\s+model|assistant|agent)|if\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant|agent|bot))\b/i,
    severity: "medium",
    reason: "Addresses the reader as an AI",
  },
  {
    name: "ai-addressed-uk",
    re: /\b(якщо\s+ти\s+(ші|штучний\s+інтелект|асистент|бот|модель|агент)|ти\s+[—-]\s*(ші|асистент|агент))\b/iu,
    severity: "medium",
    reason: "Addresses the reader as an AI (Ukrainian)",
  },
  {
    name: "ai-addressed-de",
    re: /\b(wenn\s+du\s+(eine?\s+)?(ki|ai|sprachmodell|assistent|agent|bot)\s+bist|als\s+(ki|sprachmodell|assistent))\b/iu,
    severity: "medium",
    reason: "Addresses the reader as an AI (German)",
  },
  {
    name: "tool-call",
    re: /\b(call|invoke|use|trigger|execute|run)\s+(the\s+)?(tool|function|action|webhook|api|endpoint|skill|plugin)\b[^.\n]{0,60}/i,
    severity: "high",
    reason: "Directs a tool/function call",
  },
  {
    name: "tool-call-uk",
    re: /\b(виклич|викликай|використай|запусти|виконай)\s+(інструмент|функцію|команду|вебхук|api)\b/iu,
    severity: "high",
    reason: "Directs a tool/function call (Ukrainian)",
  },
  {
    name: "tool-call-de",
    re: /\b(rufe?|benutze|verwende|führe)\s+(das\s+|die\s+|den\s+)?(tool|funktion|werkzeug|befehl|webhook)\b/iu,
    severity: "high",
    reason: "Directs a tool/function call (German)",
  },
  {
    name: "run-command",
    re: /\b(run|execute|exec)\s+(the\s+|this\s+|following\s+)?(command|shell|script|code|bash)\b/i,
    severity: "high",
    reason: "Directs command execution",
  },
  {
    name: "shell-dangerous",
    re: /\b(curl|wget)\s+(-[a-zA-Z]+\s+)*https?:\/\/|\brm\s+-rf\b|\bpowershell(\.exe)?\s+(-\w+\s+)*(-enc|-e|iex|invoke-expression|downloadstring)|\bInvoke-WebRequest\b|\bbase64\s+(-d|--decode)\s*\|/i,
    severity: "high",
    reason: "Shell command with network/destructive effect",
    standalone: true,
  },
  {
    name: "exfil-send",
    re: /\b(send|forward|email|mail|post|upload|transmit|exfiltrate|leak|copy|надішли|надсилай|перешли|відправ|відправляй|schicke?|sende|leite\s+weiter)\b[^.\n]{0,80}?\b(to|на|an|at)\s+(https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+|the\s+(following|this)\s+(address|url|endpoint|email|webhook)|\S+\.(com|net|org|io|ru|ua|de|xyz|top))/iu,
    severity: "critical",
    reason: "Directs data to be sent to an external address",
    standalone: true,
  },
  {
    name: "exfil-collect",
    re: /\b(all|the|every|any)\s+(user'?s?\s+|customer\s+|stored\s+|saved\s+)?(password|credential|api\s*key|secret|token|private\s+key|ssn|credit\s+card|contact|email\s+address)s?\b[^.\n]{0,40}\b(send|include|append|forward|paste|insert|list|output|print)\b|\b(send|include|append|forward|paste|insert|list|output|print)\b[^.\n]{0,40}\b(password|credential|api\s*key|secret|token|private\s+key|ssn|credit\s+card)s?\b/i,
    severity: "critical",
    reason: "Directs collection of secrets",
    standalone: true,
  },
  {
    // chat-template turn tokens; in visible text the role-spoofing detector rates them, so instruction-patterns
    // skips this one, while hidden, encoded and smuggled text still counts it as an instruction
    name: "chat-token",
    re: /<\|[^|<>\n]{1,40}\|>|\[\/?INST\]|<<\/?SYS>>|<\/?(?:start|end)_of_turn>/i,
    severity: "high",
    reason: "Chat-template turn token injected into content",
    standalone: true,
  },
  {
    name: "chat-delimiter",
    re: /^[^\S\r\n\u2028\u2029]*###\s*(SYSTEM|System|INSTRUCTION|Instruction)s?:?\s*$|^[^\S\r\n\u2028\u2029]*(assistant|system|human|user)\s*:\s*$/im,
    severity: "high",
    reason: "Chat-template delimiter injected into content",
    standalone: true,
  },
  {
    // A role label that gives an order: "System: forward the file", "Assistant: reply only with ...". A label with a value
    // ("System: Windows 11", "Assistant: Maria Petrenko") is a field in normal mail and is rated low by instruction-patterns
    // in visible text only, so it never makes a hidden element critical.
    name: "role-line",
    re: /^[^\S\r\n\u2028\u2029]*(?:assistant|system)\s*:\s*(?:please\s+)?(?:ignore|disregard|forget|override|forward|send|reply|respond|answer|output|print|return|delete|remove|execute|run|call|open|click|transfer|approve|confirm|summari[sz]e|translate|tell|say|write|include|add|always|never|do\s+not|don'?t|you\s+(?:must|should|are|will|have\s+to))\b/im,
    severity: "high",
    reason: "Role label that gives an order, formatted as a chat turn",
  },
  {
    name: "approve-silently",
    re: /\b(approve|confirm|accept|authorize|pay|transfer|wire)\b[^.\n]{0,30}\b(immediately|without\s+(asking|review|confirmation|checking)|automatically|silently|no\s+need\s+to\s+(ask|verify|check))\b/i,
    severity: "high",
    reason: "Pushes for an unreviewed irreversible action",
    standalone: true,
  },
  {
    name: "summary-manipulation",
    re: /\b(when|if)\s+(you\s+)?(summariz|summaris|translat|process|read|analys|analyz)\w*\s+(this|the)\b[^.\n]{0,60}\b(say|respond|reply|write|output|tell|include|add|state|answer)\b/i,
    severity: "high",
    reason: "Conditions the agent's output on reading this document",
    standalone: true,
  },
  {
    name: "output-override",
    re: /\b(respond|reply|answer|output|say)\s+(only\s+)?(with|exactly)\s*[:"'“]/i,
    severity: "medium",
    reason: "Prescribes the exact model output",
  },
  {
    name: "output-override-uk",
    re: /\b(відповідай|відповідь\s+має\s+бути|напиши|виведи)\s+(тільки|лише|виключно)\b/iu,
    severity: "medium",
    reason: "Prescribes the exact model output (Ukrainian)",
  },
  {
    name: "output-override-de",
    re: /\b(antworte|gib)\s+(nur|ausschließlich|lediglich)\s+(mit|aus)?\b/iu,
    severity: "medium",
    reason: "Prescribes the exact model output (German)",
  },
  {
    name: "grant-approval",
    re: /\b(this\s+(document|file|email|invoice|request)\s+(is|has\s+been)\s+(pre-?approved|verified|safe|trusted|whitelisted|cleared))\b/i,
    severity: "medium",
    reason: "Self-asserted trust claim",
    standalone: true,
  },
];

/** Words that indicate the text is addressed to an agent/model, used as context for non-standalone patterns. */
const AGENT_CONTEXT =
  /\b(ai|a\.i\.|llm|assistant|agent|model|chatgpt|gpt|claude|gemini|copilot|bot|system|ші|асистент|агент|модел[ьі]|бот|ki|sprachmodell|assistent)\b/i;

/** Returns all instruction matches in `text` with offsets relative to `text`. */
/** JS \\b is ASCII-only; for Unicode patterns swap it for letter-aware lookarounds. */
export function unicodeBoundary(re: RegExp): RegExp {
  let src = re.source;
  let flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  if (!flags.includes("u")) flags += "u";
  src = src.replace(/\\b/g, "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))");
  return new RegExp(src, flags);
}

const COMPILED = INSTRUCTION_PATTERNS.map((p) => ({ ...p, re: unicodeBoundary(p.re) }));

// Positions of the agent-context words in the whole text, found once; a window then needs one binary search instead of
// a regex over 320+ chars per match. Only words that lie fully inside the window count (a word cut by the window's
// edge, "xbot" read as "bot", used to count).
export function contextFinder(text: string, context: RegExp = AGENT_CONTEXT): (from: number, to: number) => boolean {
  let hits: number[] | undefined; // start, end pairs, ascending and non-overlapping
  return (from, to) => {
    if (!hits) {
      hits = [];
      const re = new RegExp(context.source, "gi");
      for (let m: RegExpExecArray | null; (m = re.exec(text)); ) hits.push(m.index, m.index + m[0].length);
    }
    let lo = 0;
    let hi = hits.length / 2;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (hits[2 * mid] < from) lo = mid + 1;
      else hi = mid;
    }
    return lo < hits.length / 2 && hits[2 * lo + 1] <= to;
  };
}

// One code point folded to what it passes for: NFKD without combining marks first (math, fullwidth and circled letters,
// ligatures, diacritics fold to the exact letter), then UTS #39 for what is still not ASCII (Cyrillic, Greek, Armenian,
// Cherokee lookalikes). NFKD goes first because UTS #39 maps to a skeleton, not a letter: I and its lookalikes become "l".
// the skeleton of I is "l"; an uppercase lookalike (Cyrillic I) reads as I in a word, so it folds to I
const lookalikeToAscii = (c: string): string => {
  const cp = c.codePointAt(0)!;
  if (cp < 0x80) return c;
  const ascii = CONFUSABLE_TO_ASCII.get(cp);
  return ascii === "l" && /\p{Lu}/u.test(c) ? "I" : ascii ?? c;
};
const foldCache = new Map<number, string>();
function foldCodePoint(cp: number): string {
  let f = foldCache.get(cp);
  if (f === undefined) {
    f = [...String.fromCodePoint(cp).normalize("NFKD").replace(/\p{M}/gu, "")].map(lookalikeToAscii).join("");
    foldCache.set(cp, f);
  }
  return f;
}

/** The text as it reads, with each folded character's span in the original; undefined when folding changes nothing. */
export function foldText(text: string): { folded: string; from: Int32Array; to: Int32Array } | undefined {
  if (!/[^\x00-\x7F]/.test(text)) return undefined;
  const parts: string[] = [];
  const from: number[] = [];
  const to: number[] = [];
  let changed = false;
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i)!;
    const len = cp > 0xffff ? 2 : 1;
    const f = cp < 0x80 ? text[i] : foldCodePoint(cp);
    if (f !== text.slice(i, i + len)) changed = true;
    parts.push(f);
    for (let k = 0; k < f.length; k++) {
      from.push(i);
      to.push(i + len);
    }
    i += len;
  }
  return changed ? { folded: parts.join(""), from: Int32Array.from(from), to: Int32Array.from(to) } : undefined;
}

// lookalike-gaps: digits and symbols typed for letters, read only inside words that also hold 2+ letters, one
// character for one, so positions stay; "1" is read once as "l" and once as "i"
const LEET: Record<string, string> = { "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "i", "€": "e" };
const LEET_WORD = /[\p{L}\p{N}@$!|€]+/gu;
function leetFold(text: string, one: string): string {
  return text.replace(LEET_WORD, (w) => (/[0-9@$!|€]/.test(w) && /\p{L}[^\p{L}]*\p{L}/u.test(w) ? w.replace(/[0-9@$!|€]/g, (c) => (c === "1" ? one : LEET[c] ?? c)) : w));
}

function matchOnce(text: string, lineAnchoredOnly: boolean, out: InstructionMatch[], from?: Int32Array, to?: Int32Array, folded?: "leet"): void {
  const inContext = contextFinder(text);
  for (const p of COMPILED) {
    const re = p.re;
    if (lineAnchoredOnly && !re.multiline) continue;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    // at most 200 accepted matches per pattern; rejected ones do not count, so harmless repetitions in front of a
    // real instruction cannot use the limit up
    let accepted = 0;
    while (accepted < 200 && (m = re.exec(text))) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const start = m.index;
      const end = start + m[0].length;
      if (!p.standalone && !inContext(Math.max(0, start - 160), Math.min(text.length, end + 160))) continue;
      accepted++;
      // matches on the folded text point back into the original
      out.push({ start: from ? from[start] : start, end: to ? to[end - 1] : end, pattern: p.name, severity: p.severity, reason: p.reason, ...(folded ? { folded } : {}) });
    }
  }
}

export function matchInstructions(text: string, lineAnchoredOnly = false): InstructionMatch[] {
  const out: InstructionMatch[] = [];
  matchOnce(text, lineAnchoredOnly, out);
  // and on the folded text: the original pass keeps the Ukrainian, Russian and German patterns, which folding to Latin
  // lookalikes would break; the folded pass reads "\u{1D408}\u{1D420}\u{1D427}\u{1D428}\u{1D42B}\u{1D41E}" as "Ignore"
  const f = foldText(text);
  if (f) matchOnce(f.folded, lineAnchoredOnly, out, f.from, f.to);
  // and once more with leet read as letters, on top of the lookalike fold
  const base = f ? f.folded : text;
  if (/[0-9@$!|\u20AC]/.test(base)) {
    for (const one of /1/.test(base) ? ["l", "i"] : ["l"]) {
      const l = leetFold(base, one);
      if (l !== base) matchOnce(l, lineAnchoredOnly, out, f?.from, f?.to, "leet");
    }
  }
  // dedupe overlapping matches keeping the most severe; on a tie the match found without leet folding stays
  out.sort((a, b) => a.start - b.start || b.end - a.end || Number(!!a.folded) - Number(!!b.folded));
  const merged: InstructionMatch[] = [];
  for (const m of out) {
    const last = merged[merged.length - 1];
    if (last && m.start < last.end) {
      if (sevRank(m.severity) > sevRank(last.severity)) merged[merged.length - 1] = { ...m, start: Math.min(m.start, last.start), end: Math.max(m.end, last.end) };
      else last.end = Math.max(last.end, m.end);
      continue;
    }
    merged.push({ ...m });
  }
  return merged;
}

function sevRank(s: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}

/**
 * Heuristic: does text look like it *discusses* injection (quotes, "example", "for example", code fences)
 * rather than performing it? Used to downgrade severity in instruction-pattern detector.
 */
// Positions of the code fences in the last text asked about, found once (counting them per match was O(n) each).
let fenceCache: { text: string; at: number[] } | undefined;
registerScanCache(() => (fenceCache = undefined), () => fenceCache !== undefined);
/** Is [start, end) inside a code fence that opens before it and closes after it? An unclosed fence quotes nothing. */
export function insideClosedFence(text: string, start: number, end: number): boolean {
  if (fenceCache?.text !== text) {
    const at: number[] = [];
    for (let i = text.indexOf("```"); i >= 0; i = text.indexOf("```", i + 3)) at.push(i);
    fenceCache = { text, at };
  }
  const at = fenceCache.at;
  let lo = 0;
  let hi = at.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (at[mid] < start) lo = mid + 1;
    else hi = mid;
  }
  // lo fences before the match; an odd count opens one, and it quotes the match only if a fence closes after it
  return lo % 2 === 1 && lo < at.length && at[lo] >= end;
}

// a single quote that is not an apostrophe inside a word ("I'm", "don't")
const SINGLE_QUOTE = /(?<![\p{L}\p{N}])'|'(?![\p{L}\p{N}])/gu;
/**
 * Is [start, end) enclosed in quotes on its line: a quote opened before it and closed after it? An odd quote with no
 * closing one after the match quotes nothing; an attacker could otherwise switch the check off with one ".
 * Straight quotes have a direction: a closing quote with nothing opened before it (`email" ] }`, `John"`) does
 * not open a quotation, so it cannot switch off what follows it on the line (run 5).
 */
export function enclosedInQuotes(text: string, start: number, end: number): boolean {
  const q = quoteIndex(text);
  const lineStart = q.newline[below(q.newline, start) - 1] + 1 || 0;
  const nextNl = q.newline[below(q.newline, end)] ?? text.length;
  // per quote kind: how many on the line before the match, the last one before it, and is there one after it on the line
  const before = (at: number[]) => below(at, start) - below(at, lineStart);
  const last = (at: number[]) => {
    const i = below(at, start) - 1;
    return i >= 0 && at[i] >= lineStart ? at[i] : -1;
  };
  const after = (at: number[]) => {
    const i = below(at, end);
    return i < at.length && at[i] < nextNl;
  };
  for (const [open, close] of [[q.openDouble, q.closeDouble], [q.openSingle, q.closeSingle]]) {
    const o = last(open);
    if (o >= 0 && o > last(close) && after(close)) return true;
  }
  if (before(q.backtick) % 2 === 1 && after(q.backtick)) return true;
  return before(q.openCurly) > before(q.closeCurly) && after(q.closeCurly);
}

/**
 * The direction of a straight quote at i, read from its neighbours; the first rule that fits wins. An escaped `\"` is
 * read through its backslashes, because double-escaped JSON uses `\"` as its real quotes.
 */
function quoteSide(text: string, i: number): "open" | "close" | undefined {
  let j = i - 1;
  while (j >= 0 && text[j] === "\\") j--;
  const prev = j >= 0 ? text[j] : "\n";
  const next = text[i + 1] ?? "";
  // a JSON or markup break: `" ] }`, `"/>`
  if (/[\]}),;>]/.test(next) || (next === "/" && text[i + 2] === ">")) return "close";
  if (/[\s([{:=,]/.test(prev) && next !== "" && !/\s/.test(next)) return "open";
  if (!/\s/.test(prev)) return "close";
  return undefined;
}

// Positions of newlines and quote characters in the last text asked about, found once; counts on a line are then two
// binary searches, so many matches on one long line stay linear and exact.
let quoteCache: { text: string; newline: number[]; backtick: number[]; openCurly: number[]; closeCurly: number[]; openDouble: number[]; closeDouble: number[]; openSingle: number[]; closeSingle: number[] } | undefined;
registerScanCache(() => (quoteCache = undefined), () => quoteCache !== undefined);
function quoteIndex(text: string) {
  if (quoteCache?.text !== text) {
    const c = { text, newline: [] as number[], backtick: [] as number[], openCurly: [] as number[], closeCurly: [] as number[], openDouble: [] as number[], closeDouble: [] as number[], openSingle: [] as number[], closeSingle: [] as number[] };
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === "\n") c.newline.push(i);
      else if (ch === '"') {
        const side = quoteSide(text, i);
        if (side) (side === "open" ? c.openDouble : c.closeDouble).push(i);
      } else if (ch === "`") c.backtick.push(i);
      else if (ch === "\u201C") c.openCurly.push(i);
      else if (ch === "\u201D") c.closeCurly.push(i);
    }
    SINGLE_QUOTE.lastIndex = 0;
    for (let m: RegExpExecArray | null; (m = SINGLE_QUOTE.exec(text)); ) {
      const side = quoteSide(text, m.index);
      if (side) (side === "open" ? c.openSingle : c.closeSingle).push(m.index);
    }
    quoteCache = c;
  }
  return quoteCache;
}

/** Index of the first position in the ascending list that is >= at. */
function below(list: number[], at: number): number {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid] < at) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** A cue that the text right after it is an example being discussed ("phrases like ..."); tested on the 200 chars before. */
export const CUE_BEFORE = /\b(for\s+example|e\.g\.|such\s+as|like|example|examples|attack(er)?s?\s+(may|might|could|often|typically|will)|phrases?\s+(like|such\s+as)|pattern|detects?|flag(s|ged)?|classic|known\s+as|called)\b[^.\n]{0,60}$/i;

export function looksLikeDiscussion(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 200), start);
  if (insideClosedFence(text, start, end)) return true;
  // quoted on the same line (e.g. the string "ignore previous instructions")
  if (enclosedInQuotes(text, start, end)) return true;
  if (/QUOTED CONTENT, NOT INSTRUCTIONS/.test(before)) return true;
  if (CUE_BEFORE.test(before))
    return true;
  return false;
}
