import type { ContentType, DetectorContext, EmailField, EmailInput, Finding, Provenance, ResolvedContentType, Result, ScanOptions, Severity, Verdict } from "./types";
import { DETECTORS } from "./detectors";
import { hiddenHtml } from "./detectors/hidden-html";
import { HTML_ELEMENTS } from "./detectors/role-spoofing";
import { foldText, matchInstructions } from "./patterns";
import { htmlToTextMap, makeExcerpt, maxSeverity, SEVERITY_WEIGHT, clamp } from "./util/text";
import { parseEmailHeaders, parseFrontMatter, parseHtmlMeta } from "./detectors/metadata";
import { decodeEncodedWords, displayAndAddress, headerList } from "./util/mime";
import { clearScanCaches } from "./util/caches";

export const VERSION = "1.0.0";

export function detectContentType(input: string): ResolvedContentType {
  const head = input.slice(0, 4000);
  if (/^\s*(<!doctype\s+html|<html|<head|<body)/i.test(head)) return "html";
  const tagCount = (head.match(/<\/?(div|p|span|br|table|tr|td|a|img|meta|script|style|h[1-6]|ul|li|strong|em|b|i|font)\b[^>]*>/gi) || []).length;
  if (tagCount >= 3 || /<!--/.test(head)) return "html";
  if (/^\uFEFF?(---|\+\+\+)\r?\n/.test(input)) return "markdown";
  const mdSignals = (head.match(/^#{1,6}\s|^\s*[-*+]\s|^\s*\d+\.\s|\[[^\]]+\]\([^)]+\)|^```|\*\*[^*]+\*\*|^>\s/gm) || []).length;
  if (mdSignals >= 2) return "markdown";
  return "text";
}

// a tag of a real HTML element or a comment; made-up tags (<rule>, <note>) are role-spoofing's
const FRAGMENT_TAG = /<!--|<\/?([A-Za-z][A-Za-z0-9]{0,15})(?=[\s/>])/g;
const RAW_ELEMENTS = new Set(["noembed", "noframes", "plaintext", "xmp"]);
// a bogus comment ("<!— … >", "<?x … >", "</ x … >") holding 3+ words of prose: hidden in a browser
const BOGUS_COMMENT = /<(?:!(?!--|\[|[dD][oO][cC][tT][yY][pP][eE])|\?|\/[^A-Za-z>\s])/g;
function hasBogusProse(text: string): boolean {
  BOGUS_COMMENT.lastIndex = 0;
  let gt = -1;
  for (let m: RegExpExecArray | null; (m = BOGUS_COMMENT.exec(text)); ) {
    if (gt < m.index) gt = text.indexOf(">", m.index);
    const body = text.slice(m.index + 2, gt < 0 ? Math.min(text.length, m.index + 2000) : Math.min(gt, m.index + 2000));
    if ((body.match(/(?<![\p{L}\p{N}])\p{L}{2,}/gu) || []).length >= 3) return true;
    if (gt < 0) return false;
    // the comment ends at that ">": a "<!" inside it is part of it, so reading resumes after it
    BOGUS_COMMENT.lastIndex = gt + 1;
  }
  return false;
}
function hasHtmlFragment(text: string): boolean {
  if (hasBogusProse(text)) return true;
  FRAGMENT_TAG.lastIndex = 0;
  for (let m: RegExpExecArray | null; (m = FRAGMENT_TAG.exec(text)); ) {
    if (!m[1]) return true;
    const name = m[1].toLowerCase();
    if (HTML_ELEMENTS.has(name) || RAW_ELEMENTS.has(name)) return true;
  }
  return false;
}

export function resolveContentType(input: string, ct: ContentType | undefined): ResolvedContentType {
  if (!ct || ct === "auto") return detectContentType(input);
  return ct;
}

/**
 * Score: sum severity weights with diminishing returns per category, then a mild bonus for category diversity.
 * Normalized to 0–100. One critical finding alone is a block (~74); one high is a review (~59); one medium is a review (~39); lows and infos stay ok unless they pile up across categories.
 */
export function computeScore(findings: Finding[]): number {
  if (!findings.length) return 0;
  const byCat = new Map<string, number[]>();
  for (const f of findings) {
    const arr = byCat.get(f.category) ?? [];
    arr.push(SEVERITY_WEIGHT[f.severity]);
    byCat.set(f.category, arr);
  }
  let total = 0;
  for (const weights of byCat.values()) {
    weights.sort((a, b) => b - a);
    // diminishing returns inside a category: 1, 1/2, 1/3 ... capped
    let catScore = 0;
    weights.slice(0, 12).forEach((w, i) => (catScore += w / Math.pow(i + 1, 1.5)));
    total += Math.min(catScore, 70);
  }
  const cats = byCat.size;
  const diversity = cats >= 3 ? 1.15 : cats === 2 ? 1.07 : 1;
  const raw = total * diversity;
  // soft normalization: one critical (48) -> 74 block; one high (32) -> 59 review; one medium (18) -> 39 review; one low (6) -> 15 ok
  const score = 100 * (1 - Math.exp(-raw / 36));
  return Math.round(clamp(score, 0, 100));
}

export function verdictFor(score: number): Verdict {
  if (score >= 70) return "block";
  if (score >= 30) return "review";
  return "ok";
}

function provenanceFor(input: string, ct: ResolvedContentType, findings: Finding[]): Provenance {
  const prov: Provenance = { detectedSignals: [] };
  const fields: { key: string; value: string }[] = [];
  const fm = parseFrontMatter(input);
  // loops, not push(...spread): a document with hundreds of thousands of fields or findings overflows the call stack
  for (const f of fm?.fields ?? []) fields.push(f);
  if (ct === "html") for (const f of parseHtmlMeta(input)) fields.push(f);
  for (const f of parseEmailHeaders(input)) fields.push(f);
  for (const f of fields) {
    const k = f.key;
    if (!prov.declaredAuthor && /^(author|from|sender|dc\.creator|article:author|creator|og:site_name|reply-to)$/.test(k)) prov.declaredAuthor = f.value.slice(0, 120);
    if (!prov.declaredSource && /^(source|origin|generator|url|canonical|og:url|site|publisher|x-mailer|x-originating-ip)$/.test(k)) prov.declaredSource = f.value.slice(0, 160);
    if (!prov.declaredTitle && /^(title|subject|og:title)$/.test(k)) prov.declaredTitle = f.value.slice(0, 160);
  }
  const cats = new Set(findings.filter((f) => f.severity !== "info").map((f) => f.category));
  const labels: Record<string, string> = {
    "zero-width": "invisible characters",
    "bidi-override": "bidi overrides",
    "unicode-tags": "hidden Unicode-tag text",
    homoglyph: "mixed-script lookalikes",
    "hidden-html": "hidden HTML content",
    "encoded-payload": "encoded payload",
    "instruction-patterns": "agent-directed instructions",
    "exfil-urls": "exfiltration URLs",
    "authority-spoof": "spoofed authority",
    metadata: "instructions in metadata",
    "role-spoofing": "fake chat turns",
    "cross-field": "signals across email parts",
    "fake-delimiter": "fake context delimiters",
  };
  for (const c of cats) prov.detectedSignals.push(labels[c] ?? c);
  return prov;
}

/** One document through every enabled detector; findings deduped and sorted, errors collected (fail closed). */
function scanDocument(input: string, opts: ScanOptions, contentTypeHint?: ContentType) {
  const maxLength = capOf(opts);
  // past the cap nothing is read, so the scan cannot call the input clean: the result is an error (too_large)
  const cut = input.length > maxLength;
  const text = cut ? input.slice(0, maxLength) : input;
  const contentType = resolveContentType(text, contentTypeHint ?? opts.contentType);
  const ctx: DetectorContext = {
    input: text,
    contentType,
    options: { decodeBase64: opts.decodeBase64 ?? true, ...opts },
    helpers: {
      matchInstructions,
      excerpt: (s, e, pad) => makeExcerpt(text, s, e, pad),
    },
  };
  const enabled = opts.detectors ? DETECTORS.filter((d) => opts.detectors!.includes(d.id)) : DETECTORS;
  const findings: Finding[] = [];
  const failed: { id: string; message: string }[] = [];
  for (const d of enabled) {
    try {
      for (const f of d.run(ctx)) findings.push(f);
    } catch (err) {
      // fail closed: a detector that throws must surface as verdict "error", never silently drop out
      failed.push({ id: d.id, message: (err as Error)?.message ?? String(err) });
    }
  }
  // an HTML fragment in plain text or markdown: hidden-html reads it as HTML too, the other detectors keep the text view
  if (contentType !== "html" && enabled.includes(hiddenHtml) && hasHtmlFragment(text)) {
    try {
      for (const f of hiddenHtml.run({ ...ctx, contentType: "html", fragment: true })) findings.push(f);
    } catch (err) {
      failed.push({ id: hiddenHtml.id, message: (err as Error)?.message ?? String(err) });
    }
  }
  return { text, contentType, failed, cut, findings: capPerCategory(dedupe(findings)).sort((a, b) => a.start - b.start || rank(b.severity) - rank(a.severity)) };
}

// At most this many findings per category: the score reads only the strongest few of each, and an unbounded list lets
// hostile input grow the result to many megabytes. The strongest are kept, so the score does not change.
const PER_CATEGORY = 200;
function capPerCategory(findings: Finding[]): Finding[] {
  const byCat = new Map<string, number>();
  for (const f of findings) byCat.set(f.category, (byCat.get(f.category) ?? 0) + 1);
  if (![...byCat.values()].some((n) => n > PER_CATEGORY)) return findings;
  const kept = new Map<string, number>();
  return findings
    .slice()
    .sort((a, b) => rank(b.severity) - rank(a.severity) || a.start - b.start)
    .filter((f) => {
      const n = kept.get(f.category) ?? 0;
      kept.set(f.category, n + 1);
      return n < PER_CATEGORY;
    });
}

function summarize(findings: Finding[]): Result["summary"] {
  const summary: Result["summary"] = {};
  for (const f of findings) {
    const s = summary[f.category] ?? { count: 0, maxSeverity: "info" as Severity };
    s.count++;
    s.maxSeverity = maxSeverity(s.maxSeverity, f.severity);
    summary[f.category] = s;
  }
  return summary;
}

/** The size cap; anything that is not a positive number keeps the default, so a bad option cannot turn the cap off. */
function capOf(opts: ScanOptions): number {
  return typeof opts.maxLength === "number" && opts.maxLength > 0 ? opts.maxLength : 2_000_000;
}

function errorOf(failed: { id: string; message: string }[], cut = false, maxLength = 2_000_000) {
  if (!failed.length && !cut) return {};
  const messages = failed.map((f) => `${f.id}: ${f.message}`);
  if (cut) messages.unshift(`input over ${maxLength} characters: only the first ${maxLength} were scanned`);
  return { error: { reason: cut ? ("too_large" as const) : ("scan_error" as const), detectors: [...new Set(failed.map((f) => f.id))], message: messages.join("; ") } };
}

/** The result of an input that could not be read at all: it fails closed. */
function unreadable(err: unknown): Result {
  return {
    score: 0,
    verdict: "error",
    contentType: "text",
    findings: [],
    summary: {},
    provenance: { detectedSignals: [] },
    length: 0,
    durationMs: 0,
    version: VERSION,
    error: { reason: "scan_error", detectors: [], message: `input: ${(err as Error)?.message ?? String(err)}` },
  };
}

const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());

export function scan(input: string | EmailInput, opts: ScanOptions = {}): Result {
  try {
    return scanOnce(input, opts);
  } catch (err) {
    // an input that cannot be read (a field whose toString throws) must not escape as an exception
    return unreadable(err);
  } finally {
    clearScanCaches();
  }
}

function scanOnce(input: string | EmailInput, opts: ScanOptions): Result {
  if (input !== null && typeof input === "object" && !Array.isArray(input)) return scanEmail(input, opts);
  const t0 = now();
  if (typeof input !== "string") input = input == null ? "" : String(input);
  const { text, contentType, failed, cut, findings } = scanDocument(input, opts);
  const score = computeScore(findings);
  return {
    score,
    verdict: failed.length || cut ? "error" : verdictFor(score),
    contentType,
    findings,
    summary: summarize(findings),
    provenance: provenanceFor(text, contentType, findings),
    length: input.length,
    durationMs: Math.round((now() - t0) * 100) / 100,
    version: VERSION,
    ...errorOf(failed, cut, capOf(opts)),
  };
}

// An email as its parts: each part is its own document, so a fence, a quote or a line start in one part never
// changes how another is read; one score over all findings decides the verdict (two parts at 59 can block, clean parts
// cannot dilute a blocked one), and `fields` gives each part's own score.
// Nothing addressed to an agent belongs in a subject: instructions, role markers and authority markers there rate
// one step higher; a role label used as a field and anything quoted or discussed keep their level.
const LIFTED = new Set(["instruction-patterns", "role-spoofing", "authority-spoof"]);
const STEP_UP: Record<Severity, Severity> = { info: "info", low: "medium", medium: "high", high: "critical", critical: "critical" };
function liftInSubject(f: Finding): Finding {
  if (!LIFTED.has(f.category) || f.meta?.discussion || f.meta?.pattern === "role-label" || f.severity === "info") return f;
  return { ...f, severity: STEP_UP[f.severity], reason: `${f.reason} — in the subject, rated one step higher` };
}

// A file name that hides what the file is. Windows hides the last extension by default, so "invoice.pdf.exe" reads
// as "invoice.pdf"; padding pushes the real extension out of view, and a bidi control flips it on screen. No legitimate
// file is named that way, so both are critical. ".tar.gz", ".min.js", versions and dates are not.
const BIDI_IN_NAME = /[\u202A-\u202E\u2066-\u2069]/;
const HIDDEN_EXECUTABLE = /\.(?:pdf|docx?|xlsx?|pptx?|od[tsp]|rtf|txt|csv|jpe?g|png|gif|bmp|tiff?|heic|webp|svg|mp3|mp4|m4a|mov|avi|wav|zip|rar|7z)\s*\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|lnk|iso|img|msi|ps1|hta|jar|wsf|cpl)$/i;
function nameFindings(name: string): Finding[] {
  const out: Finding[] = [];
  const at = (start: number, end: number, reason: string): Finding => ({ id: "metadata", category: "metadata", severity: "critical", start, end, excerpt: makeExcerpt(name, start, end, 12), reason });
  const b = BIDI_IN_NAME.exec(name);
  if (b) out.push(at(b.index, b.index + 1, "Attachment name holds a bidi control that flips how its extension reads"));
  const trimmed = name.trimEnd();
  const x = HIDDEN_EXECUTABLE.exec(trimmed);
  if (x) out.push(at(x.index, trimmed.length, `Attachment name hides an executable behind a document extension: ${x[0].replace(/\s+/g, " ")}`));
  return out;
}

function scanEmail(email: EmailInput, opts: ScanOptions): Result {
  const t0 = now();
  const str = (v: unknown) => (typeof v === "string" ? v : v == null ? "" : String(v));
  type Part = { field: EmailField; attachment?: number; name?: string; header?: string; text: string; hint?: ContentType };
  const parts: Part[] = [];
  if (str(email.subject)) parts.push({ field: "subject", text: str(email.subject), hint: "text" });
  if (str(email.body)) parts.push({ field: "body", text: str(email.body) });
  if (str(email.html)) parts.push({ field: "html", text: str(email.html), hint: "html" });
  (Array.isArray(email.attachments) ? email.attachments : []).forEach((a, i) => {
    if (str(a?.text)) parts.push({ field: "attachment", attachment: i, name: str(a?.name) || undefined, text: str(a.text) });
  });
  for (const h of headerList(email.headers)) if (h.value && !SKIPPED_HEADERS.test(h.name)) parts.push({ field: "header", header: h.name, text: h.value, hint: "text" });
  if (!parts.length) return scan("", opts);
  const findings: Finding[] = [];
  let cut = false;
  const failed: { id: string; message: string }[] = [];
  const fields: NonNullable<Result["fields"]> = [];
  let main: { text: string; contentType: ResolvedContentType } | undefined;
  for (const p of parts) {
    // subject and header values are read with their RFC 2047 encoded words decoded; offsets map back to the original
    const decoded = p.field === "subject" || p.field === "header" ? decodeEncodedWords(p.text) : undefined;
    const r = scanDocument(decoded?.text ?? p.text, opts, p.hint);
    if (r.cut) cut = true;
    const back = (f: Finding): Finding => (decoded ? { ...f, start: decoded.from[f.start] ?? 0, end: decoded.to[f.end - 1] ?? p.text.length } : f);
    const where = (f: Finding): Finding => {
      const g = { ...back(f), field: p.field };
      if (p.field === "attachment") return { ...g, attachment: p.attachment };
      if (p.field === "subject") return liftInSubject(g);
      if (p.field === "header") return liftInHeader({ ...g, meta: { ...g.meta, header: p.header } });
      return g;
    };
    const tagged = r.findings.map(where);
    if (p.field === "attachment" && p.name) {
      const n = scanDocument(p.name, opts, "text");
      if (n.cut) cut = true;
      for (const e of n.failed) failed.push({ id: e.id, message: `attachment[${p.attachment}] name: ${e.message}` });
      for (const f of [...n.findings, ...nameFindings(p.name)]) tagged.push({ ...f, field: "attachment", attachment: p.attachment, meta: { ...f.meta, part: "name" } });
    }
    if (p.field === "header" && /^(from|sender|reply-to)$/i.test(p.header!)) {
      const f = displayNameSpoof(decoded?.text ?? p.text);
      if (f) tagged.push({ ...back(f), field: "header", meta: { ...f.meta, header: p.header } });
    }
    for (const f of tagged) findings.push(f);
    const label = p.field === "attachment" ? `attachment[${p.attachment}]` : p.field === "header" ? `header ${p.header}` : p.field;
    for (const e of r.failed) failed.push({ id: e.id, message: `${label}: ${e.message}` });
    fields.push({
      field: p.field,
      ...(p.field === "attachment" ? { attachment: p.attachment, ...(p.name ? { name: p.name } : {}) } : {}),
      ...(p.field === "header" ? { header: p.header } : {}),
      contentType: r.contentType,
      length: p.text.length,
      score: computeScore(tagged),
    });
    // the HTML part, else the plain one, stands for the email in contentType and provenance
    if (p.field === "html" || (p.field === "body" && !main)) main = { text: r.text, contentType: r.contentType };
  }
  main ??= { text: parts[0].text, contentType: fields[0].contentType };
  for (const f of crossField(findings, parts)) findings.push(f);
  // the per-category cap again over the whole email, so many parts cannot multiply it
  const all = capPerCategory(findings);
  if (all !== findings) {
    findings.length = 0;
    for (const f of all) findings.push(f);
  }
  const score = computeScore(findings);
  return {
    score,
    verdict: failed.length || cut ? "error" : verdictFor(score),
    contentType: main.contentType,
    findings,
    summary: summarize(findings),
    provenance: provenanceFor(main.text, main.contentType, findings),
    length: parts.reduce((n, p) => n + p.text.length, 0),
    durationMs: Math.round((now() - t0) * 100) / 100,
    version: VERSION,
    fields,
    ...errorOf(failed, cut, capOf(opts)),
  };
}

// Which texts hold each pattern as a substring, for many patterns against long texts in one pass per text
// (Aho-Corasick), so the cross-field address check stays linear. Patterns must be distinct;
// returns, for each pattern, the indices of the texts that hold it, in order.
function textsHolding(patterns: string[], texts: string[]): number[][] {
  const next: Map<string, number>[] = [new Map()];
  const fail = [0];
  const out = [-1]; // the pattern that ends at this node
  const dict = [-1]; // the nearest node on the fail chain where a pattern ends
  patterns.forEach((p, id) => {
    let n = 0;
    for (const ch of p) {
      let m = next[n].get(ch);
      if (m === undefined) {
        m = next.length;
        next[n].set(ch, m);
        next.push(new Map());
        fail.push(0);
        out.push(-1);
        dict.push(-1);
      }
      n = m;
    }
    out[n] = id;
  });
  const queue = [...next[0].values()];
  for (let q = 0; q < queue.length; q++) {
    const n = queue[q];
    for (const [ch, m] of next[n]) {
      let f = fail[n];
      while (f && !next[f].has(ch)) f = fail[f];
      fail[m] = next[f].get(ch) ?? 0;
      dict[m] = out[fail[m]] >= 0 ? fail[m] : dict[fail[m]];
      queue.push(m);
    }
  }
  const holding: number[][] = patterns.map(() => []);
  // a node already reached in this text has had its whole fail chain recorded, so each node is recorded once per text
  const seen = new Array<number>(next.length).fill(-1);
  texts.forEach((t, ti) => {
    let n = 0;
    for (const ch of t) {
      while (n && !next[n].has(ch)) n = fail[n];
      n = next[n].get(ch) ?? 0;
      for (let k = out[n] >= 0 ? n : dict[n]; k >= 0 && seen[k] !== ti; k = dict[k]) {
        seen[k] = ti;
        holding[out[k]].push(ti);
      }
    }
  });
  return holding;
}

// Structure read across the parts of an email: an attack split so that each part alone looks weak.
const partKey = (f: Finding) => (f.field === "attachment" ? `attachment[${f.attachment}]` : f.field === "header" ? `header ${f.meta?.header}` : f.field ?? "");
function crossField(findings: Finding[], parts: { field: EmailField; attachment?: number; header?: string; text: string }[]): Finding[] {
  const out: Finding[] = [];
  const at = (f: Finding, severity: Severity, reason: string, fields: string[]): Finding => ({ ...f, id: "cross-field", category: "cross-field", severity, reason, meta: { fields } });
  const real = (f: Finding) => !f.meta?.discussion && f.meta?.pattern !== "role-label" && f.severity !== "info";
  // 1. an instruction or marker in the subject while the body is a decoy ("TEST")
  const visible = parts.filter((p) => p.field === "body" || p.field === "html").map((p) => (p.field === "html" ? htmlToTextMap(p.text).text : p.text)).join("").replace(/\s+/g, "");
  if (visible.length < 20 && !parts.some((p) => p.field === "attachment")) {
    const s = findings.filter((f) => f.field === "subject" && LIFTED.has(f.category) && real(f) && rank(f.severity) >= rank("medium")).sort((a, b) => rank(b.severity) - rank(a.severity))[0];
    if (s) out.push(at(s, "critical", `${s.reason} — in the subject of an email with a near-empty body`, ["subject", "body"]));
  }
  // 2. one fake turn split over two or more parts, one marker high or more
  const roles = findings.filter((f) => f.category === "role-spoofing" && real(f));
  const keys = [...new Set(roles.map(partKey))];
  if (keys.length >= 2 && roles.some((f) => rank(f.severity) >= rank("high"))) {
    const top = roles.slice().sort((a, b) => rank(b.severity) - rank(a.severity))[0];
    out.push(at(top, "critical", `Fake chat turn split over ${keys.join(", ")}`, keys));
  }
  // 3. an address hidden in lookalike letters in one part and written plainly in another
  const addressOf = (f: Finding) => (f.category === "homoglyph" ? (f.meta?.address as string | undefined) : undefined);
  const addresses = [...new Set(findings.map(addressOf).filter((a): a is string => !!a).map((a) => a.toLowerCase()))];
  const holding = addresses.length ? textsHolding(addresses, parts.map((p) => p.text.toLowerCase())) : [];
  const holders = new Map(addresses.map((a, i) => [a, holding[i]]));
  for (const f of findings) {
    const address = addressOf(f);
    if (!address) continue;
    const i = holders.get(address.toLowerCase())!.find((j) => !(parts[j].field === f.field && parts[j].attachment === f.attachment && parts[j].header === f.meta?.header));
    const other = i === undefined ? undefined : parts[i];
    if (other) {
      out.push(at(f, "high", `Address ${address} hidden in lookalike letters here and written plainly in the ${other.field}`, [partKey(f), other.field]));
      break;
    }
  }
  return out;
}

// Headers are hidden from the reader, and nothing in them is addressed to an agent: instructions, role markers and
// authority markers there are critical. Signature and trace headers carry cryptographic base64, not text.
const SKIPPED_HEADERS = /^(dkim-signature|domainkey-signature|x-google-dkim-signature|arc-seal|arc-message-signature|arc-authentication-results|authentication-results|received|x-received)$/i;
function liftInHeader(f: Finding): Finding {
  if (!LIFTED.has(f.category) || f.meta?.discussion || f.meta?.pattern === "role-label" || f.severity === "info" || f.severity === "critical") return f;
  return { ...f, severity: "critical", reason: `${f.reason} — in a header, hidden from the reader` };
}

// A display name that holds an address other than the real one claims to be someone it is not. Lookalike letters
// are folded first, so a fullwidth or Cyrillic address in the name counts too.
const ADDRESS_IN_NAME = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
function displayNameSpoof(value: string): Finding | undefined {
  const da = displayAndAddress(value);
  if (!da || !da.display) return undefined;
  const claimed = ADDRESS_IN_NAME.exec(foldText(da.display)?.folded ?? da.display)?.[0];
  if (!claimed || claimed.toLowerCase() === da.address.toLowerCase()) return undefined;
  const start = Math.max(0, value.indexOf(da.display));
  return {
    id: "metadata",
    category: "metadata",
    severity: "high",
    start,
    end: start + da.display.length,
    excerpt: makeExcerpt(value, start, start + da.display.length, 12),
    reason: `Display name claims to be ${claimed}, but the message comes from ${da.address}: check the real sender before trusting it`,
    meta: { claimed, address: da.address },
  };
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const k = `${f.category}|${f.start}|${f.end}|${f.reason}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

function rank(s: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}
