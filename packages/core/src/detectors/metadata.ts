import type { Detector, Finding } from "../types";

/**
 * Metadata fields (YAML front matter, HTML <meta>, email-style headers) that carry instructions.
 * Also exports the front-matter parser used for provenance.
 */
export interface FrontMatter {
  start: number;
  end: number;
  fields: { key: string; value: string; start: number; end: number }[];
}

export function parseFrontMatter(input: string): FrontMatter | null {
  const m = /^\uFEFF?(---|\+\+\+)\r?\n([\s\S]*?)\r?\n\1(\r?\n|$)/.exec(input);
  if (!m) return null;
  const bodyStart = m.index + m[1].length + (input[m.index + m[1].length] === "\r" ? 2 : 1);
  const body = m[2];
  const fields: FrontMatter["fields"] = [];
  let offset = bodyStart;
  for (const line of body.split(/\n/)) {
    const lm = /^([A-Za-z_][\w.-]*)\s*[:=]\s*(.*)$/.exec(line.replace(/\r$/, ""));
    if (lm) {
      const vStart = offset + line.indexOf(lm[2], lm[1].length);
      fields.push({ key: lm[1].toLowerCase(), value: lm[2].replace(/^["']|["']$/g, ""), start: vStart, end: vStart + lm[2].length });
    } else if (/^\s+\S/.test(line) && fields.length) {
      // continuation line: append to last field
      const last = fields[fields.length - 1];
      last.value += " " + line.trim();
      last.end = offset + line.length;
    }
    offset += line.length + 1;
  }
  return { start: m.index, end: m.index + m[0].length, fields };
}

export function parseHtmlMeta(input: string): { key: string; value: string; start: number; end: number }[] {
  const out: { key: string; value: string; start: number; end: number }[] = [];
  const re = /<meta\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input))) {
    const tag = m[0];
    const key = /\b(?:name|property|http-equiv|itemprop)\s*=\s*["']?([^"'\s>]+)/i.exec(tag)?.[1]?.toLowerCase();
    const cm = /\bcontent\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    if (!key || !cm) continue;
    const value = cm[2] ?? cm[3] ?? cm[4] ?? "";
    const vStart = m.index + cm.index + cm[0].indexOf(value);
    out.push({ key, value, start: vStart, end: vStart + value.length });
  }
  // first "<title" decides, as with the lazy regex /<title\b[^>]*>([\s\S]*?)<\/title>/i, which re-scanned to the end
  // for every "<title" without a "</title>" (quadratic); each search here runs once
  const open = /<title\b/i.exec(input);
  const gt = open ? input.indexOf(">", open.index + 6) : -1;
  const close = gt >= 0 ? /<\/title>/gi : null;
  if (close) close.lastIndex = gt + 1;
  const c = close?.exec(input);
  if (c) out.push({ key: "title", value: input.slice(gt + 1, c.index).trim(), start: gt + 1, end: c.index });
  return out;
}

export function parseEmailHeaders(input: string): { key: string; value: string; start: number; end: number }[] {
  const out: { key: string; value: string; start: number; end: number }[] = [];
  const head = input.slice(0, 2000);
  const re = /^(From|To|Subject|Reply-To|Sender|X-[\w-]+|Author|Source)\s*:\s*(.+)$/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(head))) {
    const vStart = m.index + m[0].indexOf(m[2]);
    out.push({ key: m[1].toLowerCase(), value: m[2].trim(), start: vStart, end: vStart + m[2].length });
  }
  return out;
}

export const metadata: Detector = {
  id: "metadata",
  category: "metadata",
  severity: "high",
  description: "Front matter, <meta>, <title> and header fields whose values contain agent-directed instructions.",
  run(ctx) {
    const findings: Finding[] = [];
    const fields: { key: string; value: string; start: number; end: number; where: string }[] = [];
    const fm = parseFrontMatter(ctx.input);
    if (fm) for (const f of fm.fields) fields.push({ ...f, where: "front matter" });
    if (ctx.contentType === "html") for (const f of parseHtmlMeta(ctx.input)) fields.push({ ...f, where: "HTML meta" });
    for (const f of parseEmailHeaders(ctx.input)) fields.push({ ...f, where: "header" });

    for (const f of fields) {
      if (f.value.length < 8) continue;
      const instr = ctx.helpers.matchInstructions(f.value);
      const imperative = /^(ignore|disregard|you\s+(are|must|should)|always|never|do\s+not|respond|reply|send|forward|when\s+(you|summar)|if\s+you\s+are|note\s+to|assistant|system)\b/i.test(f.value.trim());
      if (instr.length) {
        findings.push({
          id: "metadata",
          category: "metadata",
          severity: "critical",
          start: f.start,
          end: f.end,
          excerpt: ctx.helpers.excerpt(f.start, f.end),
          reason: `${f.where} field “${f.key}” contains agent-directed instructions (${instr.map((i) => i.pattern).join(", ")})`,
          decoded: f.value,
          meta: { field: f.key, where: f.where },
        });
      } else if (imperative && f.value.length > 20) {
        findings.push({
          id: "metadata",
          category: "metadata",
          severity: "medium",
          start: f.start,
          end: f.end,
          excerpt: ctx.helpers.excerpt(f.start, f.end),
          reason: `${f.where} field “${f.key}” reads as an instruction rather than metadata`,
          decoded: f.value,
          meta: { field: f.key, where: f.where },
        });
      } else if (f.value.length > 400 && !/^(description|summary|abstract|keywords|og:description|twitter:description)$/.test(f.key)) {
        findings.push({
          id: "metadata",
          category: "metadata",
          severity: "low",
          start: f.start,
          end: f.end,
          excerpt: ctx.helpers.excerpt(f.start, f.end),
          reason: `${f.where} field “${f.key}” is unusually long (${f.value.length} chars) for metadata`,
          meta: { field: f.key, where: f.where },
        });
      }
    }
    return findings;
  },
};
