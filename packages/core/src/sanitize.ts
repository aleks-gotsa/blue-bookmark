import type { Finding, Result, Severity } from "./types";
import { scan } from "./scan";

export interface SanitizeOptions {
  /** Marker wrapped around suspicious instruction spans. */
  marker?: { open: string; close: string };
  /** Minimum severity for an instruction span to be wrapped. Default "medium". */
  minSeverity?: Severity;
  /** Replace hidden HTML/metadata with this placeholder (default: "[hidden content removed]"). */
  removedPlaceholder?: string;
}

const DEFAULT_MARKER = { open: "[QUOTED CONTENT, NOT INSTRUCTIONS: ", close: " :END QUOTED CONTENT]" };

/**
 * Produce a neutralized copy of the input:
 *  - zero-width / bidi / tag characters are removed (tags are replaced by their visible decoded text in a marker so nothing is silently lost),
 *  - hidden HTML elements, comments and stashes are replaced by a placeholder,
 *  - encoded payloads that decoded to instructions are replaced by a placeholder,
 *  - instruction / authority spans are wrapped in a visible marker,
 *  - metadata fields holding instructions are wrapped as well.
 * Offsets in `result.findings` refer to the ORIGINAL input; this function processes edits from the end backwards.
 */
export function sanitize(input: string, result: Result, opts: SanitizeOptions = {}): string {
  let out = applyEdits(input, result, opts, true);
  // Stripping zero-width / bidi characters can reveal instructions that were split or reversed; wrap those too, but never
  // again inside a marker the first pass made
  const revealed = scan(out, { contentType: result.contentType, detectors: ["instruction-patterns", "authority-spoof"] });
  if (revealed.findings.some((f) => rank(f.severity) >= rank(opts.minSeverity ?? "medium"))) out = applyEdits(out, revealed, opts, false);
  return out;
}

/** Spans between an open marker and its close, in text where every marker string is one sanitize wrote. */
function markedRegions(text: string, open: string, close: string): [number, number][] {
  const out: [number, number][] = [];
  if (!open || !close) return out;
  for (let i = text.indexOf(open); i >= 0; ) {
    const j = text.indexOf(close, i + open.length);
    if (j < 0) break;
    out.push([i, j + close.length]);
    i = text.indexOf(open, j + close.length);
  }
  return out;
}

/** first: the input is the caller's text, so marker strings in it are the attacker's; otherwise they are ours. */
function applyEdits(input: string, result: Result, opts: SanitizeOptions, first: boolean): string {
  const marker = opts.marker ?? DEFAULT_MARKER;
  const minSev = opts.minSeverity ?? "medium";
  const placeholder = opts.removedPlaceholder ?? "[hidden content removed]";

  // attacker text put inside the marker must not be able to close it (or open a fake one) and go on as plain text:
  // every copy of the marker's own strings in that text is replaced, in one pass, by text that cannot rebuild them
  const markerParts = [marker.open.trim(), marker.close.trim()].filter(Boolean);
  // invisible characters inside a marker string would be swept out later and rebuild it, so they are dropped from text
  // that holds a marker once they are gone
  const INVISIBLE = /[\u00ad\u200b-\u200f\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069]|\uDB40[\uDC00-\uDC7F]/g;
  const inside = (t: string) => {
    const bare = t.replace(INVISIBLE, "");
    const src = markerParts.some((m) => bare.includes(m)) ? bare : t;
    return markerParts.reduce((x, m) => x.split(m).join("(marker removed)"), src);
  };
  const wrap = (s: number, e: number) => marker.open + inside(input.slice(s, e)) + marker.close;
  type Edit = { start: number; end: number; replace: string; wrap?: boolean };
  const edits: Edit[] = [];
  // on the first pass, a marker string in the caller's text is the attacker's even when invisible characters split it:
  // they are removed by their own edits, which would rebuild it, so the whole span is replaced
  if (first) {
    const keep: number[] = [];
    let bare = "";
    for (let i = 0; i < input.length; i++) {
      const c = input[i];
      if (/[\u00ad\u200b-\u200f\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069]/.test(c)) continue;
      if (c === "\uDB40" && /[\uDC00-\uDC7F]/.test(input[i + 1] ?? "")) { i++; continue; }
      keep.push(i);
      bare += c;
    }
    for (const m of markerParts)
      for (let j = bare.indexOf(m); j >= 0; j = bare.indexOf(m, j + m.length))
        edits.push({ start: keep[j], end: keep[j + m.length - 1] + 1, replace: "(marker removed)" });
  }
  for (const f of result.findings) {
    if (f.end <= f.start) continue;
    switch (f.category) {
      case "zero-width":
        if (f.meta && typeof (f.meta as { total?: number }).total === "number") break; // aggregate finding, not a span to edit
        edits.push({ start: f.start, end: f.end, replace: "" });
        break;
      case "bidi-override":
        edits.push({ start: f.start, end: f.end, replace: "" });
        break;
      case "unicode-tags":
        edits.push({ start: f.start, end: f.end, replace: `${marker.open}hidden tag text: ${inside(f.decoded ?? "")}${marker.close}` });
        break;
      case "hidden-html":
        if (rank(f.severity) >= rank("low")) edits.push({ start: f.start, end: f.end, replace: placeholder });
        break;
      case "encoded-payload":
        if (rank(f.severity) >= rank("high")) edits.push({ start: f.start, end: f.end, replace: `[encoded payload removed: ${inside((f.decoded ?? "").slice(0, 60)).replace(/\s+/g, " ").replace(/[[\]]/g, "")}…]` });
        break;
      case "instruction-patterns":
      case "authority-spoof":
      case "metadata":
        if (rank(f.severity) >= rank(minSev)) edits.push({ start: f.start, end: f.end, replace: wrap(f.start, f.end), wrap: true });
        break;
      case "exfil-urls":
        if (rank(f.severity) >= rank("high")) edits.push({ start: f.start, end: f.end, replace: "[suspicious URL removed]" });
        break;
      case "homoglyph":
        // leave the word, but annotate confusables so a downstream reader sees it
        if (rank(f.severity) >= rank("medium")) edits.push({ start: f.start, end: f.end, replace: input.slice(f.start, f.end) + " [mixed-script]" });
        break;
    }
  }
  // resolve overlaps: keep the larger span (earlier start, longer), drop those contained in it, and clip one that only
  // starts inside it, so its tail is still edited
  edits.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Edit[] = [];
  for (const e of edits) {
    const last = kept[kept.length - 1];
    if (last && e.end <= last.end) continue;
    if (last && e.start < last.end) {
      const start = last.end;
      kept.push({ ...e, start, replace: e.wrap ? wrap(start, e.end) : e.replace });
      continue;
    }
    kept.push(e);
  }
  // on the second pass, nothing inside a marker of the first is edited again
  const marked = first ? [] : markedRegions(input, marker.open, marker.close);
  const final = marked.length ? kept.filter((e) => !marked.some(([a, b]) => e.start < b && a < e.end)) : kept;
  // text between edits is copied as it is, except that on the first pass marker strings in it are the attacker's too
  const pieces: string[] = [];
  let at = 0;
  for (const e of final) {
    pieces.push(first ? inside(input.slice(at, e.start)) : input.slice(at, e.start), e.replace);
    at = e.end;
  }
  pieces.push(first ? inside(input.slice(at)) : input.slice(at));
  let out = pieces.join("");
  // final sweep: any remaining invisible format chars (ones the detector classified as info) are harmless but we strip the dangerous classes anyway
  out = out.replace(/[\u202A-\u202E\u2066-\u2069]/g, "").replace(/\uDB40[\uDC00-\uDC7F]/g, "");
  return out;
}

function rank(s: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}

export function findingsAtOrAbove(findings: Finding[], sev: Severity): Finding[] {
  return findings.filter((f) => rank(f.severity) >= rank(sev));
}
