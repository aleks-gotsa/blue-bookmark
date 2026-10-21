export type ContentType = "auto" | "text" | "html" | "markdown";
export type ResolvedContentType = "text" | "html" | "markdown";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Category =
  | "zero-width"
  | "bidi-override"
  | "unicode-tags"
  | "homoglyph"
  | "role-spoofing"
  | "cross-field"
  | "fake-delimiter"
  | "hidden-html"
  | "encoded-payload"
  | "instruction-patterns"
  | "exfil-urls"
  | "authority-spoof"
  | "metadata";

/** "error": the scan did not complete (a detector threw, or the input was over the size cap); the content must not be treated as scanned */
export type Verdict = "ok" | "review" | "block" | "error";

export interface ScanError {
  /** scan_error: a detector or the input reader threw; too_large: the input was over `maxLength` and only its start was read */
  reason: "scan_error" | "too_large";
  /** Ids of the detectors that threw */
  detectors: string[];
  message: string;
}

export interface Finding {
  /** Detector id, e.g. "zero-width" */
  id: string;
  category: Category;
  severity: Severity;
  /** Character offset (UTF-16 code unit) into the ORIGINAL input, inclusive */
  start: number;
  /** Character offset into the ORIGINAL input, exclusive */
  end: number;
  /** Short excerpt of the original text around/at the span (escaped, invisible chars shown as U+XXXX) */
  excerpt: string;
  /** Human-readable reason */
  reason: string;
  /** Optional decoded content (unicode tags, base64, hex, rot13) */
  decoded?: string;
  /** Free-form extra data */
  meta?: Record<string, unknown>;
  /** Which part of an EmailInput the finding is in; offsets are inside that part. Absent for a string input. */
  field?: EmailField;
  /** Index into EmailInput.attachments when field is "attachment" */
  attachment?: number;
}

export type EmailField = "subject" | "body" | "html" | "attachment" | "header";

/** An email as its parts. Every part is optional; each is scanned as its own document. */
export interface EmailInput {
  subject?: string;
  /** text/plain part */
  body?: string;
  /** text/html part */
  html?: string;
  /** Text the caller already extracted from attachments */
  attachments?: { name?: string; text: string }[];
  /** Header values by name (n8n mail nodes), or the raw header block; hidden from the reader, scanned for structure */
  headers?: Record<string, string | string[] | undefined> | string;
}

export interface ScanOptions {
  contentType?: ContentType;
  /** Decode base64 / hex / rot13 blobs and scan the decoded text. Default true. */
  decodeBase64?: boolean;
  /** Restrict to a subset of detectors (by id). Default: all. */
  detectors?: string[];
  /** Max input length to analyse (chars). Longer input is truncated for analysis. Default 2_000_000. */
  maxLength?: number;
}

export interface Provenance {
  /** Declared author/source extracted from metadata (front matter, <meta name="author">, From: header) */
  declaredAuthor?: string;
  declaredSource?: string;
  declaredTitle?: string;
  /** Signals detected in the body that contradict or exceed the declared role */
  detectedSignals: string[];
}

export interface Result {
  score: number;
  verdict: Verdict;
  contentType: ResolvedContentType;
  findings: Finding[];
  /** Per-category max severity and count */
  summary: Record<string, { count: number; maxSeverity: Severity }>;
  provenance: Provenance;
  /** Input length in UTF-16 code units */
  length: number;
  /** Wall-clock milliseconds spent scanning */
  durationMs: number;
  version: string;
  /** Present only when verdict is "error"; score then covers the detectors that did run */
  error?: ScanError;
  /** For an EmailInput: each part with its own score; the verdict comes from `score`, over all parts together */
  fields?: { field: EmailField; attachment?: number; name?: string; header?: string; contentType: ResolvedContentType; length: number; score: number }[];
}

export interface DetectorContext {
  input: string;
  contentType: ResolvedContentType;
  /** An HTML fragment inside plain text or markdown, read by hidden-html in addition to the text view */
  fragment?: boolean;
  options: Required<Pick<ScanOptions, "decodeBase64">> & ScanOptions;
  /** Shared helpers so detectors can reuse the instruction-pattern matcher on decoded text */
  helpers: {
    /** `lineAnchoredOnly`: run only the patterns whose ^ and $ match at line breaks (the `m` flag) */
    matchInstructions(text: string, lineAnchoredOnly?: boolean): InstructionMatch[];
    excerpt(start: number, end: number, pad?: number): string;
  };
}

export interface InstructionMatch {
  start: number;
  end: number;
  pattern: string;
  severity: Severity;
  reason: string;
  /** set when the match exists only after digits and symbols were read as letters */
  folded?: "leet";
}

export interface Detector {
  id: string;
  category: Category;
  /** Default/maximum severity this detector produces, used for docs and UI legends */
  severity: Severity;
  description: string;
  run(ctx: DetectorContext): Finding[];
}
