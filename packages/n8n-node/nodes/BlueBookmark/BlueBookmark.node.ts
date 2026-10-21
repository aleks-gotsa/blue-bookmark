import type {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from "n8n-workflow";
import { NodeConnectionTypes, NodeOperationError } from "n8n-workflow";
import { scan, sanitize, VERSION } from "@blue-bookmark/core";
import type { ContentType, EmailInput, Result } from "@blue-bookmark/core";

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** The Email input's expressions as an EmailInput; empty or missing parts are left out. */
function emailInputOf(get: (name: string) => unknown): EmailInput {
  const headers = get("emailHeaders");
  const attachments = get("emailAttachments");
  const list = Array.isArray(attachments) ? attachments : attachments && typeof attachments === "object" ? [attachments] : [];
  return {
    subject: str(get("emailSubject")),
    body: str(get("emailBody")),
    html: str(get("emailHtml")),
    headers: typeof headers === "string" || (headers && typeof headers === "object" && !Array.isArray(headers)) ? (headers as EmailInput["headers"]) : undefined,
    attachments: list
      .filter((a): a is Record<string, unknown> => !!a && typeof a === "object")
      .map((a) => ({ name: str(a.name), text: typeof a.text === "string" ? a.text : "" })),
  };
}

function hasContent(e: EmailInput): boolean {
  return !!(e.subject || e.body || e.html || e.headers || e.attachments?.some((a) => a.text || a.name));
}

/** Strip Hidden Content per part: each part cleaned with its own findings, offsets inside that part. */
function sanitizeEmail(e: EmailInput, result: Result) {
  const part = (text: string | undefined, keep: (f: Result["findings"][number]) => boolean, contentType: Result["contentType"]) =>
    text ? sanitize(text, { ...result, contentType, findings: result.findings.filter(keep) }) : text;
  const typeOf = (field: string, attachment?: number) => result.fields?.find((f) => f.field === field && f.attachment === attachment)?.contentType ?? "text";
  return {
    subject: part(e.subject, (f) => f.field === "subject", "text"),
    body: part(e.body, (f) => f.field === "body", typeOf("body")),
    html: part(e.html, (f) => f.field === "html", "html"),
    attachments: (e.attachments ?? []).map((a, i) => ({ name: a.name, text: part(a.text, (f) => f.field === "attachment" && f.attachment === i && f.meta?.part !== "name", typeOf("attachment", i)) })),
  };
}

type Mode = "score" | "passFail";

// Decoded text is cut in the output: a whole decoded payload would travel with the item to whatever reads it next.
const cut = (t: string, n: number) => (t.length > n ? t.slice(0, n) + "…" : t);

export class BlueBookmark implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Blue Bookmark",
    name: "blueBookmark",
    icon: "file:blueBookmark.svg",
    group: ["transform"],
    version: 1,
    subtitle: '={{$parameter["mode"] === "passFail" ? "Pass / Fail · threshold " + $parameter["threshold"] : "Score only"}}',
    description:
      "Static scanner for hidden and indirect prompt-injection content (invisible Unicode, hidden HTML, encoded payloads, agent-directed instructions) before a document reaches an AI agent. Offline, no LLM call.",
    defaults: { name: "Blue Bookmark" },
    inputs: [NodeConnectionTypes.Main],
    // Like n8n's native Guardrails node: one output in Score mode, "Pass" and "Fail" outputs in Pass/Fail mode.
    outputs: `={{ $parameter["mode"] === "passFail" ? [{ type: "main", displayName: "Pass" }, { type: "main", displayName: "Fail" }] : [{ type: "main", displayName: "Output" }] }}`,
    properties: [
      {
        displayName: "Input",
        name: "inputType",
        type: "options",
        default: "text",
        options: [
          { name: "Text", value: "text", description: "One text field (Source)" },
          { name: "Email", value: "email", description: "The parts of a message: subject, plain text, HTML, headers, attachments" },
        ],
        description: "Email scans each part on its own, reads headers and attachment names, and looks for attacks split across parts",
      },
      {
        displayName: "Subject",
        name: "emailSubject",
        type: "string",
        default: "={{ $json.subject }}",
        displayOptions: { show: { inputType: ["email"] } },
      },
      {
        displayName: "Body (Plain Text)",
        name: "emailBody",
        type: "string",
        default: "={{ $json.text ?? $json.textPlain }}",
        displayOptions: { show: { inputType: ["email"] } },
      },
      {
        displayName: "HTML",
        name: "emailHtml",
        type: "string",
        default: "={{ $json.html ?? $json.textHtml }}",
        displayOptions: { show: { inputType: ["email"] } },
      },
      {
        displayName: "Headers",
        name: "emailHeaders",
        type: "json",
        default: "={{ $json.headers }}",
        description: "An object of header values, or the raw header block",
        displayOptions: { show: { inputType: ["email"] } },
      },
      {
        displayName: "Attachments",
        name: "emailAttachments",
        type: "json",
        default: "={{ [] }}",
        description: "An array of { name, text }; extract the text with a previous node (binary files are not read here)",
        displayOptions: { show: { inputType: ["email"] } },
      },
      {
        displayName: "Source",
        name: "source",
        type: "string",
        default: "={{ $json.text }}",
        required: true,
        description: "The text, HTML or Markdown to scan. Use an expression to point at the field that holds the document.",
        typeOptions: { rows: 2 },
        displayOptions: { show: { inputType: ["text"] } },
      },
      {
        displayName: "Content Type",
        name: "contentType",
        type: "options",
        default: "auto",
        options: [
          { name: "Auto-Detect", value: "auto" },
          { name: "Plain Text", value: "text" },
          { name: "HTML", value: "html" },
          { name: "Markdown", value: "markdown" },
        ],
        description: "How to interpret the source. HTML enables hidden-element and comment detection.",
        displayOptions: { show: { inputType: ["text"] } },
      },
      {
        displayName: "Mode",
        name: "mode",
        type: "options",
        default: "score",
        options: [
          { name: "Score Only", value: "score", description: "One output; every item gets a guard object" },
          { name: "Pass / Fail", value: "passFail", description: "Two outputs; items at or above the threshold go to Fail" },
        ],
      },
      {
        displayName: "Threshold",
        name: "threshold",
        type: "number",
        default: 50,
        typeOptions: { minValue: 0, maxValue: 100, numberPrecision: 0 },
        description: "Score (0–100) at or above which an item is routed to the Fail output",
        displayOptions: { show: { mode: ["passFail"] } },
      },
      {
        displayName: "Decode Base64",
        name: "decodeBase64",
        type: "boolean",
        default: true,
        description: "Whether to decode base64 / hex / ROT13 blobs and scan the decoded text for instructions",
      },
      {
        displayName: "Strip Hidden Content",
        name: "stripHidden",
        type: "boolean",
        default: false,
        description: "Whether to add a sanitized copy of the document (invisible characters removed, hidden HTML stripped, suspicious instructions wrapped in a visible marker) as guard.sanitized",
      },
      {
        displayName: "Options",
        name: "options",
        type: "collection",
        placeholder: "Add option",
        default: {},
        options: [
          {
            displayName: "Output Field",
            name: "outputField",
            type: "string",
            default: "guard",
            description: "Name of the field that receives the scan result",
          },
          {
            displayName: "Max Findings",
            name: "maxFindings",
            type: "number",
            default: 100,
            description: "Cap the findings array in the output (the score always uses all findings)",
          },
          {
            displayName: "Continue on Empty Source",
            name: "allowEmpty",
            type: "boolean",
            default: true,
            description: "Whether an empty or missing source should pass through with score 0 instead of throwing",
          },
        ],
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const mode = this.getNodeParameter("mode", 0) as Mode;
    const pass: INodeExecutionData[] = [];
    const fail: INodeExecutionData[] = [];
    // An item whose scan did not complete. It carries no score, so a downstream `score >= threshold` check cannot read it as clean.
    const errorItem = (i: number, message: string, reason = "scan_error"): INodeExecutionData => {
      const options = this.getNodeParameter("options", i, {}) as { outputField?: string };
      const guard = { verdict: "error", reason, error: message, version: VERSION };
      return { json: { ...items[i].json, [options.outputField || "guard"]: guard, error: message }, binary: items[i].binary, pairedItem: { item: i } };
    };

    for (let i = 0; i < items.length; i++) {
      try {
        const inputType = this.getNodeParameter("inputType", i, "text") as "text" | "email";
        const decodeBase64 = this.getNodeParameter("decodeBase64", i) as boolean;
        const stripHidden = this.getNodeParameter("stripHidden", i) as boolean;
        const threshold = mode === "passFail" ? (this.getNodeParameter("threshold", i) as number) : 50;
        // `score >= NaN` is always false, so a broken threshold expression would send every item to Pass
        if (typeof threshold !== "number" || !Number.isFinite(threshold)) {
          throw new NodeOperationError(this.getNode(), `Threshold must be a number, got ${String(threshold)}`, { itemIndex: i });
        }
        const options = this.getNodeParameter("options", i, {}) as { outputField?: string; maxFindings?: number; allowEmpty?: boolean };
        const field = options.outputField || "guard";
        const maxFindings = options.maxFindings ?? 100;

        // Text: one Source field, as before. Email: the parts of a message, each scanned on its own.
        let text = "";
        let email: EmailInput | undefined;
        if (inputType === "email") {
          email = emailInputOf((name) => this.getNodeParameter(name, i, undefined));
          if (!hasContent(email) && options.allowEmpty === false) throw new NodeOperationError(this.getNode(), "Email is empty", { itemIndex: i });
        } else {
          const raw = this.getNodeParameter("source", i, "");
          text = raw == null ? "" : typeof raw === "string" ? raw : JSON.stringify(raw);
          if (!text && options.allowEmpty === false) {
            throw new NodeOperationError(this.getNode(), "Source is empty", { itemIndex: i });
          }
        }

        const result: Result = email ? scan(email, { decodeBase64 }) : scan(text, { contentType: this.getNodeParameter("contentType", i) as ContentType, decodeBase64 });
        if (result.error) {
          // Pass / Fail has a Fail output for this; Score Only has nowhere safe to put it, so it stops (see catch below)
          if (mode === "passFail") {
            fail.push(errorItem(i, `${result.error.reason}: ${result.error.message}`, result.error.reason));
            continue;
          }
          throw new NodeOperationError(this.getNode(), `${result.error.reason}: ${result.error.message}`, { itemIndex: i });
        }
        const guard: Record<string, unknown> = {
          score: result.score,
          verdict: result.verdict,
          contentType: result.contentType,
          findings: result.findings.slice(0, maxFindings).map((f) => ({
            id: f.id,
            category: f.category,
            severity: f.severity,
            start: f.start,
            end: f.end,
            excerpt: f.excerpt,
            reason: f.reason,
            ...(f.decoded ? { decoded: cut(f.decoded, 1000) } : {}),
            ...(f.field ? { field: f.field } : {}),
            ...(f.attachment !== undefined ? { attachment: f.attachment } : {}),
            ...(f.meta?.header ? { header: f.meta.header } : {}),
            ...(f.meta?.part ? { part: f.meta.part } : {}),
          })),
          ...(result.fields ? { fields: result.fields.slice(0, 100) } : {}),
          summary: result.summary,
          provenance: result.provenance,
          durationMs: result.durationMs,
          version: result.version,
        };
        if (mode === "passFail") guard.threshold = threshold;
        if (stripHidden) guard.sanitized = email ? sanitizeEmail(email, result) : sanitize(text, result);

        const out: INodeExecutionData = {
          json: { ...items[i].json, [field]: guard },
          binary: items[i].binary,
          pairedItem: { item: i },
        };
        if (mode === "passFail" && result.score >= threshold) fail.push(out);
        else pass.push(out);
      } catch (error) {
        // Fail closed. Without Continue On Fail the execution stops. With it, the item never reaches Pass:
        // Pass / Fail routes it to Fail; Score Only marks it verdict "error" with no score, because
        // n8n would otherwise pass the unscanned input straight through.
        if (this.continueOnFail()) {
          (mode === "passFail" ? fail : pass).push(errorItem(i, (error as Error).message, /^too_large:/.test((error as Error).message) ? "too_large" : "scan_error"));
          continue;
        }
        throw error;
      }
    }
    return mode === "passFail" ? [pass, fail] : [pass];
  }
}
