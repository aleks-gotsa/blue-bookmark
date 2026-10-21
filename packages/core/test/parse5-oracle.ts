// The reference for hidden-html: parse5 builds the tree the browser builds, and this small oracle decides
// whether a marker word is hidden from a reader. Tests only; parse5 never ships.
import { parse } from "parse5";
import { scan } from "../src";

export const MARK = "QQZXMARK";
export type Where = "hidden" | "visible" | "attribute" | "absent";

// elements whose content a reader never sees (scripting on, as in a browser)
const NOT_RENDERED = new Set(["script", "style", "template", "noscript", "noembed", "noframes", "iframe", "title", "head"]);

/** Inline display:none or visibility:hidden; parse5 has already decoded entities, CSS comments are dropped here. */
function styleHides(value: string): boolean {
  return value
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .toLowerCase()
    .split(";")
    .some((decl) => {
      const at = decl.indexOf(":");
      if (at < 0) return false;
      const key = decl.slice(0, at).trim();
      const val = decl.slice(at + 1).trim();
      return (key === "display" && /^none\b/.test(val)) || (key === "visibility" && /^hidden\b/.test(val));
    });
}

interface Node {
  nodeName: string;
  tagName?: string;
  value?: string;
  data?: string;
  attrs?: { name: string; value: string }[];
  childNodes?: Node[];
  content?: Node;
}

/** Where the browser puts the marker: shown, hidden from a reader, or only inside an attribute value. */
export function oracle(html: string): Where {
  let where: Where = "absent";
  const seen = (w: Where) => {
    // shown anywhere beats hidden; hidden beats attribute-only
    if (where === "visible" || (where === "hidden" && w === "attribute")) return;
    where = w;
  };
  const walk = (n: Node, hidden: boolean) => {
    if (n.nodeName === "#comment") {
      if (n.data?.includes(MARK)) seen("hidden");
      return;
    }
    if (n.nodeName === "#text") {
      if (n.value?.includes(MARK)) seen(hidden ? "hidden" : "visible");
      return;
    }
    let h = hidden;
    if (n.tagName) {
      if (NOT_RENDERED.has(n.tagName)) h = true;
      for (const a of n.attrs ?? []) {
        if (a.name === "hidden" || (a.name === "style" && styleHides(a.value))) h = true;
        if (a.value.includes(MARK)) seen("attribute");
      }
    }
    for (const c of n.childNodes ?? []) walk(c, h);
    if (n.content) walk(n.content, true);
  };
  walk(parse(html, { scriptingEnabled: true }) as unknown as Node, false);
  return where;
}

/**
 * What hidden-html says about the marker: in the text a hidden-html finding reports as hidden, or not. The text, not
 * the finding's source range: a hidden table's range also covers text foster-parented out of it.
 */
export function ours(html: string): "hidden" | "visible" {
  const r = scan(html, { contentType: "html" });
  return r.findings.some((f) => f.category === "hidden-html" && (f.decoded ?? "").includes(MARK)) ? "hidden" : "visible";
}

export type Outcome = "agree" | "miss" | "false-hidden" | "attribute";
export function compare(html: string): Outcome {
  const o = oracle(html);
  const u = ours(html);
  if (o === "attribute") return "attribute";
  if (o === "hidden" && u !== "hidden") return "miss";
  if (o === "visible" && u === "hidden") return "false-hidden";
  return "agree";
}

// The shapes both differential tests use. Every shape wraps one marker sentence.
// longer than 80 characters and not imperative: every reading path reports it, so the test checks reading, not rating
export const P = `the quarterly report ${MARK} is attached here for everyone on the team to read before the meeting on Monday`;

export interface Shape {
  wrap: (p: string) => string;
  expect: Outcome;
  /** the HTML-reader module that closes a disagreement */
  owner?: string;
}

export const SHAPES: Record<string, Shape> = {
  "hidden attribute": { wrap: (p) => `<div hidden>${p}</div>`, expect: "agree" },
  "display none": { wrap: (p) => `<div style="display:none">${p}</div>`, expect: "agree" },
  "comment inside a hidden element": { wrap: (p) => `<div hidden><!-- c -->${p}</div>`, expect: "agree" },
  "visible element inside a hidden one": { wrap: (p) => `<div hidden><div style="display:block">${p}</div></div>`, expect: "agree" },
  "template": { wrap: (p) => `<template>${p}</template>`, expect: "agree" },
  "noscript": { wrap: (p) => `<noscript>${p}</noscript>`, expect: "agree" },
  "stray < before a hidden span": { wrap: (p) => `a < b <span hidden>${p}</span>`, expect: "agree" },
  "unclosed hidden element": { wrap: (p) => `<span style="display:none">${p}`, expect: "agree" },
  "select option": { wrap: (p) => `<select><option>${p}</option></select>`, expect: "agree" },
  "visible paragraph": { wrap: (p) => `<p>${p}</p>`, expect: "agree" },
  "visible after a hidden sibling": { wrap: (p) => `<span hidden>x</span><p>${p}</p>`, expect: "agree" },

  "bogus comment <!x": { wrap: (p) => `<!x ${p}>`, expect: "agree" },
  "bogus comment <?x": { wrap: (p) => `<?x ${p}>`, expect: "agree" },
  "bogus close </ x": { wrap: (p) => `</ x ${p}>`, expect: "agree" },
  "close tag swallowed by a bogus comment": { wrap: (p) => `<div hidden>x<?</div>${p}</div>`, expect: "agree" },
  "named entity in style": { wrap: (p) => `<div style="display&colon;none">${p}</div>`, expect: "agree" },
  "numeric entity in style": { wrap: (p) => `<div style="display:&#110;one">${p}</div>`, expect: "agree" },
  "noembed": { wrap: (p) => `<noembed>${p}</noembed>`, expect: "agree" },
  "noframes": { wrap: (p) => `<noframes>${p}</noframes>`, expect: "agree" },
  "iframe text": { wrap: (p) => `<iframe>${p}</iframe>`, expect: "agree" },
  "plaintext": { wrap: (p) => `<plaintext><div hidden>${p}</div>`, expect: "agree" },
  "self-closing div": { wrap: (p) => `<div hidden/>${p}`, expect: "agree" },
  // by design: style text is CSS, rated only when it holds an instruction
  "svg style text": { wrap: (p) => `<svg><style>${p}</style></svg>`, expect: "miss", owner: "by design" },
  "ancestor end tag closes a hidden child": { wrap: (p) => `<div><span hidden>secret</div>${p}`, expect: "agree" },
  "implicit p close": { wrap: (p) => `<p style="display:none">hidden start<div>${p}</div>`, expect: "agree" },
  "hidden element inside a select option": { wrap: (p) => `<select><option><span hidden>${p}</span></option></select>`, expect: "agree" },
  "table foster parenting": { wrap: (p) => `<table hidden><tr><td>cell</td></tr>${p}</table>`, expect: "agree" },
};

export const PRE = ["", "<p>Hello team,</p>", "<html><body><h1>News</h1>", "Plain intro line. "];
export const POST = ["", "<p>Thanks</p>", "</body></html>", " More text after."];


export interface Run {
  start: number;
  end: number;
  hidden: boolean;
}
/** Every text node with letters, with its source range and whether the browser hides it (same rules as oracle()). */
export function oracleRuns(html: string): Run[] {
  const out: Run[] = [];
  const walk = (n: Node & { sourceCodeLocation?: { startOffset: number; endOffset: number } }, hidden: boolean) => {
    if (n.nodeName === "#comment") return;
    if (n.nodeName === "#text") {
      const loc = n.sourceCodeLocation;
      if (loc && /[\p{L}\p{N}]/u.test(n.value ?? "")) out.push({ start: loc.startOffset, end: loc.endOffset, hidden });
      return;
    }
    let h = hidden;
    if (n.tagName) {
      if (NOT_RENDERED.has(n.tagName)) h = true;
      for (const a of n.attrs ?? []) if (a.name === "hidden" || (a.name === "style" && styleHides(a.value))) h = true;
    }
    for (const c of n.childNodes ?? []) walk(c, h);
    if (n.content) walk(n.content, true);
  };
  walk(parse(html, { scriptingEnabled: true, sourceCodeLocationInfo: true }) as unknown as Node, false);
  return out;
}
