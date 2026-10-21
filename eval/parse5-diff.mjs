// hidden-html against the browser's reading on real pages. parse5 builds the tree with source locations; the
// same oracle as packages/core/test/parse5-oracle.ts marks each text node and comment hidden or visible; each is then
// checked against the spans of hidden-html findings that use the same rules (hidden attribute, display:none,
// visibility:hidden, comments, not-rendered elements), so a difference is one of reading, not of rules: hidden-html's
// other rules (colour, classes, aria-hidden, stylesheets) have no counterpart in the oracle. Script and style text is
// code, not prose, and is skipped. A "miss" also counts hidden text that hidden-html reads but does not report because
// of its rating thresholds (a <title>, a short comment without an imperative); "missed by" shows which. Counts only,
// never text.
// Usage: node eval/parse5-diff.mjs <bundle.cjs> [browsesafe|stackexchange] [max pages]
import { createReadStream } from "node:fs";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";
import { join, resolve } from "node:path";

const [bundle, which = "browsesafe", maxArg] = process.argv.slice(2);
const require = createRequire(join(import.meta.dirname, "..", "packages", "core", "package.json"));
const { parse } = require("parse5");
const L = createRequire(import.meta.url)(resolve(bundle));
const MAX = Number(maxArg ?? 1000);
const MIN = 20; // letters: shorter runs (icons, separators) are not counted

const NOT_RENDERED = new Set(["script", "style", "template", "noscript", "noembed", "noframes", "iframe", "title", "head"]);
const styleHides = (v) => v.replace(/\/\*[\s\S]*?\*\//g, "").toLowerCase().split(";").some((d) => {
  const at = d.indexOf(":");
  const key = d.slice(0, at).trim(), val = d.slice(at + 1).trim();
  return at > 0 && ((key === "display" && /^none\b/.test(val)) || (key === "visibility" && /^hidden\b/.test(val)));
});
// hidden-html findings that rest on a rule the oracle also has
const SAME_RULES = /^(display:none|visibility:hidden|hidden attribute)$|^(HTML comment|Unclosed HTML comment|Comment inside|<(template|noscript|noembed|noframes|iframe|title)> content|<title>)/;
const letters = (s) => (s.match(/[\p{L}\p{N}]/gu) || []).length;

/** Text nodes and comments with their source offsets and whether the browser hides them. */
function runs(html) {
  const out = [];
  const walk = (n, hidden) => {
    const loc = n.sourceCodeLocation;
    if (n.nodeName === "#text" && hidden === "code") return;
    if (n.nodeName === "#comment" || n.nodeName === "#text") {
      const t = n.nodeName === "#comment" ? n.data : n.value;
      if (loc && letters(t) >= MIN) out.push({ start: loc.startOffset, end: loc.endOffset, hidden: Boolean(hidden) || n.nodeName === "#comment", why: n.nodeName === "#comment" ? "comment" : typeof hidden === "string" ? hidden : "", n: letters(t) });
      return;
    }
    let h = hidden;
    if (n.tagName) {
      // h: false, "code", or why the subtree is hidden (the outermost reason wins)
      if (n.tagName === "script" || n.tagName === "style") h = "code";
      else if (!h && NOT_RENDERED.has(n.tagName)) h = `<${n.tagName}>`;
      for (const a of n.attrs ?? []) if (!h && (a.name === "hidden" || (a.name === "style" && styleHides(a.value)))) h = a.name === "hidden" ? "hidden attribute" : "inline style";
    }
    for (const c of n.childNodes ?? []) walk(c, h);
    if (n.content) walk(n.content, h || "<template>");
  };
  walk(parse(html, { scriptingEnabled: true, sourceCodeLocationInfo: true }), false);
  return out;
}

async function* pages() {
  const file = join(import.meta.dirname, "data", "ext", which === "browsesafe" ? "browsesafe-train.jsonl" : "stackexchange-sample.jsonl");
  for await (const l of createInterface({ input: createReadStream(file) })) {
    if (!l.trim()) continue;
    const r = JSON.parse(l);
    if (which === "browsesafe") yield { id: `bs-train-${r.idx}`, label: r.label === "yes" ? "attack" : "benign", html: r.content };
    else {
      yield { id: `se-q${r.qid}`, label: "benign", html: r.question };
      for (const a of r.answers) yield { id: `se-a${a.answer_id}`, label: "benign", html: a.text };
    }
  }
}

const R = {};
const add = (k, v = 1) => (R[k] = (R[k] || 0) + v);
let n = 0;
for await (const p of pages()) {
  if (!p.html || n++ >= MAX) continue;
  const spans = L.scan(p.html, { contentType: "html" }).findings.filter((f) => f.category === "hidden-html" && SAME_RULES.test(f.meta?.hiddenBy ?? f.reason)).map((f) => [f.start, f.end]);
  const ours = (r) => spans.some(([s, e]) => s <= r.start && e >= r.end);
  let miss = 0, falseHidden = 0;
  for (const r of runs(p.html)) {
    if (r.hidden && !ours(r)) miss += r.n, add(`${p.label} missed by: ${r.why}`, r.n);
    if (!r.hidden && ours(r)) falseHidden += r.n;
    add(`${p.label} letters ${r.hidden ? "hidden" : "visible"}`, r.n);
  }
  add(`${p.label} pages`);
  if (miss) add(`${p.label} pages with a miss`), add(`${p.label} letters missed`, miss);
  if (falseHidden) add(`${p.label} pages with false-hidden`), add(`${p.label} letters false-hidden`, falseHidden);
}
for (const k of Object.keys(R).sort()) console.log(`${which} ${k}`.padEnd(48), R[k]);
