import { describe, expect, it } from "vitest";
import { attr, tagsOf, type Tag } from "../src/detectors/hidden-html";
import { buildTree } from "../src/html-tree";
import { expectLinear } from "./linear";
import { P, POST, PRE, SHAPES, oracleRuns } from "./parse5-oracle";

// commit (a): the tree builder alone, run by run against parse5. Every text run
// must be hidden or visible exactly as the browser has it, so a run assigned to the wrong element cannot pass by
// sitting inside some finding.

// the oracle's own hiding rules: the hidden attribute and inline display:none / visibility:hidden
const hides = ({ text: tag }: Tag) => {
  if (attr(tag, "hidden") !== undefined) return "hidden attribute";
  const st = (attr(tag, "style") ?? "").replace(/\/\*[\s\S]*?\*\//g, "").toLowerCase();
  return /(?:^|;)\s*display\s*:\s*none\b|(?:^|;)\s*visibility\s*:\s*hidden\b/.test(st) ? "inline style" : undefined;
};

/**
 * Text runs where the tree and parse5 disagree on hidden or visible. Each of our runs is compared with the narrowest
 * parse5 text node that overlaps it: parse5 merges foster-parented text into the text before the table, so that node's
 * source range spans the whole table and the cells inside it.
 */
function disagreements(html: string): string[] {
  const tree = buildTree(html, tagsOf(html), hides);
  const oracle = oracleRuns(html);
  const out: string[] = [];
  for (const r of tree.runs) {
    if (!/[\p{L}\p{N}]/u.test(html.slice(r.start, r.end))) continue;
    let best: { start: number; end: number; hidden: boolean } | undefined;
    for (const o of oracle) if (o.start < r.end && o.end > r.start && (!best || o.end - o.start < best.end - best.start)) best = o;
    if (!best) continue;
    const hidden = r.hider >= 0;
    if (hidden !== best.hidden) out.push(`${JSON.stringify(html.slice(r.start, r.end).slice(0, 30))}: browser ${best.hidden ? "hidden" : "visible"}, tree ${hidden ? "hidden" : "visible"}`);
  }
  return out;
}

describe("the tree hides what the browser hides", () => {
  for (const [name, s] of Object.entries(SHAPES)) {
    it(name, () => {
      for (const pre of PRE) for (const post of POST) expect(disagreements(pre + s.wrap(P) + post), pre + "|" + post).toEqual([]);
    });
  }
  it.each([
    ["an end tag with nothing open is ignored", (p: string) => `</div><div hidden>${p}</div>`],
    ["li closes an open li", (p: string) => `<ul><li hidden>hidden item<li>${p}</ul>`],
    ["a new cell closes the open one", (p: string) => `<table><tr><td hidden>x<td>${p}</table>`],
    ["svg breaks out on a p", (p: string) => `<svg><g style="display:none"><p>${p}</p></g></svg>`],
    ["self-closing inside svg closes", (p: string) => `<svg><g style="display:none"/><text>${p}</text></svg>`],
    ["text after </body> stays in the body", (p: string) => `<html><body><div hidden>x</div></body>${p}</html>`],
    ["text in head moves to the body", (p: string) => `<html><head>${p}</head><body></body></html>`],
  ])("%s", (_name, wrap) => {
    expect(disagreements(wrap(P))).toEqual([]);
  });
});

describe("seeded fuzz, three levels", () => {
  const n = Number(process.env.DG_FUZZ_N ?? 300);
  it(`${n} nested cases agree with the browser run by run`, () => {
    let seed = 20261021;
    const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
    const names = Object.keys(SHAPES);
    const pick = <T,>(a: T[]) => a[Math.floor(rnd() * a.length)];
    const found: string[] = [];
    for (let i = 0; i < n; i++) {
      const chain = [pick(names), pick(names), pick(names)];
      const html = pick(PRE) + chain.reduceRight((inner, k) => SHAPES[k].wrap(inner), P) + pick(POST);
      const d = disagreements(html);
      if (d.length) found.push(`${chain.join(" > ")}: ${d[0]}`);
    }
    expect([...new Set(found)].slice(0, 10)).toEqual([]);
  });
});

describe("linear", () => {
  const run = (html: string) => buildTree(html, tagsOf(html), hides);
  it("deep nesting", () => expectLinear("deep", (k) => "<div>".repeat(k) + "a" + "</div>".repeat(k), 20_000, run));
  it("many stray end tags", () => expectLinear("stray", (k) => "<div>" + "</span>".repeat(k), 20_000, run));
  it("many implicit p closes", () => expectLinear("p closes", (k) => "<p>a<div>b".repeat(k), 20_000, run));
  it("a long table with foster-parented text", () => expectLinear("foster", (k) => "<table>" + "text<span>x</span>".repeat(k), 20_000, run));
  it("a deep select", () => expectLinear("select", (k) => "<select>" + "<option><span>a".repeat(k), 20_000, run));
  it("many li in nested lists", () => expectLinear("lists", (k) => "<ul><li>a".repeat(k), 20_000, run));
});
