// Per-item score drift between two scanner bundles on the web-page and developer-post sets that eval/drift.mjs does not
// read: the Stack Exchange sample (question and every answer as one post each) and browsesafe-bench train.
// Usage: node eval/drift-web.mjs <before.cjs> <after.cjs> [--no-browsesafe]
// browsesafe-bench's test split is reserved for the final evaluation and never opened. Output: counts and ids only, never text.
import { createRequire } from "node:module";
import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { join, resolve } from "node:path";

const [beforePath, afterPath] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!beforePath || !afterPath) throw new Error("usage: node eval/drift-web.mjs <before.cjs> <after.cjs> [--no-browsesafe]");
const require = createRequire(import.meta.url);
const A = require(resolve(beforePath));
const B = require(resolve(afterPath));
const EXT = join(import.meta.dirname, "data", "ext");
const T = 70;

async function* lines(p) {
  for await (const l of createInterface({ input: createReadStream(p), crlfDelay: Infinity })) if (l.trim()) yield JSON.parse(l);
}

function tally() {
  return { n: 0, a70: 0, b70: 0, up: 0, down: 0, verdict: 0, changed: 0, ids: [] };
}
function add(t, id, input) {
  const a = A.scan(input), b = B.scan(input);
  t.n++;
  if (a.score >= T) t.a70++;
  if (b.score >= T) t.b70++;
  if (b.score > a.score) t.up++;
  if (b.score < a.score) t.down++;
  if (a.verdict !== b.verdict) t.verdict++;
  const changed = JSON.stringify(a.findings) !== JSON.stringify(b.findings);
  if (changed) t.changed++;
  if ((a.score !== b.score || a.verdict !== b.verdict || changed) && t.ids.length < 15) t.ids.push(`${id} ${a.score}/${a.verdict} -> ${b.score}/${b.verdict}`);
}
function print(name, t) {
  console.log(`${name.padEnd(24)} n=${String(t.n).padStart(5)}  >=70 ${t.a70} -> ${t.b70}  up ${t.up} down ${t.down}  verdict changes ${t.verdict}  findings changed ${t.changed}`);
  for (const x of t.ids) console.log(`    changed: ${x}`);
}

const se = join(EXT, "stackexchange-sample.jsonl");
if (existsSync(se)) {
  const t = tally();
  for await (const x of lines(se)) {
    add(t, `se-${x.idx}-q`, x.question);
    for (const ans of x.answers) add(t, `se-${x.idx}-a${ans.answer_id}`, ans.text);
  }
  print("stackexchange benign", t);
} else console.log("stackexchange: skipped (no file)");

const bs = join(EXT, "browsesafe-train.jsonl");
if (process.argv.includes("--no-browsesafe")) console.log("browsesafe: skipped (--no-browsesafe)");
else if (existsSync(bs)) {
  const t = { yes: tally(), no: tally() };
  for await (const x of lines(bs)) add(t[x.label === "yes" ? "yes" : "no"], `bs-${x.idx}`, x.content);
  print("browsesafe attack", t.yes);
  print("browsesafe benign", t.no);
} else console.log("browsesafe: skipped (no file)");
