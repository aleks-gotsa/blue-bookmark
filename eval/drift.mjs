// Per-item score drift between two scanner bundles (CJS builds of packages/core/src/index.ts), over every dev source.
// Usage: node eval/drift.mjs <before.cjs> <after.cjs> [--no-pool]
// Build a bundle: npx esbuild packages/core/src/index.ts --bundle --platform=node --format=cjs --outfile=<out.cjs>
// Sources: dev (string and email path), the test fixtures, the LLMail Phase 2 pool (DG_REDTEAM_DATA; dev and
// final-set keys excluded), and the external train/test splits in eval/data/ext/ (never validation: final set).
// final.jsonl and holdout.jsonl are never opened. Output: counts and ids only, never text.
import { createRequire } from "node:module";
import { createReadStream, existsSync, readFileSync, readdirSync } from "node:fs";
import { createInterface } from "node:readline";
import { join, resolve } from "node:path";
import { md5, nearKey } from "./dedupe.js";

const [beforePath, afterPath] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!beforePath || !afterPath) throw new Error("usage: node eval/drift.mjs <before.cjs> <after.cjs> [--no-pool]");
const require = createRequire(import.meta.url);
const A = require(resolve(beforePath));
const B = require(resolve(afterPath));
const ROOT = join(import.meta.dirname, "..");
const DATA = join(ROOT, "eval", "data");
const T = 70;
const isExfil = (f) => f.category === "instruction-patterns" && f.meta?.pattern === "exfil-send";
const load = (p) => readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

function measure(lib, input) {
  const r = lib.scan(input);
  return { s: r.score, n: lib.computeScore(r.findings.filter((f) => !isExfil(f))), h: JSON.stringify(r.findings) };
}

function report(name, items) {
  const rows = items.map((x) => ({ id: x.id, label: x.label, a: measure(A, x.input), b: measure(B, x.input) }));
  for (const label of [1, 0]) {
    const r = rows.filter((x) => x.label === label);
    if (!r.length) continue;
    const c = (k, v) => r.filter((x) => x[k][v] >= T).length;
    const up = r.filter((x) => x.b.s > x.a.s), down = r.filter((x) => x.b.s < x.a.s);
    const cross = r.filter((x) => (x.a.s >= T) !== (x.b.s >= T));
    console.log(`${(name + (label ? " attack" : " benign")).padEnd(24)} n=${String(r.length).padStart(5)}  >=70 ${c("a", "s")} -> ${c("b", "s")}  (no exfil ${c("a", "n")} -> ${c("b", "n")})  >=30 ${r.filter((x) => x.a.s >= 30).length} -> ${r.filter((x) => x.b.s >= 30).length}  up ${up.length} down ${down.length}  crosses 70 up ${cross.filter((x) => x.b.s >= T).length} down ${cross.filter((x) => x.b.s < T).length}  findings changed ${r.filter((x) => x.a.h !== x.b.h).length}`);
    for (const x of cross.slice(0, 15)) console.log(`    crosses 70: ${x.id} ${x.a.s} -> ${x.b.s} (no exfil ${x.a.n} -> ${x.b.n})`);
    if (!label) for (const x of up.filter((x) => x.b.s >= 30 && x.a.s < 30).slice(0, 15)) console.log(`    benign into review: ${x.id} ${x.a.s} -> ${x.b.s}`);
    for (const x of down.slice(0, 10)) console.log(`    down: ${x.id} ${x.a.s} -> ${x.b.s}`);
  }
}

const textOf = (x) => [x.body_html || x.body, x.attachment_text].filter(Boolean).join("\n\n");
const emailOf = (x) => ({ subject: x.subject, body: x.body, html: x.body_html, attachments: x.attachment_text ? [{ text: x.attachment_text }] : [] });
const dev = load(join(DATA, "dev.jsonl"));
const lab = (x) => (x.tier === "T0" ? 0 : 1);
report("dev string", dev.map((x) => ({ id: x.id, label: lab(x), input: textOf(x) })));
report("dev email", dev.map((x) => ({ id: x.id, label: lab(x), input: emailOf(x) })));

const fx = join(ROOT, "packages", "core", "test", "fixtures");
report("fixtures", ["attacks", "benign"].flatMap((sub) => readdirSync(join(fx, sub)).sort().map((n) => ({ id: n, label: sub === "attacks" ? 1 : 0, input: readFileSync(join(fx, sub, n), "utf8") }))));

const ext = join(DATA, "ext");
for (const name of ["agentic", "neural"]) {
  const items = ["train", "test"].flatMap((split) => {
    const p = join(ext, `${name}-${split}.jsonl`);
    return existsSync(p) ? load(p).map((x) => ({ id: `${name}-${split}-${x.idx}`, label: x.label, input: x.text })) : [];
  });
  if (items.length) report(name, items);
}

if (!process.argv.includes("--no-pool")) {
  const raw = join(process.env.DG_REDTEAM_DATA || "", "raw_submissions_phase2.jsonl");
  if (!process.env.DG_REDTEAM_DATA || !existsSync(raw)) console.log("pool: skipped (set DG_REDTEAM_DATA)");
  else {
    const excl = new Set([...dev.map((x) => nearKey(x.subject, x.body)), ...JSON.parse(readFileSync(join(DATA, "final-keys.json"), "utf8"))]);
    const seen = new Set();
    const items = [];
    for await (const l of createInterface({ input: createReadStream(raw) })) {
      const x = JSON.parse(l);
      if (!/^level[12][k-v]$/.test(x.scenario || "")) continue;
      const subject = (x.subject || "").trim(), body = (x.body || "").trim();
      if (!body || /million|profit forecast/i.test(subject + body)) continue;
      const k = nearKey(subject, body);
      if (excl.has(k) || seen.has(k)) continue;
      seen.add(k);
      items.push({ id: "llm-" + md5(subject, body).slice(0, 10), label: 1, input: { subject, body, html: "", attachments: [] } });
    }
    report("llmail pool", items);
  }
}
