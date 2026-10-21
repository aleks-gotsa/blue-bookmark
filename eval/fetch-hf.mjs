// Fetch rows of a public Hugging Face dataset through the datasets-server API into a JSONL file (eval/data/ is gitignored).
// Usage: node eval/fetch-hf.mjs <dataset> <config> <split> <out.jsonl> [total] [--sample N --seed S]
// --sample takes N rows from evenly spread pages instead of all rows. Only train/test splits that are not reserved.
import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const [ds, config, split, out, totalArg] = args.filter((a, i) => !a.startsWith("--") && !args[i - 1]?.startsWith("--"));
const opt = (k) => { const i = args.indexOf(k); return i < 0 ? undefined : +args[i + 1]; };
const base = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(ds)}&config=${config}&split=${split}`;
async function page(off, len) {
  for (let t = 0; t < 12; t++) {
    const r = await fetch(`${base}&offset=${off}&length=${len}`);
    if (r.ok) return (await r.json());
    await new Promise((s) => setTimeout(s, 3000 * (t + 1)));
  }
  throw new Error("fetch failed at " + off);
}
const first = await page(0, 1);
const total = +(totalArg ?? first.num_rows_total);
const sample = opt("--sample");
const offsets = [];
if (sample) { const pages = Math.ceil(sample / 100), step = Math.floor(total / pages); for (let p = 0; p < pages; p++) offsets.push(p * step + ((opt("--seed") ?? 0) * 7919) % Math.max(1, step - 100)); }
else for (let off = 0; off < total; off += 100) offsets.push(off);
// written page by page: a large set does not fit in one string
writeFileSync(out, "");
let count = 0;
for (const off of offsets) {
  const j = await page(off, 100);
  appendFileSync(out, j.rows.map((r) => JSON.stringify({ idx: r.row_idx, ...r.row }) + "\n").join(""));
  count += j.rows.length;
}
console.log(ds, split, count, "rows of", total);
