// Offline eval: runs the scanner core on JSONL (and optionally the test fixtures). No n8n, no network.
// Usage: node eval/run.ts [file.jsonl ...] [--fixtures] [--email]
// --email: each row goes through scan(EmailInput) (subject, body, body_html, attachment_text as their own parts)
// Per-item results (no text, no excerpts) go to eval/data/results-<name>.jsonl; summary goes to stdout.
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { basename, join } from "node:path";
import { scan } from "@blue-bookmark/core";

interface Item {
  id: string;
  tier: string;
  subject?: string;
  body?: string;
  body_html?: string;
  attachment_text?: string;
}

const THRESHOLD = 70;
const ROOT = join(import.meta.dirname, "..");
const DATA = join(ROOT, "eval", "data");

// Same input as the n8n workflow: body_html || body, plus attachment_text. Subject is NOT scanned.
// ponytail: "\n\n" separator is an assumption; attachment_text is empty in the current data so it is unverified.
const textOf = (x: Item) => [x.body_html || x.body, x.attachment_text].filter(Boolean).join("\n\n");

function loadJsonl(path: string): Item[] {
  return readFileSync(path, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

function loadFixtures(): Item[] {
  const dir = join(ROOT, "packages", "core", "test", "fixtures");
  return (["attacks", "benign"] as const).flatMap((sub) =>
    readdirSync(join(dir, sub))
      .sort()
      .map((name) => ({ id: name, tier: sub === "attacks" ? "FX-attack" : "FX-benign", body: readFileSync(join(dir, sub, name), "utf8") })),
  );
}

const EMAIL = process.argv.includes("--email");
const emailOf = (x: Item) => ({ subject: x.subject, body: x.body, html: x.body_html, attachments: x.attachment_text ? [{ text: x.attachment_text }] : [] });

function evaluate(name: string, items: Item[]) {
  const rows = items.map((x) => {
    const r = EMAIL ? scan(emailOf(x)) : scan(textOf(x));
    const signals = r.findings.map((f) => ({ category: f.category, pattern: (f.meta?.pattern as string | undefined) ?? null, severity: f.severity }));
    return { id: x.id, tier: x.tier, score: r.score, verdict: r.verdict, contentType: r.contentType, signals };
  });
  mkdirSync(DATA, { recursive: true });
  writeFileSync(join(DATA, `results-${name}${EMAIL ? "-email" : ""}.jsonl`), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

  const tiers = [...new Set(rows.map((r) => r.tier))].sort();
  console.log(`\n=== ${name} (${rows.length} items) ===`);
  console.log("tier        n   >=70  rate    >=30   hist 0|1-9|10-19|...|90-100");
  for (const t of tiers) {
    const tr = rows.filter((r) => r.tier === t);
    const block = tr.filter((r) => r.score >= THRESHOLD).length;
    const review = tr.filter((r) => r.score >= 30).length;
    const hist = new Array(11).fill(0);
    for (const r of tr) hist[r.score === 0 ? 0 : Math.min(10, Math.floor(r.score / 10) + 1)]++;
    console.log(`${t.padEnd(10)} ${String(tr.length).padStart(3)}  ${String(block).padStart(4)}  ${((100 * block) / tr.length).toFixed(1).padStart(5)}%  ${String(review).padStart(4)}   ${hist.join(" ")}`);
  }
  const attacks = rows.filter((r) => r.tier !== "T0" && r.tier !== "FX-benign");
  const benign = rows.filter((r) => r.tier === "T0" || r.tier === "FX-benign");
  console.log(`attacks >=70: ${attacks.filter((r) => r.score >= THRESHOLD).length}/${attacks.length}   benign FP >=70: ${benign.filter((r) => r.score >= THRESHOLD).length}/${benign.length}`);

  // Items (not findings) per signal and tier; info-level fires are kept on purpose (downgraded findings show up here).
  const counts = new Map<string, Record<string, number>>();
  for (const r of rows) {
    for (const key of new Set(r.signals.map((s) => `${s.category}${s.pattern ? "/" + s.pattern : ""}:${s.severity}`))) {
      const c = counts.get(key) ?? {};
      c[r.tier] = (c[r.tier] ?? 0) + 1;
      counts.set(key, c);
    }
  }
  console.log(`\nsignal (items per tier)${" ".repeat(34)}${tiers.map((t) => t.padStart(10)).join("")}`);
  for (const [key, c] of [...counts].sort((a, b) => a[0].localeCompare(b[0]))) {
    console.log(`${key.padEnd(56)}${tiers.map((t) => String(c[t] ?? "").padStart(10)).join("")}`);
  }
}

const args = process.argv.slice(2);
for (const path of args.filter((a) => !a.startsWith("--"))) evaluate(basename(path, ".jsonl"), loadJsonl(path));
if (args.includes("--fixtures")) evaluate("fixtures", loadFixtures());
