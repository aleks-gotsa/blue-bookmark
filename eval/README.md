# Evaluation scripts

The scripts behind [docs/EVAL.md](../docs/EVAL.md). They run the scanner core directly, offline, and print counts only, never the text of an item. Data goes in `eval/data/`, which git ignores.

| Script | What it does |
|---|---|
| `fetch-hf.mjs` | Downloads a public Hugging Face dataset split into `eval/data/` as JSONL. |
| `run.ts` | Scores a JSONL file of emails and prints detection per tier, false blocks and per-signal counts. |
| `drift.mjs` | Compares two builds of the core item by item on the email sets: what changed, what crossed 70. |
| `drift-web.mjs` | The same on web pages (browsesafe-bench) and developer posts (Stack Exchange). |
| `phase4.mjs` | The final evaluation: scores the set-aside data once, prototype against v1, and refuses a second run. |
| `parse5-diff.mjs` | Compares the HTML reader with parse5, the parser browsers follow, on real pages. |
| `dedupe.js` | Near-duplicate keys, so one email template that differs only by a date counts once. |

Build a core bundle to compare:

```bash
npx esbuild packages/core/src/index.ts --bundle --platform=node --format=cjs --outfile=/tmp/core.cjs
```

The datasets: [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) (Microsoft, MIT), [browsesafe-bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench) (MIT), agentic-prompt-injection-5k and neuralchemy (Hugging Face), and a Stack Exchange sample (CC BY-SA 4.0).
