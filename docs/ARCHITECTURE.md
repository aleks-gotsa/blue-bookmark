# Architecture

## The repository

```
packages/core       the scanner: a TypeScript library with no runtime dependencies
packages/n8n-node   the n8n node; the core is bundled into its build, so it has no dependencies either
apps/demo           a single-file HTML page that runs the core in the browser
examples/           a ready n8n workflow
eval/               the scripts that produced every number in docs/EVAL.md
docs/               SETUP.md, EVAL.md, LIMITATIONS.md and this file
```

## One scan

```
input ──► split into parts ──► per part: content type ──► 12 detectors ──► findings ──► score ──► verdict
          (email only)          text / html / markdown      (each alone)                 0–100     ok / review / block / error
```

1. **Input.** `scan(text)` takes one document. `scan({ subject, body, html, headers, attachments })` takes an email; each part is scanned as its own document (`scanEmail` in `packages/core/src/scan.ts`), so a quote or a code fence in one part never changes how another part is read. Subject and header values are decoded from RFC 2047 first, and positions map back to the original.
2. **Content type.** `auto` looks at the text: HTML turns on the HTML reader. Plain text that contains an HTML fragment is also read as HTML by `hidden-html`, while the other detectors keep the plain view.
3. **Detectors.** Twelve independent modules in `packages/core/src/detectors/`. Each gets the text and shared helpers (instruction patterns, excerpts) and returns findings: category, severity, start and end offsets, excerpt, reason, and the decoded text when something was decoded. Detectors do not call each other. The HTML reader (`html-tree.ts`) builds a tree the way a browser would and is checked against parse5 in tests.
4. **Email-only checks.** A subject or header holding instructions rates one step higher; an executable hidden behind a document extension in an attachment name is critical; `cross-field` finds one attack split across parts.
5. **Score.** `computeScore`: severities have weights (info 2, low 6, medium 18, high 32, critical 48). Inside a category, each further finding counts less; categories are added, with a small bonus for 2 or 3+ different categories; the total is squashed to 0–100. One critical finding alone is about 74 (block), one high about 59, one medium about 39.
6. **Verdict.** `ok` below 30, `review` 30–69, `block` 70 and above. If any detector throws, the verdict is `error`: the scan fails closed and never drops a detector silently.

## Rules the design keeps

- **Structure, not meaning.** Every signal answers "is something hidden, smuggled or pretending to be structure?". Judging what plain text means is left to the next layer.
- **Positions into the original input.** Every finding points at the characters the user can highlight, also after decoding and normalisation.
- **Linear time.** Input is attacker-controlled, so every detector is written to run in linear time; growth tests (`packages/core/test/linear.ts`) fail on quadratic behaviour.
- **Fail closed.** A scan error is a verdict of its own; the n8n node routes it to Fail, and in Score only mode the check after the node must treat a missing score as not clean.
- **No runtime dependencies and no network.** The core runs the same in Node, in n8n and in a browser.

## Adding a signal

Describe what it catches and what normal mail looks the same, write failing tests from real attacks and from normal mail that looks similar, implement it in one detector, then re-run the evaluation and check that normal mail stays at zero false blocks before committing.
