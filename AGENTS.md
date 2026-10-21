# AGENTS.md

Instructions for an AI agent that has been asked to install, use or change Blue Bookmark. People should start with [README.md](README.md) and [docs/SETUP.md](docs/SETUP.md).

## What this repository is

An n8n community node and a TypeScript library that score an email or document for hidden prompt injection (0–100) before an AI agent reads it. Offline, no LLM call, no runtime dependencies.

- `packages/core`: the scanner. `scan(text)` or `scan({ subject, body, html, headers, attachments })` returns score, verdict and findings.
- `packages/n8n-node`: the n8n node, with the core bundled into one file.
- `examples/n8n/email-guard.json`: a ready workflow.

## Install the node into the user's n8n

1. `npm install && npm run build`. The build must end with `bundle ok`.
2. Copy `packages/n8n-node/dist/nodes/BlueBookmark/*` into `~/.n8n/custom/BlueBookmark/` (in Docker: the folder mounted as `/home/node/.n8n/custom/BlueBookmark`).
3. Ask the user to restart n8n.
4. Import `examples/n8n/email-guard.json` and run it. Expected: the clean invoice scores 0 and goes to **Safe**; the invoice with a hidden instruction scores 97 and goes to **Quarantine**.

## Put it in front of their agent

- **Input** = *Email*, mapped to the trigger's subject, text and HTML fields.
- **Mode** = *Pass / Fail*, **Threshold** = 70. **Pass** goes to the agent, **Fail** to quarantine or a person.
- Give the agent the email fields or `guard.sanitized`, never the `guard` object: findings quote the hidden text.
- In *Score only* mode, let an item through only if `guard.score` is a number below 70. An error has no score.

## Change the code

- `npm test` must pass before every commit; the commit hook runs it.
- A new signal checks structure, not meaning: hidden, smuggled or fake-structure content. Rules that judge what plain text means do not belong here.
- Write failing tests first, from attack shapes and from normal mail that looks similar. Every detector must stay linear on any input.
- Commits follow Conventional Commits (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Do not

- Do not lower the threshold or delete a test to make something pass.
- Do not add runtime dependencies to either package.
- Do not put real email, customer data or credentials into tests or issues.
