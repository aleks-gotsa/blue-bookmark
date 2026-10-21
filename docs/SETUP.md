# Setup guide

Step by step, from nothing to a working guard in n8n.

## What you need

| | Version | Why |
|---|---|---|
| [n8n](https://n8n.io/) | 2.x (checked on 2.43.7) | runs the node |
| [Node.js](https://nodejs.org/) | 24 (checked) | builds the node |
| [Git](https://git-scm.com/) | any | gets the code |

## 1. Build the node

```bash
git clone https://github.com/aleks-gotsa/blue-bookmark.git
cd blue-bookmark
npm install
npm run build
```

The build ends with `bundle ok: … needs only n8n-workflow`. The node is one file with no dependencies.

## 2. Copy it into n8n

```bash
mkdir -p ~/.n8n/custom/BlueBookmark
cp packages/n8n-node/dist/nodes/BlueBookmark/* ~/.n8n/custom/BlueBookmark/
```

n8n in Docker: copy the same two files into the folder mounted as `/home/node/.n8n/custom/BlueBookmark`.

## 3. Restart n8n

The node appears in the node picker as **Blue Bookmark**.

## 4. Try the example

1. **Workflows → Import from File** → [`examples/n8n/email-guard.json`](../examples/n8n/email-guard.json).
2. Click **Execute workflow**.
3. The normal invoice goes to **Safe** (score 0). The invoice with a hidden instruction goes to **Quarantine** (score 97).

## 5. Put it in front of your agent

1. Replace **Sample emails** with your mail trigger (Gmail, IMAP).
2. In **Blue Bookmark**, keep **Input** = *Email* and map the subject, text and HTML fields of your trigger.
3. Keep **Mode** = *Pass / Fail*, **Threshold** = 70.
4. Wire **Pass** to your agent and **Fail** to quarantine or a person.
5. Give the agent the email fields (or `guard.sanitized`), never the `guard` object itself: its findings quote the hidden text.

Every parameter: [`packages/n8n-node/README.md`](../packages/n8n-node/README.md).

**Using *Score only* mode instead?** The check after the node must fail closed: let an item through only if the score is a number below 70. A check like `score >= 70 → block` lets a failed scan through as clean.

## Other ways to use it

**As a library** (TypeScript or JavaScript, Node or browser):

```ts
import { scan } from "@blue-bookmark/core";

const result = scan(text);   // or scan({ subject, body, html, headers, attachments })
result.score;                // 0–100
result.verdict;              // "ok" | "review" | "block" | "error": decide on this, an error has score 0
result.findings;             // what was found, where, and why
```

**The demo:** after `npm run build`, open `apps/demo/dist/index.html` in a browser. Paste text or drop a file; your text never leaves the browser (the page loads only a font and an animation library).
