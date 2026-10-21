# @blue-bookmark/core

The scanner behind [Blue Bookmark](../../README.md), as a TypeScript library: no runtime dependencies, no network, runs in Node and in the browser. This page is the library reference.

## Use

Not on npm yet; build it from this repository (`npm install && npm run build`).

```ts
import { scan, sanitize } from "@blue-bookmark/core";

const result = scan(text, { contentType: "auto", decodeBase64: true });
// result.score      0–100
// result.verdict    "ok" | "review" | "block" | "error" (see result.error); decide on the verdict, an error has score 0
// result.findings   [{ id, category, severity, start, end, excerpt, reason, decoded? }]
// result.provenance { declaredAuthor?, declaredSource?, declaredTitle?, detectedSignals[] }

if (result.verdict !== "ok") {
  const clean = sanitize(text, result);
  // invisible characters removed, hidden HTML stripped, decoded tag text made visible,
  // instruction spans wrapped in [QUOTED CONTENT, NOT INSTRUCTIONS: … :END QUOTED CONTENT]
}
```

Browser: `dist/blue-bookmark.iife.js` exposes `window.BlueBookmark` with the same API.

## Scanning an email

`scan` also takes an email as its parts. Each part is scanned as its own document, so a quote or a code fence in one part never changes how another is read.

```ts
const result = scan({
  subject, body, html,                           // every part is optional
  headers,                                       // { name: value } or the raw header block
  attachments: [{ name: "invoice.pdf", text }],  // text you extracted; binary files are not read
});
// result.fields    each part with its own score; the verdict comes from one score over all parts
// finding.field    "subject" | "body" | "html" | "attachment" | "header"; offsets are inside that part
```

- **Subject:** agent-directed instructions, role markers and authority markers rate one step higher, since nothing addressed to an agent belongs there.
- **Headers:** RFC 2047 encoded words are decoded; instructions and role markers in a header are critical, since the reader never sees them. A display name holding a different address is high.
- **Attachment names:** a document extension followed by an executable one (`invoice.pdf.exe`, also with padding spaces) or a bidi control in the name is critical.
- **`cross-field`:** an instruction in the subject with a near-empty body, or one fake chat turn split over two or more parts, is critical; an address in lookalike letters in one part and plain in another is high.

## What it detects

Twelve small detectors, each a module in `packages/core/src/detectors/`, plus a `cross-field` check that reads the parts of an email together (see [Scanning an email](#scanning-an-email)):

| # | Detector | Looks for | Typical severity |
| --- | --- | --- | --- |
| 1 | `zero-width` | U+200B–200F, U+2060–2064, U+FEFF, U+00AD in runs, splitting Latin words, or scattered as a steganographic channel. Ignores single ZWJ in emoji sequences and single ZWSP/ZWNJ next to CJK, Arabic and Indic text, and a lone BOM at position 0. Runs of variation selectors (one byte each) or of U+2062 / U+2064 (Sneaky Bits, one bit each) are decoded and rated critical. | medium–critical |
| 2 | `bidi-override` | U+202A–202E, U+2066–2069 (Trojan Source). Lone PDF/PDI terminators are ignored. | high |
| 3 | `unicode-tags` | U+E0000–E007F tag characters; decodes them to ASCII and reports the hidden text. Subdivision flag emoji (🏴 + tags) are ignored. | critical |
| 4 | `homoglyph` | Lookalike letters from the Unicode UTS #39 confusables table (Cyrillic, Greek, Armenian, Cherokee, fullwidth, math alphanumerics and more) inside otherwise Latin tokens. Whole words in another script (a Ukrainian sentence) are not a finding; hyphenated compounds like `n8n-нода` are checked per part. An email address written in lookalike letters is high, critical with zero-width characters between them. | low–critical |
| 5 | `hidden-html` | HTML only: comments, `display:none` / `visibility:hidden` / `font-size:0` / `opacity:0` / off-screen / clipped / colour-equals-background elements, `hidden` and `aria-hidden`, sr-only classes, stylesheet rules that hide a class, `<meta>` / `<title>` / `alt` / `data-*` stashes, `<script type="text/plain">` and `<template>` content. Email preheaders are downgraded to a note. | medium–critical |
| 6 | `encoded-payload` | Base64 blobs ≥ 40 chars (also double-encoded), hex runs, ROT13 paragraphs. Only reported as high/critical if the decoded text matches instruction patterns. | low–critical |
| 7 | `instruction-patterns` | Agent-directed imperatives in English, Ukrainian, German and Russian: override prior instructions, role reassignment, secrecy ("do not tell the user"), tool/command calls, exfil directives, dangerous shell, chat-template tokens in hidden, encoded or smuggled text (visible ones belong to `role-spoofing`), prescribed output, "approve immediately". Patterns also run on a folded copy of the text (diacritics, fullwidth, math and circled letters, cross-script lookalikes), so a fullwidth `ignore` still matches. Non-standalone patterns require nearby agent-addressed context; quoted or fenced matches are downgraded to a note (a README that *discusses* injection stays clean). | medium–critical |
| 8 | `exfil-urls` | Image URLs with data-like or templated query strings, very long query strings, secret-named parameters, `data:` and `javascript:` URIs, userinfo-before-host tricks, homograph/punycode and digit-substituted lookalike domains, known request-catcher services. | low–high |
| 9 | `authority-spoof` | "This message is from the system administrator", "Note to AI:", "Trusted mode enabled", "I am your developer", shouted `IMPORTANT:` markers next to agent context. EN/UK/DE. | medium–high |
| 10 | `metadata` | YAML front matter, HTML `<meta>`/`<title>`, and email-style headers whose values are instructions. | medium–critical |
| 11 | `role-spoofing` | Fake conversation structure in visible text: chat-template turn tokens (`<\|im_start\|>`, `<\|assistant\|>`, `[INST]`, `<<SYS>>`, `<start_of_turn>`) and pseudo-XML role tags (`<user>`, `</assistant>`, `</tool_output>`). One token is high; two different markers, a token pair or a role switch is critical. A `User:` line and an `Assistant:` line together read as a transcript (medium); a single `System:` label with a value, as in an IT notification, is only a field. Markers inside quotes, a closed code fence or `<code>` / `<pre>` are a note. | info–critical |
| 12 | `fake-delimiter` | Lines and brackets that claim to end or begin a context: `----- END OF EMAILS -----`, `[END USER]`, an orphan `</context>`. One alone is medium, since such lines appear in ordinary work mail; next to a role marker or a second, different delimiter it is high; quoted or inside code it is a note. Forward and PGP markers, vCard and calendar blocks, signature separators and email-builder comments never count. | info–high |

Positions are character offsets (UTF-16 code units) into the **original** input, so a UI can highlight exactly what was found.

### Scoring

Severity weights (info 2, low 6, medium 18, high 32, critical 48) are summed per category with diminishing returns, categories are added with a small diversity bonus, and the total is squashed to 0–100. One critical finding alone is a block (~74); one high is a review (~59); one medium is a review (~39); notes and lows stay ok unless they pile up.

Verdicts: **ok** < 30, **review** 30–69, **block** ≥ 70.

## License

MIT
