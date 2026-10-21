# Changelog

## 1.0.0 (October 2026)

First public release. Measured results: [docs/EVAL.md](docs/EVAL.md).

### Breaking changes

- The project is now **Blue Bookmark**: the n8n node is "Blue Bookmark" (type `blueBookmark`, a workflow made with the old node must swap it), the packages are `n8n-nodes-blue-bookmark` and `@blue-bookmark/core`, the browser global is `window.BlueBookmark`.

- `Result.verdict` can be `"error"`, with `Result.error` explaining why: `scan_error` when a detector or the input reader throws, `too_large` when the input is over the size cap (2,000,000 characters by default) and only its start was read. Nothing drops out silently: the scan fails closed. The n8n node routes such items to **Fail**; in *Score only* mode the check after the node must treat a missing score as not clean.
- Chat-template tokens in visible text are reported under the new `role-spoofing` category instead of `instruction-patterns`.
- New finding categories: `role-spoofing`, `fake-delimiter`, and `cross-field` (email input only).
- The n8n node is built as one file with the core bundled in; it has no runtime dependencies.

### New

- **Email input.** `scan({ subject, body, html, headers, attachments })` scans each part on its own, decodes RFC 2047 headers, reads attachment names, and finds one attack split across parts. The n8n node has a matching *Email* input.
- **Fake chat structure:** `role-spoofing` (`<|assistant|>`, `</tool_output>`, `[INST]`, role tags and transcripts) and `fake-delimiter` (`[END USER]`, `----- END OF EMAILS -----`).
- **HTML read like a browser:** a tree reader checked against parse5, bogus comments, character references in attributes and CSS, raw-text elements, hidden form fields, all-hidden messages, and HTML fragments inside plain text.
- **Encodings:** split and per-word encoded payloads, binary, `%xx`, escapes, `&#`, `U+` notation, base32; variation-selector and Sneaky Bits smuggling.
- **Lookalikes:** the full Unicode UTS #39 confusables table, instruction patterns matched on a folded copy of the text, digits and symbols typed for letters, addresses written in lookalike letters.
- An example n8n workflow in `examples/n8n/`.

### Fixed

- Every detector runs in linear time on attacker-controlled input; growth tests guard it.
- Quotes and code fences no longer switch a finding off when they are unbalanced or point the wrong way.
- Many false positives on normal mail: `System:` field labels, signatures, quoted replies, formulas, Ukrainian text with Latin letters.

## 0.1.0

Prototype, not published: ten detectors, the n8n node in Text mode, the browser demo.
