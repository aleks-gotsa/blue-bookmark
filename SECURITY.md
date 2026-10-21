# Security policy

Blue Bookmark is a static scanner. A report is useful to us in one of two shapes.

## 1. Detector bypass

Content that carries a hidden, smuggled or structurally spoofed instruction and still scores **below 70**. In scope:

- hidden HTML / CSS, HTML comments, zero-size or colour-equals-background text
- invisible or deceptive Unicode (zero-width, bidi, TAG characters, homoglyphs)
- encoded payloads (base64, hex, ROT13 and similar) that decode to instructions
- metadata or provenance spoofing (front matter, `<meta>`, email headers)
- instructions explicitly addressed to an AI agent
- structural spoofing: fake chat-role markers, fake system / tool-output tags, fake delimiters, obfuscated addresses

**Not a bypass:** a plain-language, persuasive message with no hidden or structural carrier (for example, a polite email asking the assistant to forward something). Judging meaning is out of scope by design; see [How it works](README.md#how-it-works).

Report a bypass with the **Bypass report** issue template. Bypasses of a static scanner are expected and are fixed in the open, so a public issue is fine. Please send a minimal synthetic payload, never real email, customer data or credentials.

## 2. Vulnerability in the code

Something that harms the system running Blue Bookmark, for example:

- a crash or exception on crafted input that makes the n8n node fail open
- catastrophic regex backtracking (ReDoS) or another input that makes a scan take seconds instead of milliseconds
- `sanitize()` output that is less safe than its input

Report these **privately** through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue. We aim to acknowledge within 7 days.

## Supported versions

Only the latest released version receives fixes.
