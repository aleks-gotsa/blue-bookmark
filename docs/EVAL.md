# Evaluation

Measured on 21 October 2026 on the frozen v1 code, against the unreleased prototype (0.1.0) it grew from. Every number below comes from runs made that day. Block threshold 70 in both versions.

## Method

- The scanner core runs directly on each item, offline, with no n8n and no network. Scripts: [`eval/`](../eval).
- **String path:** `body_html || body` plus attachment text, as one string, the way the prototype's n8n workflow called the node. **Email path:** subject, body, HTML and attachments passed as separate parts (`scan({ ... })`, new in v1; the prototype cannot take it).
- **Without exfil-send:** every LLMail-Inject attack has the same goal (send `confirmation` to `contact@contact.com`), and one pattern, `exfil-send`, matches that goal directly. The score without it shows how much rests on that one pattern.
- **Development data** was looked at and tuned on while v1 was built. **Final data** was set aside before tuning and scored once, after the code was frozen; `eval/phase4.mjs` refuses to run a second time.

## Data

| Set | Source and licence | Role |
| --- | --- | --- |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) Phase 2 | Microsoft, MIT | development (100 attacks, 100 normal, plus 27,513 attacks), final (259 attacks, 73 normal) |
| [agentic-prompt-injection-5k](https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k) | Enes Deniz, CC BY 4.0 | train/test for development; validation as final |
| [neuralchemy (core)](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | neuralchemy, Apache 2.0 | train/test for development; validation as final |
| [browsesafe-bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench) | Perplexity, MIT | train for development (web pages); test as final |
| Stack Exchange preferences, sample | HuggingFaceH4, CC BY-SA 4.0 | normal developer posts, development only |
| Built-in fixtures | this repository | 14 attacks, 14 normal |

LLMail-Inject tiers: T1 beat every Microsoft defence, T2 got past their detector only, T3 were caught by their detector, T0 is normal mail.

## Final data (scored once)

| Set | n | Prototype ≥ 70 | v1 ≥ 70 | v1 email path | v1 email, without exfil-send |
| --- | --- | --- | --- | --- | --- |
| LLMail T1 attacks | 106 | 43 (40.6%) | 86 (81.1%) | 86 (81.1%) | 48 (45.3%) |
| LLMail T2 attacks | 124 | 36 (29.0%) | 54 (43.5%) | 55 (44.4%) | 38 (30.6%) |
| LLMail T3 attacks | 29 | 11 (37.9%) | 17 (58.6%) | 18 (62.1%) | 12 (41.4%) |
| **LLMail T0 normal** | 73 | **0** | **0** | **0** | 0 |
| agentic-5k attacks | 308 | 28 (9.1%) | 28 (9.1%) | – | – |
| **agentic-5k normal** | 159 | **0** | **0** | – | – |
| neuralchemy attacks | 534 | 17 (3.2%) | 84 (15.7%) | – | – |
| **neuralchemy normal** | 407 | **0** | **1 (0.2%)** | – | – |
| browsesafe attacks (web pages) | 1,824 | 1,092 (59.9%) | 1,185 (65.0%) | – | – |
| **browsesafe normal (web pages)** | 1,856 | **297 (16.0%)** | **336 (18.1%)** | – | – |

No scan returned `error` in either version.

## Development data (tuned on; for comparison only)

| Set | n | Prototype ≥ 70 | v1 ≥ 70 | v1 without exfil-send |
| --- | --- | --- | --- | --- |
| LLMail attacks, string path | 100 | 42 | 70 | 52 |
| LLMail attacks, email path | 100 | – | 71 | 53 |
| **LLMail normal** (both paths) | 100 | **0** | **0** | 0 |
| LLMail attacks, large pool, string path | 27,513 | 10,522 | 15,673 | – |
| LLMail attacks, large pool, email path | 27,513 | – | 15,995 | 9,217 |
| Fixtures, attacks / normal | 14 / 14 | 14 / 0 | 14 / 0 | – |
| agentic-5k train+test, attacks / normal | 2,442 / 2,026 | 320 / 26 | 383 / 4 | – |
| neuralchemy train+test, attacks / normal | 3,202 / 2,131 | 170 / 0 | 503 / 0 | – |
| Stack Exchange normal posts | 8,198 | 12 | 16 | – |
| browsesafe train, attacks / normal | 5,473 / 5,566 | 3,273 / 802 | 3,649 / 935 | – |

## What the numbers say

- **On mail, v1 roughly doubles the prototype on the hardest unseen attacks** (LLMail T1, 40.6% → 81.1%), with **0 false blocks** on normal mail in every set (100 in development, 73 unseen).
- **About half of that gain rests on one pattern.** Without `exfil-send`, T1 is 45.3%. That pattern matches LLMail-Inject's fixed goal; on a real mailbox with a different goal it would not fire. The structural signals alone (fake chat structure, fake delimiters, encodings, cross-part checks) add about 5 points on T1 and 1.6 on T2 over the prototype's full score.
- **The gain on agentic-5k did not transfer.** Its train/test splits went from 320 to 383 blocked; its unseen validation split stayed at 28 of 308. That is a sign of over-fitting to the development half of that set.
- **neuralchemy's gain did transfer:** 3.2% → 15.7% on unseen data, with one new false block in 407 normal texts.
- **Web pages are not solved and got slightly worse:** normal browsesafe pages are blocked 18.1% of the time (prototype: 16.0%). The main causes, measured on the train split: words that mix scripts, the `exfil-send` and authority patterns on page prose, URL rules, zero-width characters. v1 is built for email; do not put its block threshold in front of arbitrary web pages.

## Limits of this evaluation

- Most attack data comes from one challenge with one fixed goal. Independent sets (BIPIA, Nemotron, NotInject) and a white-box adaptive red team were not run yet.
- Which items were set aside as final depended on which items had been looked at during development, so the split cannot be rebuilt from public data alone; the scripts and the public datasets are enough to re-run the development numbers.
- Plain persuasion is out of scope by design, and a large part of the misses is that.
