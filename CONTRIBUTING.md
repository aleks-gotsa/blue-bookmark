# Contributing

## Found a bypass?

Content that hides an instruction and still scores below 70 is the most useful report. Use the **Bypass report** issue template; for anything that could harm users before a fix, follow [SECURITY.md](SECURITY.md) instead.

## Changing the scanner

Blue Bookmark checks structure, not meaning: hidden content, invisible or lookalike characters, encodings, fake chat structure. A rule that needs to understand what plain text says belongs in an LLM guard, not here.

For a new signal or a fix:

1. Describe it in the issue or pull request: what it catches, what normal mail looks the same, how it is rated.
2. Write failing tests first: real attack shapes, and normal mail that looks similar (signatures, quoted replies, newsletters, IT notifications).
3. Implement it in one detector in `packages/core/src/detectors/`, in linear time on any input.
4. Run `npm test`, then the evaluation scripts in `eval/`. Normal mail must stay at zero false blocks.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how a scan works.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`, English, imperative, lowercase, at most 72 characters. Types: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`, `perf`, `ci`. Scopes: `detector`, `eval`, `workflow`, `demo`. One signal or one fix per commit. The commit hook runs the tests.
