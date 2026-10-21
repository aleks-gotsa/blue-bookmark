# Trojan Source, two years later

In 2021 Boucher and Anderson showed that bidirectional override characters (U+202E and friends) can make source code *look* different from how a compiler reads it. The attack is simple: a comment that visually ends before a line of code actually contains it.

Most compilers and editors now warn about these characters. GitHub highlights them, and rustc rejects them by default.

The same family of tricks has reappeared in LLM pipelines: zero-width spaces splitting trigger words, Unicode tag characters (U+E0000 block) that are invisible to humans but visible to tokenizers, and CSS-hidden text in HTML emails. If your agent reads documents, it should normalise and inspect them first.

Further reading: the original paper, and the Unicode Technical Report #36 on security considerations.