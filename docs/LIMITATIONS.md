# Limitations

What the results do not cover yet, and what would close each gap.

| Limitation | Why it matters | Next step |
|---|---|---|
| Normal web pages are blocked too often (18.1%). | Fine for email, not for agents that browse. | Fix the main causes measured on the web-page set. |
| Plain persuasion is not caught. | A polite request with no hidden part looks like normal mail. | By design: that is the LLM guard's job. |
| About half of the LLMail gain comes from one pattern that matches that challenge's goal. | On a mailbox with a different attacker goal, fewer attacks would be blocked. | Independent test sets (BIPIA, Nemotron, NotInject) and a white-box red team. |
| `name (at) domain` addresses are not read. | One obfuscation trick stays open. | Read it as supporting weight. |
| PDF and binary attachments are not read. | Only the text you extract and pass in is scanned. | Read attachment text inside the node. |
