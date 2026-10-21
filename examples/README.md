# Examples

## n8n: `n8n/email-guard.json`

Two sample emails go through Blue Bookmark in *Email* mode with *Pass / Fail* at threshold 70. The normal invoice goes to **Safe**, the invoice with a hidden `display:none` instruction goes to **Quarantine**.

1. Install the node (see [Get started](../README.md#get-started)).
2. In n8n: **Workflows → Import from File** → `email-guard.json`.
3. Click **Execute workflow**.

Checked on n8n 2.43.7: the normal email scores 0 (`ok`), the hidden-HTML email 97 (`block`).

To use it on real mail, replace **Sample emails** with your mail trigger and map its subject, text and HTML fields in Blue Bookmark.
