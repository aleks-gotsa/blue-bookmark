// Email header helpers for the email input: unfold a raw header block, decode RFC 2047 encoded words with a map
// back to the original offsets, and read a display name and its address. No dependencies.

/** Header name and value pairs from an object (n8n mail nodes) or a raw block (RFC 5322 folding: a line that starts with
 * whitespace continues the previous one). */
export function headerList(headers: Record<string, string | string[] | undefined> | string | undefined): { name: string; value: string }[] {
  if (!headers) return [];
  if (typeof headers === "string") {
    const out: { name: string; value: string }[] = [];
    for (const line of headers.split(/\r?\n/)) {
      if (/^[ \t]/.test(line) && out.length) out[out.length - 1].value += " " + line.trim();
      else {
        const c = line.indexOf(":");
        if (c > 0) out.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
      }
    }
    return out;
  }
  const out: { name: string; value: string }[] = [];
  for (const [name, v] of Object.entries(headers)) for (const value of Array.isArray(v) ? v : [v]) if (typeof value === "string") out.push({ name, value });
  return out;
}

const ENCODED_WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;

function bytesOf(enc: string, data: string): Uint8Array | null {
  if (enc === "B" || enc === "b") {
    const clean = data.replace(/[^A-Za-z0-9+/]/g, "");
    if (typeof atob !== "function") return null;
    try {
      const bin = atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
      return Uint8Array.from(bin, (c) => c.charCodeAt(0));
    } catch {
      return null;
    }
  }
  const out: number[] = [];
  for (let i = 0; i < data.length; i++) {
    const c = data[i];
    if (c === "_") out.push(0x20);
    else if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(data.slice(i + 1, i + 3))) {
      out.push(parseInt(data.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(c.charCodeAt(0) & 0xff);
  }
  return Uint8Array.from(out);
}

/** The value with its encoded words decoded; `from`/`to` give each decoded character's span in the original value, so a
 * finding on decoded text points at the encoded word. Undefined when the value has none. */
export function decodeEncodedWords(value: string): { text: string; from: number[]; to: number[] } | undefined {
  if (!value.includes("=?")) return undefined;
  let text = "";
  const from: number[] = [];
  const to: number[] = [];
  let last = 0;
  let changed = false;
  ENCODED_WORD.lastIndex = 0;
  for (let m: RegExpExecArray | null; (m = ENCODED_WORD.exec(value)); ) {
    const bytes = bytesOf(m[2], m[3]);
    if (!bytes) continue;
    let decoded: string;
    try {
      decoded = new TextDecoder(m[1].toLowerCase(), { fatal: false }).decode(bytes);
    } catch {
      decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    }
    // whitespace between two adjacent encoded words is not part of the text (RFC 2047 §6.2)
    const gap = value.slice(last, m.index);
    const keepGap = !(changed && /^\s*$/.test(gap));
    if (keepGap)
      for (let i = last; i < m.index; i++) {
        text += value[i];
        from.push(i);
        to.push(i + 1);
      }
    for (const ch of decoded) {
      text += ch;
      for (let k = 0; k < ch.length; k++) {
        from.push(m.index);
        to.push(m.index + m[0].length);
      }
    }
    last = m.index + m[0].length;
    changed = true;
  }
  if (!changed) return undefined;
  for (let i = last; i < value.length; i++) {
    text += value[i];
    from.push(i);
    to.push(i + 1);
  }
  return { text, from, to };
}

/** The display name and the address of a "Name <addr>" value; undefined without angle brackets. */
export function displayAndAddress(value: string): { display: string; address: string } | undefined {
  const m = /^(.*)<([^<>\s]+@[^<>\s]+)>\s*$/.exec(value);
  if (!m) return undefined;
  return { display: m[1].trim().replace(/^"|"$/g, ""), address: m[2] };
}
