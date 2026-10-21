import type { Detector, Finding, Severity } from "../types";
import { isCyrillicLetter, isGreekLetter, isLatinLetter } from "../util/text";

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'()\]]+|data:[a-z]+\/[a-z0-9.+-]+(?:;[a-z0-9=-]+)*,[^\s"')]{20,}|javascript:[^\s"')]+/gi;

const WELL_KNOWN = /(^|\.)(google|googleapis|gstatic|youtube|github|githubusercontent|microsoft|office|live|apple|amazon|amazonaws|cloudfront|wikipedia|wikimedia|linkedin|facebook|twitter|x|instagram|notion|slack|zoom|dropbox|figma|npmjs|unpkg|jsdelivr|cloudflare|mozilla|w3|stackoverflow|medium|substack|shopify|stripe|paypal|gov|edu)\.(com|org|net|io|dev|co|ua|de|uk)$/i;

export const exfilUrls: Detector = {
  id: "exfil-urls",
  category: "exfil-urls",
  severity: "high",
  description: "URLs that look like exfiltration channels: long query strings, image markdown with parameters, data: and javascript: URIs, lookalike domains.",
  run(ctx) {
    const s = ctx.input;
    const findings: Finding[] = [];
    let m: RegExpExecArray | null;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(s))) {
      let url = m[0].replace(/[.,;:!?]+$/, "");
      const start = m.index;
      const end = start + url.length;
      const reasons: string[] = [];
      let severity: Severity = "info";
      const bump = (sv: Severity) => {
        if (rank(sv) > rank(severity)) severity = sv;
      };

      if (/^javascript:/i.test(url)) {
        reasons.push("javascript: URI");
        bump("high");
      } else if (/^data:/i.test(url)) {
        if (/^data:image\//i.test(url)) {
          // inline images are common in HTML email; only flag if huge or non-base64
          if (url.length > 200000) {
            reasons.push("very large inline data: image");
            bump("low");
          }
        } else {
          reasons.push(`data: URI with ${/^data:([^;,]+)/i.exec(url)?.[1]} payload`);
          bump(/text\/html|application\/(x-)?javascript|text\/javascript/i.test(url) ? "high" : "medium");
        }
      } else {
        const u = parseUrl(url);
        if (u) {
          const q = u.query;
          const before = s.slice(Math.max(0, start - 60), start);
          const inImage = /!\[[^\]]*\]\(\s*$/.test(before) || /<img\b[^>]*\bsrc\s*=\s*["']?$/i.test(before);
          // markdown image or <img> with query string carrying data
          if (inImage && q.length > 0) {
            const hasTemplate = /\{\{|\{[a-z_]+\}|\$\{|%7B%7B/i.test(url);
            const looksData = /(=[^&]{24,})|\b(data|q|query|text|content|secret|token|key|summary|msg|message|ctx|context|history|prompt|conv|chat|p|s)=/i.test(q);
            if (hasTemplate || looksData) {
              reasons.push(`image URL carries ${hasTemplate ? "a template placeholder" : "data-like parameters"} in its query string (exfiltration via image fetch)`);
              bump("high");
            } else if (!WELL_KNOWN.test(u.host)) {
              reasons.push("image URL with query parameters on an unknown host");
              bump("low");
            }
          }
          if (q.length >= 200) {
            reasons.push(`very long query string (${q.length} chars)`);
            bump("medium");
          } else if (q.length >= 90 && !WELL_KNOWN.test(u.host) && !/utm_/.test(q)) {
            reasons.push(`long query string (${q.length} chars)`);
            bump("low");
          }
          if (/\b(secret|password|passwd|token|api_?key|apikey|credential|ssn|cc|card)=/i.test(q)) {
            reasons.push("query parameter named like a secret");
            bump("high");
          }
          // credentials in URL
          if (u.userinfo) {
            reasons.push(`user info before host (“${u.userinfo}@”) can disguise the real destination`);
            bump("high");
          }
          // lookalike host
          const look = lookalike(u.host);
          if (look) {
            reasons.push(look);
            bump("medium");
          }
          // IP host or suspicious TLDs with image/webhook paths
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.host)) {
            reasons.push("raw IP address host");
            bump("low");
          }
          if (/\.(xyz|top|click|tk|ml|ga|cf|gq|zip|mov|icu|buzz|ru)$/i.test(u.host) && (q.length > 0 || /webhook|collect|log|track|beacon|pixel|ping/i.test(u.path))) {
            reasons.push("collector-like path on a cheap TLD");
            bump("medium");
          }
          if (/\b(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|burpcollaborator|oastify\.com|interact\.sh|beeceptor\.com|hookbin|canarytokens)\b/i.test(u.host)) {
            reasons.push("known request-catcher / collaborator service");
            bump("high");
          }
        }
      }
      if (!reasons.length) continue;
      findings.push({
        id: "exfil-urls",
        category: "exfil-urls",
        severity,
        start,
        end,
        excerpt: ctx.helpers.excerpt(start, end, 10),
        reason: reasons.join("; "),
        meta: { url: url.slice(0, 500) },
      });
    }
    return findings;
  },
};

function parseUrl(url: string): { host: string; path: string; query: string; userinfo?: string } | null {
  const m = /^(?:https?:\/\/)?(?:([^/@\s]+)@)?([^/?#\s]+)([^?#]*)(?:\?([^#]*))?/i.exec(url.replace(/^www\./i, "http://www."));
  if (!m) return null;
  return { userinfo: m[1], host: m[2].toLowerCase().replace(/:\d+$/, ""), path: m[3] || "/", query: m[4] || "" };
}

function lookalike(host: string): string | null {
  // non-ASCII or mixed-script label
  for (const label of host.split(".")) {
    let latin = 0,
      other = 0;
    for (const ch of label) {
      const cp = ch.codePointAt(0)!;
      if (isLatinLetter(cp)) latin++;
      else if (isCyrillicLetter(cp) || isGreekLetter(cp)) other++;
    }
    if (latin && other) return `host label “${label}” mixes Latin and Cyrillic/Greek letters (homograph domain)`;
    if (other && !latin && /xn--/.test(host)) return "punycode host";
  }
  if (/xn--/.test(host)) return "punycode (IDN) host — may render as a lookalike";
  // digit substitutions in brand-like words
  const brands = ["google", "microsoft", "paypal", "apple", "amazon", "github", "openai", "anthropic", "n8n", "slack", "dropbox", "notion", "linkedin", "facebook"];
  const normalized = host.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/rn/g, "m").replace(/vv/g, "w");
  for (const b of brands) {
    if (normalized.includes(b) && !host.includes(b)) return `host “${host}” imitates “${b}” with digit/letter substitution`;
    const re = new RegExp(`(^|\\.)${b}[-.][a-z0-9-]+\\.(com|net|org|io|xyz|top|co)$`, "i");
    if (re.test(host) && !new RegExp(`(^|\\.)${b}\\.(com|io|dev|org|ai)$`).test(host)) return `host “${host}” uses “${b}” as a prefix of a different domain`;
  }
  return null;
}

function rank(s: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(s);
}
