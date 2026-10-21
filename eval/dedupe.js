// Near-duplicate keys for LLMail items: md5 of subject and body after dates and times are stripped, so one
// template that differs only by a timestamp counts once.
import { createHash } from "node:crypto";

export const md5 = (subject, body) => createHash("md5").update(subject + "\n" + body).digest("hex");

const MON = "(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
const DAY = "(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:r(?:s(?:day)?)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)";
const TZ = "(?:\\s*(?:utc|gmt|[a-z]{1,2}[sd]t|z|[+-]\\d{2}:?\\d{2}))?";
const STRIP = [
  new RegExp(`\\b\\d{4}-\\d{2}-\\d{2}(?:[t ]\\d{1,2}:\\d{2}(?::\\d{2}(?:\\.\\d+)?)?)?${TZ}\\b`, "gi"),
  /\b\d{1,4}[/.-]\d{1,2}[/.-]\d{2,4}\b/g,
  new RegExp(`\\b\\d{1,2}:\\d{2}(?::\\d{2}(?:\\.\\d+)?)?(?:\\s*[ap]\\.?m\\.?)?${TZ}\\b`, "gi"),
  /\b\d{1,2}\s*[ap]\.?m\b\.?/gi,
  new RegExp(`\\b${DAY}\\b\\.?,?`, "gi"),
  new RegExp(`\\b\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?${MON}\\b\\.?,?(?:\\s+\\d{4})?`, "gi"),
  new RegExp(`\\b${MON}\\b\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?\\b,?(?:\\s+\\d{4})?`, "gi"),
  new RegExp(`\\b${MON}\\b\\.?\\s+\\d{4}\\b`, "gi"),
];

export const strip = (s) => {
  for (const re of STRIP) s = s.replace(re, " ");
  return s.replace(/\s+/g, " ").trim();
};

/** The near-duplicate key of an item. */
export const nearKey = (subject, body) => md5(strip(subject || ""), strip(body || ""));
