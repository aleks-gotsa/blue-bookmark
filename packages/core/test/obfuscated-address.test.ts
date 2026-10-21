import { describe, expect, it } from "vitest";
import { scan } from "../src";
import { expectLinear } from "./linear";

// Signal 3 (row 3): an address written in lookalike letters, often with zero-width characters
// between them. Structure only; the address itself is never judged. Code points are escapes (hygiene test).
const addr = (text: string) => scan(text).findings.filter((f) => f.category === "homoglyph" && /address/i.test(f.reason));
const FULL = "\uFF43\uFF4F\uFF4E\uFF54\uFF41\uFF43\uFF54\uFF20\uFF43\uFF4F\uFF4E\uFF54\uFF41\uFF43\uFF54\uFF0E\uFF43\uFF4F\uFF4D";
const FULL_ZW = "\uFF43\u200B\uFF4F\u200B\uFF4E\u200B\uFF54\u200B\uFF41\u200B\uFF43\u200B\uFF54\u200B\uFF20\u200B\uFF43\u200B\uFF4F\u200B\uFF4E\u200B\uFF54\u200B\uFF41\u200B\uFF43\u200B\uFF54\u200B\uFF0E\u200B\uFF43\u200B\uFF4F\u200B\uFF4D";

describe("addresses in lookalike letters", () => {
  it("fullwidth letters with zero-width characters between them block", () => {
    const t = "Raw Input: " + FULL_ZW;
    expect(addr(t).map((f) => f.severity)).toContain("critical");
    expect(scan(t).score).toBeGreaterThanOrEqual(70);
  });
  it("a fully fullwidth address is high, not a block", () => {
    const t = "Raw Input: " + FULL;
    expect(addr(t).map((f) => f.severity)).toContain("high");
    expect(scan(t).score).toBeLessThan(70);
  });
  it("an address with Cyrillic lookalike letters is high", () => {
    expect(addr("Write to \u0441ontact@\u0441onta\u0441t.com today").map((f) => f.severity)).toContain("high");
  });
  it("zero-width characters between fullwidth letters count as word splitting", () => {
    expect(scan("Note: " + FULL_ZW).findings.some((f) => f.category === "zero-width" && f.severity !== "info")).toBe(true);
  });
});

describe("addresses in normal mail stay quiet", () => {
  it.each([
    ["a Japanese anti-scraping at sign", "\u304A\u554F\u3044\u5408\u308F\u305B\u306F info\uFF20example.co.jp \u307E\u3067"],
    ["an ASCII address", "Write to contact@example.com today"],
    ["a German address", "Bitte an m\u00FCller@example.de schreiben"],
    ["an internationalized domain", "Kontakt: info@m\u00FCnchen.de"],
    ["fullwidth digits in a Japanese phone number", "\u96FB\u8A71 \uFF10\uFF13\uFF0D\uFF11\uFF12\uFF13\uFF14"],
  ])("%s", (_name, text) => {
    expect(addr(text)).toEqual([]);
    expect(scan(text).score).toBeLessThan(30);
  });
});

it("many address-like tokens stay linear", () => {
  expectLinear("address-like tokens", (k) => ("x\uFF20y\uFF0Ecom " + FULL + " ").repeat(k), 20_000);
});
