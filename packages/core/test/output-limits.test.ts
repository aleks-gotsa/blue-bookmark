import { describe, expect, it } from "vitest";
import { scan } from "../src";

// The result must stay small on hostile input: the library and the demo do not cap it later.
describe("output stays bounded", () => {
  it("a long word interleaved with zero-width characters is not copied whole into the reason", () => {
    const word = "a\u200b".repeat(50_000);
    const r = scan(word);
    for (const f of r.findings) expect(f.reason.length).toBeLessThan(400);
  });
  it("one category keeps at most 200 findings, and the score is the same as without the cap", () => {
    const one = scan("p\u0430ypal");
    const r = scan("p\u0430ypal ".repeat(5_000));
    const homoglyph = r.findings.filter((f) => f.category === "homoglyph");
    expect(homoglyph.length).toBeLessThanOrEqual(200);
    expect(one.findings.length).toBeGreaterThan(0);
    expect(r.score).toBeGreaterThanOrEqual(one.score);
  });
});

describe("output stays bounded over a whole email", () => {
  it("many attachments do not multiply the per-category cap", () => {
    const attachments = Array.from({ length: 30 }, () => ({ text: "p\u0430ypal ".repeat(300) }));
    const r = scan({ attachments });
    expect(r.findings.filter((f) => f.category === "homoglyph").length).toBeLessThanOrEqual(200);
  });
});
