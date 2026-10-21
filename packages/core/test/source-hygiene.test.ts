import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

// Raw invisible and bidi characters in source hide what the code says from a reviewer (Trojan Source, CVE-2021-42574).
// Code writes them as escapes; only the fixtures hold them raw, because they are the test data.
const INVISIBLE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFE00-\uFE0F\uFEFF]|\uDB40[\uDC00-\uDDEF]/;
const files = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    ["node_modules", "dist", "fixtures"].includes(e.name) ? [] : e.isDirectory() ? files(join(dir, e.name)) : /\.(ts|mts|js|mjs)$/.test(e.name) ? [join(dir, e.name)] : [],
  );

it("source files hold no raw invisible or bidi characters", () => {
  const root = join(__dirname, "..", "..", "..");
  const dirty = ["packages", "eval", "scripts"].flatMap((d) => files(join(root, d))).filter((f) => INVISIBLE.test(readFileSync(f, "utf8")));
  expect(dirty).toEqual([]);
});

// A raw letter of another script inside a Latin word reads as Latin to a reviewer: "p" + Cyrillic "a" + "ssword". Code
// and tests write such letters as escapes; whole words in another language stay raw.
const mixed = (text: string): string[] => {
  const out: string[] = [];
  const foreign = /[^\P{L}\p{Script=Latin}]/u;
  for (const w of text.match(/[\p{L}\p{M}]+/gu) ?? []) if (/[A-Za-z]/.test(w) && foreign.test(w)) out.push(w);
  for (const t of text.match(/[\p{L}\p{N}\p{M}._%+-]*@[\p{L}\p{N}\p{M}._-]+/gu) ?? []) if (foreign.test(t)) out.push(t);
  return out;
};

it("source files hold no raw lookalike letters inside Latin words or addresses", () => {
  const root = join(__dirname, "..", "..", "..");
  const dirty = ["packages", "eval", "scripts"].flatMap((d) => files(join(root, d))).flatMap((f) => mixed(readFileSync(f, "utf8")).map((w) => `${f.slice(root.length + 1)}: ${JSON.stringify(w)}`));
  expect(dirty).toEqual([]);
});

it("the lookalike check finds what it is for and leaves other languages alone", () => {
  const cyrA = String.fromCharCode(0x430), cyrE = String.fromCharCode(0x435);
  expect(mixed(`reset your p${cyrA}ssword`)).toHaveLength(1);
  expect(mixed(`x1@${cyrE}${cyrA}.io`)).toHaveLength(1);
  const ua = String.fromCharCode(0x437, 0x432, 0x456, 0x442);
  expect(mixed(`${ua} report n8n-${ua}`)).toEqual([]);
});
