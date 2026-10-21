import { describe, expect, it } from "vitest";
import { P, POST, PRE, SHAPES, compare } from "./parse5-oracle";

// hidden-html against the browser's reading. Every shape wraps one marker sentence.
// A known disagreement is asserted as that disagreement, with the module that closes it; fixing it fails the test,
// so the table must be updated in the same commit.
describe("hidden-html against the browser (parse5)", () => {
  for (const [name, s] of Object.entries(SHAPES)) {
    const label = s.owner ? `${name}: known ${s.expect}, closed by ${s.owner}` : name;
    it(label, () => {
      for (const pre of PRE) for (const post of POST) expect(compare(pre + s.wrap(P) + post), pre + "|" + post).toBe(s.expect);
    });
  }
});

describe("seeded fuzz", () => {
  // two shapes nested at random inside random surroundings: a disagreement in a case built only from agreeing
  // shapes is a new class and fails; DG_FUZZ_N runs more cases
  const n = Number(process.env.DG_FUZZ_N ?? 400);
  it(`${n} nested cases find no new disagreement class`, () => {
    let seed = 20261020;
    const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
    const names = Object.keys(SHAPES);
    const agreeing = names.filter((k) => SHAPES[k].expect === "agree");
    // inside <select> the browser drops element tags, a class of its own ("hidden element inside a select option")
    const outers = agreeing.filter((k) => k !== "select option");
    const pick = <T,>(a: T[]) => a[Math.floor(rnd() * a.length)];
    const fresh: string[] = [];
    for (let i = 0; i < n; i++) {
      const outer = pick(outers);
      const inner = pick(agreeing);
      const html = pick(PRE) + SHAPES[outer].wrap(SHAPES[inner].wrap(P)) + pick(POST);
      const r = compare(html);
      if (r === "miss" || r === "false-hidden") fresh.push(`${outer} > ${inner}: ${r}`);
    }
    expect([...new Set(fresh)]).toEqual([]);
  });
});
