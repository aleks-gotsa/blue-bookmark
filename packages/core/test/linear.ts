import { expect } from "vitest";
import { scan } from "../src";

// Timing checks that machine load cannot break: instead of a wall-clock budget, double the input and compare.
// Linear code takes about twice as long, quadratic code about four times; below FLOOR_MS both sizes are too fast to
// compare. A ceiling still catches a hang.
const FLOOR_MS = 50;
const MAX_GROWTH = 3;

function best(run: () => unknown, runs: number): number {
  let min = Infinity;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    run();
    min = Math.min(min, performance.now() - t0);
  }
  return min;
}

export function expectLinear(label: string, make: (n: number) => string, n: number, run: (text: string) => unknown = scan, ceilingMs = 20_000): void {
  const small = make(n);
  const large = make(2 * n);
  best(() => run(small), 1); // warm-up: compile the regexes and fill the caches
  // Under a full parallel suite a short pause in one sample inflated the ratio (five flaky blocks). Load only
  // ever adds time, so each attempt takes the best of interleaved runs, and up to three attempts are made: linear code
  // falls under the limit in one of them, while quadratic code grows about four times in every one.
  let ratio = Infinity;
  let t1 = 0;
  let t2 = 0;
  for (let attempt = 0; attempt < 3 && ratio >= MAX_GROWTH; attempt++) {
    t1 = Infinity;
    t2 = Infinity;
    for (let i = 0; i < 3; i++) {
      t1 = Math.min(t1, best(() => run(small), 1));
      t2 = Math.min(t2, best(() => run(large), 1));
    }
    expect(t2, `${label}: ${Math.round(t2)} ms at ${large.length} chars`).toBeLessThan(ceilingMs);
    if (t2 < FLOOR_MS) return;
    ratio = t2 / Math.max(t1, FLOOR_MS / 4);
  }
  expect(ratio, `${label}: ${Math.round(t1)} -> ${Math.round(t2)} ms when the input doubles`).toBeLessThan(MAX_GROWTH);
}
