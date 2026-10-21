// Module caches keyed on the text being scanned hold one input each (up to 2 MB). scan() clears them when it returns,
// so a long-running worker does not keep the last input alive between scans.
const caches: { clear: () => void; holds: () => boolean }[] = [];

export function registerScanCache(clear: () => void, holds: () => boolean): void {
  caches.push({ clear, holds });
}

export function clearScanCaches(): void {
  for (const c of caches) c.clear();
}

/** How many caches still hold an input; for tests. */
export function scanCachesHolding(): number {
  return caches.filter((c) => c.holds()).length;
}
