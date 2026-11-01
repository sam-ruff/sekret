import type { SecretVersion } from "@/api/types";

/** Versions asked for per history page. */
export const HISTORY_PAGE = 50;

/** The `before` cursor for the page after `last`, or undefined when `last` was the final page. */
export function nextHistoryCursor(last: SecretVersion[]): number | undefined {
  if (last.length < HISTORY_PAGE) return undefined;
  return last.reduce((oldest, v) => Math.min(oldest, v.version), Number.MAX_SAFE_INTEGER);
}

/**
 * The history to draw: the pages whose values have arrived, in order, then the rest without
 * values. `revealed` is undefined until the newest page's values arrive.
 */
export function mergeHistory(
  plainPages: readonly SecretVersion[][],
  valuePages: readonly (SecretVersion[] | undefined)[],
): { revealed: SecretVersion[] | undefined; list: SecretVersion[] } {
  const loaded: SecretVersion[][] = [];
  for (const page of valuePages) {
    if (!page) break;
    loaded.push(page);
  }
  const plain = plainPages.flat();
  if (loaded.length === 0) return { revealed: undefined, list: plain };
  const revealed = loaded.flat();
  const oldest = revealed.reduce((min, v) => Math.min(min, v.version), Number.MAX_SAFE_INTEGER);
  return { revealed, list: [...revealed, ...plain.filter((v) => v.version < oldest)] };
}

/** Whether two versions hold the same visible value and tags, so rolling one back to the other changes nothing. */
export function sameContent(a: SecretVersion, b: SecretVersion | undefined): boolean {
  if (!b || a.value_hidden || b.value_hidden || a.deleted || b.deleted) return false;
  if (a.value == null || a.value !== b.value) return false;
  return [...a.tags].sort().join("\n") === [...b.tags].sort().join("\n");
}
