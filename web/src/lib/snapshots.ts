const COUNTS = /^(\d+) created, (\d+) updated, (\d+) deleted(?: in (.+))?$/;

/**
 * A snapshot's reason as a short title: "1 created, 0 updated, 0 deleted in /payments" becomes
 * "1 added in /payments". Reasons in any other form are kept as they are.
 */
export function snapshotTitle(reason: string): string {
  const match = COUNTS.exec(reason.trim());
  if (!match) return reason;
  const [, created, updated, deleted, path] = match;
  const parts = [
    [created, "added"],
    [updated, "changed"],
    [deleted, "deleted"],
  ]
    .filter(([count]) => Number(count) > 0)
    .map(([count, word]) => `${count} ${word}`);
  const what = parts.length > 0 ? parts.join(", ") : "No changes";
  if (!path) return what;
  return `${what} in ${path === "/" ? "the top folder" : path}`;
}
