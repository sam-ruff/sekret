import type { SnapshotChange } from "@/api/types";
import { folderLabel } from "./paths";

const NAMED = 3;

/** "A", "A and B", "A, B and C", "A, B, C and 4 more". */
function nameList(names: string[]): string {
  if (names.length > NAMED) return `${names.slice(0, NAMED).join(", ")} and ${names.length - NAMED} more`;
  if (names.length === 1) return names[0];
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

function changeName(change: SnapshotChange): string {
  return change.path === "/" ? change.key : `${change.path}/${change.key}`;
}

/**
 * What restoring a snapshot does, built from the change kinds so the confirmation names
 * the secrets it would remove rather than calling every change a new version.
 */
export function restoreSummary(changes: SnapshotChange[], path: string, envName: string): string {
  const named = (kind: SnapshotChange["kind"]) => changes.filter((c) => c.kind === kind).map(changeName);
  const removed = named("removed");
  const added = named("added");
  const changed = named("changed");
  const actions = [
    removed.length > 0 && `removes ${nameList(removed)}`,
    added.length > 0 && `brings back ${nameList(added)}`,
    changed.length > 0 && `changes ${nameList(changed)}`,
  ].filter((a): a is string => typeof a === "string");
  if (actions.length === 0) return `${folderLabel(path)} in ${envName} already matches this snapshot.`;
  const what = `Restoring ${folderLabel(path)} in ${envName} ${nameList(actions)}.`;
  const history =
    removed.length > 0
      ? "Each change is saved as a new version, so removed secrets keep their history and this can be undone with another restore."
      : "Each change is saved as a new version, so history is kept and this can be undone with another restore.";
  return `${what} ${history}`;
}

const COUNTS =/^(\d+) created, (\d+) updated, (\d+) deleted(?: in (.+))?$/;

/**
 * A snapshot's reason as a short title: "1 created, 2 updated, 0 deleted in /payments" becomes
 * "1 secret added, 2 changed in /payments". Reasons in any other form are kept as they are.
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
    .map(([count, word], index) => {
      // The noun goes on the first count only: "1 secret added, 2 changed".
      if (index > 0) return `${count} ${word}`;
      return `${count} ${count === "1" ? "secret" : "secrets"} ${word}`;
    });
  const what = parts.length > 0 ? parts.join(", ") : "No changes";
  if (!path) return what;
  return `${what} in ${folderLabel(path)}`;
}
