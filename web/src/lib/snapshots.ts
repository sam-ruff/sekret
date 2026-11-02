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

export interface SnapshotEffect {
  path: string;
  key: string;
  kind: "added" | "changed" | "deleted";
}

type KeyState = { present: false } | { present: true; version: number | null | undefined };

const changeId = (change: { path: string; key: string }) => `${change.path}\u0000${change.key}`;

/** A key's state in the snapshot a change was listed for. */
function snapshotState(change: SnapshotChange): KeyState {
  if (change.kind === "removed") return { present: false };
  return { present: true, version: change.snapshot_version };
}

/** A key's state now, as any change listing it shows. */
function currentState(change: SnapshotChange): KeyState {
  if (change.kind === "added") return { present: false };
  return { present: true, version: change.current_version };
}

/**
 * What one snapshot's change did, from what restoring it and the snapshot before it would each
 * change. A key either list leaves out is as it is now in that snapshot.
 */
export function snapshotEffect(before: SnapshotChange[], after: SnapshotChange[]): SnapshotEffect[] {
  const beforeById = new Map(before.map((c) => [changeId(c), c]));
  const afterById = new Map(after.map((c) => [changeId(c), c]));
  const effects: SnapshotEffect[] = [];
  for (const id of new Set([...beforeById.keys(), ...afterById.keys()])) {
    const was = beforeById.get(id);
    const is = afterById.get(id);
    const listed = was ?? is;
    if (!listed) continue;
    const now = currentState(listed);
    const from = was ? snapshotState(was) : now;
    const to = is ? snapshotState(is) : now;
    const where = { path: listed.path, key: listed.key };
    if (!from.present && to.present) effects.push({ ...where, kind: "added" });
    else if (from.present && !to.present) effects.push({ ...where, kind: "deleted" });
    else if (from.present && to.present && from.version !== to.version) effects.push({ ...where, kind: "changed" });
  }
  return effects.sort((a, b) => a.path.localeCompare(b.path) || a.key.localeCompare(b.key));
}

/** Restore changes to secrets the snapshot's own change did not touch. */
export function unrelatedChanges(changes: SnapshotChange[], effect: SnapshotEffect[]): number {
  const touched = new Set(effect.map(changeId));
  return changes.filter((c) => !touched.has(changeId(c))).length;
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
