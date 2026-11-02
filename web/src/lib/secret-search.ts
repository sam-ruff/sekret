import { normalisePath } from "./paths";

interface Searchable {
  key: string;
  comment: string;
  tags: string[];
}

interface Located {
  path: string;
}

/** Whether a secret's key, comment or a tag contains the search text, ignoring case. */
export function matchesSecret(secret: Searchable, search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (!needle) return true;
  return (
    secret.key.toLowerCase().includes(needle) ||
    secret.comment.toLowerCase().includes(needle) ||
    secret.tags.some((tag) => tag.toLowerCase().includes(needle))
  );
}

/** Where `path` sits below `parent`, such as "payments/eu", or null when it is not below it. */
export function relativeFolder(parent: string, path: string): string | null {
  const base = normalisePath(parent);
  const target = normalisePath(path);
  if (target === base) return null;
  const prefix = base === "/" ? "/" : `${base}/`;
  if (!target.startsWith(prefix)) return null;
  return target.slice(prefix.length);
}

/** How many secrets each folder directly inside `parent` holds, counting the folders inside it. */
export function countByChildFolder(parent: string, secrets: readonly Located[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const secret of secrets) {
    const below = relativeFolder(parent, secret.path);
    if (below === null) continue;
    const child = below.split("/")[0];
    counts.set(child, (counts.get(child) ?? 0) + 1);
  }
  return counts;
}

/** Matching secrets in the folders below `parent`, nearest folders first, then by folder and key. */
export function matchesBelow<T extends Searchable & Located>(parent: string, secrets: readonly T[], search: string): T[] {
  if (!search.trim()) return [];
  const depth = (secret: T) => (relativeFolder(parent, secret.path) ?? "").split("/").length;
  return secrets
    .filter((secret) => relativeFolder(parent, secret.path) !== null && matchesSecret(secret, search))
    .sort((a, b) => depth(a) - depth(b) || a.path.localeCompare(b.path) || a.key.localeCompare(b.key));
}
