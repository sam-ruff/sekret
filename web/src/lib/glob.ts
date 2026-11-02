/**
 * Port of the server's glob matcher. `*` matches any run of characters except `separator`
 * (or anything when there is none), `**` also crosses the separator, and `?` matches one
 * non-separator character. A trailing `/**` also matches the folder itself, so `/a/**` covers `/a`.
 */
export function globMatch(pattern: string, text: string, separator?: string): boolean {
  const folder = trailingSegmentsParent(pattern, separator);
  if (folder !== null && matches(folder, text, separator)) return true;
  return matches(pattern, text, separator);
}

/** The pattern without its trailing `<separator>**`, when it ends that way. */
function trailingSegmentsParent(pattern: string, separator?: string): string | null {
  if (separator === undefined) return null;
  const trimmed = pattern.replace(/\*+$/, "");
  if (pattern.length - trimmed.length < 2 || !trimmed.endsWith(separator)) return null;
  return trimmed.slice(0, -separator.length);
}

function matches(pattern: string, text: string, separator?: string): boolean {
  const p = Array.from(pattern);
  const t = Array.from(text);
  const memo = new Map<number, boolean>();
  const width = t.length + 1;

  const step = (pi: number, ti: number): boolean => {
    const id = pi * width + ti;
    const known = memo.get(id);
    if (known !== undefined) return known;
    const result = evaluate(pi, ti);
    memo.set(id, result);
    return result;
  };

  const evaluate = (pi: number, ti: number): boolean => {
    if (pi >= p.length) return ti === t.length;
    const c = p[pi];
    if (c === "?") return ti < t.length && t[ti] !== separator && step(pi + 1, ti + 1);
    if (c !== "*") return ti < t.length && t[ti] === c && step(pi + 1, ti + 1);

    const double = p[pi + 1] === "*";
    const next = double ? pi + 2 : pi + 1;
    const crosses = double || separator === undefined;
    // `/**/` may also match a single `/` so `/a/**/b` covers `/a/b`.
    const collapse =
      double && pi > 0 && separator !== undefined && p[pi - 1] === separator && p[next] === separator;
    if (collapse && step(next + 1, ti)) return true;
    let end = ti;
    if (step(next, end)) return true;
    while (end < t.length && (crosses || t[end] !== separator)) {
      end += 1;
      if (step(next, end)) return true;
    }
    return false;
  };

  return step(0, 0);
}

const PLAIN_SEGMENT = /^[A-Za-z0-9_.\-*?]+$/;

/** Mirrors the server: whether a folder pattern could ever match a stored path such as `/a/b`. */
export function pathPatternCanMatch(pattern: string): boolean {
  if (!pattern.startsWith("/")) return false;
  const rest = pattern.slice(1);
  if (rest === "") return true;
  return rest.split("/").every((segment) => segment !== "." && segment !== ".." && PLAIN_SEGMENT.test(segment));
}

/** Mirrors the server: whether a key pattern could ever match a key, which starts with a letter or `_`. */
export function keyPatternCanMatch(pattern: string): boolean {
  return /^[A-Za-z_*?][A-Za-z0-9_.\-*?]*$/.test(pattern);
}
