/**
 * Port of the server's glob matcher. `*` matches any run of characters except `separator`
 * (or anything when there is none), `**` also crosses the separator, and `?` matches one
 * non-separator character.
 */
export function globMatch(pattern: string, text: string, separator?: string): boolean {
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
