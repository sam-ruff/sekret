export type DiffKind = "same" | "added" | "removed";

export interface DiffLine {
  kind: DiffKind;
  text: string;
}

/** The largest table the diff builds, so a value with many lines cannot exhaust memory. */
export const MAX_DIFF_CELLS = 4_000_000;

/**
 * Line diff from `before` to `after` using a longest common subsequence table. Lines shared at the
 * start and end are matched first; returns null when what is left is too large to compare.
 */
export function diffLines(before: string, after: string): DiffLine[] | null {
  const a = before === "" ? [] : before.split("\n");
  const b = after === "" ? [] : after.split("\n");

  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA -= 1;
    endB -= 1;
  }

  const middle = diffMiddle(a.slice(start, endA), b.slice(start, endB));
  if (middle === null) return null;
  const same = (text: string): DiffLine => ({ kind: "same", text });
  return [...a.slice(0, start).map(same), ...middle, ...a.slice(endA).map(same)];
}

function diffMiddle(a: string[], b: string[]): DiffLine[] | null {
  const rows = a.length + 1;
  const cols = b.length + 1;
  if (rows * cols > MAX_DIFF_CELLS) return null;
  const lcs = new Uint32Array(rows * cols);
  const at = (i: number, j: number) => lcs[i * cols + j];

  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      lcs[i * cols + j] = a[i] === b[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] });
      i += 1;
      j += 1;
    } else if (at(i + 1, j) >= at(i, j + 1)) {
      out.push({ kind: "removed", text: a[i] });
      i += 1;
    } else {
      out.push({ kind: "added", text: b[j] });
      j += 1;
    }
  }
  for (; i < a.length; i += 1) out.push({ kind: "removed", text: a[i] });
  for (; j < b.length; j += 1) out.push({ kind: "added", text: b[j] });
  return out;
}
