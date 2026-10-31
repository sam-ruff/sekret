/** Normalises a folder path to `/a/b` form; empty or slash-only input becomes `/`. */
export function normalisePath(path: string): string {
  const segments = path.split("/").filter(Boolean);
  return `/${segments.join("/")}`;
}

export function joinPath(base: string, child: string): string {
  return normalisePath(`${base}/${child}`);
}

export function parentPath(path: string): string {
  const segments = normalisePath(path).split("/").filter(Boolean);
  return `/${segments.slice(0, -1).join("/")}`;
}

/** How a folder is named in copy: the top level is "root", as in the breadcrumbs. */
export function folderLabel(path: string): string {
  const normalised = normalisePath(path);
  return normalised === "/" ? "root" : normalised;
}

export interface Crumb {
  name: string;
  path: string;
}

/** Breadcrumbs from the root down to `path`, the root named "root". */
export function crumbs(path: string): Crumb[] {
  const segments = normalisePath(path).split("/").filter(Boolean);
  return [
    { name: "root", path: "/" },
    ...segments.map((name, i) => ({ name, path: `/${segments.slice(0, i + 1).join("/")}` })),
  ];
}

const SEGMENT = /^[A-Za-z0-9_.-]+$/;

/** Mirrors the server's folder segment rules so mistakes are caught before a request. */
export function isValidFolderName(name: string): boolean {
  return SEGMENT.test(name) && name !== "." && name !== "..";
}
