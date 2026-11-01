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

/** How a folder is named in copy. The top level is "/", matching subfolders such as "/email". */
export function folderLabel(path: string): string {
  return normalisePath(path);
}

export interface Crumb {
  name: string;
  path: string;
}

/** Breadcrumbs from the top folder, named "/", down to `path`. */
export function crumbs(path: string): Crumb[] {
  const trail: Crumb[] = [{ name: "/", path: "/" }];
  let prefix = "";
  for (const name of normalisePath(path).split("/").filter(Boolean)) {
    prefix = `${prefix}/${name}`;
    trail.push({ name, path: prefix });
  }
  return trail;
}

/** The server refuses folder paths longer than this. */
export const MAX_PATH_LENGTH = 512;

/** The folder named by a `?path=` link, or the top folder when the link names one the server would refuse. */
export function folderFromLink(raw: string | null): string {
  if (raw === null || raw.length > MAX_PATH_LENGTH) return "/";
  return normalisePath(raw);
}

const SEGMENT = /^[A-Za-z0-9_.-]+$/;

/** Mirrors the server's folder segment rules so mistakes are caught before a request. */
export function isValidFolderName(name: string): boolean {
  return SEGMENT.test(name) && name !== "." && name !== "..";
}
