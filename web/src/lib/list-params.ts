import type { SortOrder, Status } from "@/api/types";

export const PAGE_SIZE = 25;

export interface ListParams<S extends string> {
  q: string;
  status: Status | "";
  sort: S;
  order: SortOrder;
  /** One-based. */
  page: number;
}

export interface SortSpec<S extends string> {
  sorts: readonly S[];
  fallback: S;
  /** Sorts whose natural direction is newest first. */
  descending: readonly S[];
}

export function defaultOrder<S extends string>(spec: SortSpec<S>, sort: S): SortOrder {
  return spec.descending.includes(sort) ? "desc" : "asc";
}

export function parseListParams<S extends string>(params: URLSearchParams, spec: SortSpec<S>): ListParams<S> {
  const rawSort = params.get("sort") as S | null;
  const sort = rawSort && spec.sorts.includes(rawSort) ? rawSort : spec.fallback;
  const rawOrder = params.get("order");
  const status = params.get("status");
  const page = Number(params.get("page"));
  return {
    q: params.get("q")?.trim() ?? "",
    status: status === "active" || status === "disabled" ? status : "",
    sort,
    order: rawOrder === "asc" || rawOrder === "desc" ? rawOrder : defaultOrder(spec, sort),
    page: Number.isInteger(page) && page > 1 ? page : 1,
  };
}

export function listSearchParams<S extends string>(list: ListParams<S>, spec: SortSpec<S>): URLSearchParams {
  const params = new URLSearchParams();
  if (list.q.trim()) params.set("q", list.q.trim());
  if (list.status) params.set("status", list.status);
  if (list.sort !== spec.fallback) params.set("sort", list.sort);
  if (list.order !== defaultOrder(spec, list.sort)) params.set("order", list.order);
  if (list.page > 1) params.set("page", String(list.page));
  return params;
}

export function listQuery<S extends string>(list: ListParams<S>, pageSize = PAGE_SIZE) {
  return {
    ...(list.q ? { q: list.q } : {}),
    ...(list.status ? { status: list.status } : {}),
    sort: list.sort,
    order: list.order,
    offset: (list.page - 1) * pageSize,
    limit: pageSize,
  };
}

/** Clicking the active column flips its direction; another column starts in its natural one. */
export function toggleSort<S extends string>(list: ListParams<S>, spec: SortSpec<S>, sort: S): ListParams<S> {
  const order = list.sort === sort ? (list.order === "asc" ? "desc" : "asc") : defaultOrder(spec, sort);
  return { ...list, sort, order, page: 1 };
}

export function pageCount(total: number, pageSize = PAGE_SIZE): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

/** "Showing 26-50 of 61", or a plain count when everything fits on one page. */
export function pageSummary(page: number, shown: number, total: number, pageSize = PAGE_SIZE): string {
  if (total === 0) return "No results";
  const from = (page - 1) * pageSize + 1;
  const to = from + shown - 1;
  if (shown === 0) return `Nothing on this page of ${total}`;
  return `Showing ${from}-${to} of ${total}`;
}
