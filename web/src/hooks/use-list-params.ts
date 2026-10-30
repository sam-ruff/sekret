import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";
import { listSearchParams, parseListParams, type ListParams, type SortSpec } from "@/lib/list-params";

/** Search, filter, sort and page state for a server-paged list, kept in the URL so it survives reloads and links. */
export function useListParams<S extends string>(spec: SortSpec<S>) {
  const [params, setParams] = useSearchParams();
  const list = useMemo(() => parseListParams(params, spec), [params, spec]);
  const update = useCallback(
    (next: ListParams<S>) => setParams(listSearchParams(next, spec), { replace: true }),
    [setParams, spec],
  );
  return { list, update };
}
