import { Search, X } from "lucide-react";
import type { Status } from "@/api/types";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useSearchText } from "@/hooks/use-search-text";
import { defaultOrder, type ListParams, type SortSpec } from "@/lib/list-params";

const ANY = "any";

interface ListToolbarProps<S extends string> {
  list: ListParams<S>;
  spec: SortSpec<S>;
  onChange: (next: ListParams<S>) => void;
  sortLabels: Record<S, string>;
  searchPlaceholder: string;
  testId: string;
}

/** Debounced search, a status filter and, on narrow screens where column headers are hidden, a sort choice. */
export function ListToolbar<S extends string>({ list, spec, onChange, sortLabels, searchPlaceholder, testId }: ListToolbarProps<S>) {
  const [text, setText] = useSearchText(list.q, (q) => onChange({ ...list, q, page: 1 }));

  const sortValue = `${list.sort}:${list.order}`;
  const sortChoices = spec.sorts.flatMap((sort) => {
    const natural = defaultOrder(spec, sort);
    const other = natural === "asc" ? "desc" : "asc";
    const label = sortLabels[sort];
    const describe = (order: string) => (order === natural ? label : `${label}, reversed`);
    return [natural, other].map((order) => ({ value: `${sort}:${order}`, label: describe(order) }));
  });

  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <InputGroup className="sm:max-w-sm">
        <InputGroupAddon>
          <Search />
        </InputGroupAddon>
        <InputGroupInput
          placeholder={searchPlaceholder}
          value={text}
          onChange={(e) => setText(e.target.value)}
          aria-label={searchPlaceholder}
          data-testid={`${testId}-search`}
        />
        {text && (
          <InputGroupAddon align="inline-end">
            <InputGroupButton size="icon-xs" aria-label="Clear search" onClick={() => setText("")}>
              <X />
            </InputGroupButton>
          </InputGroupAddon>
        )}
      </InputGroup>
      <div className="flex gap-2">
        <Select
          value={list.status || ANY}
          onValueChange={(value) => onChange({ ...list, status: value === ANY ? "" : (value as Status), page: 1 })}
        >
          <SelectTrigger className="flex-1 sm:w-36 sm:flex-none" aria-label="Status" data-testid={`${testId}-status`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>Any status</SelectItem>
            <SelectItem value="active" data-testid={`${testId}-status-active`}>
              Active
            </SelectItem>
            <SelectItem value="disabled" data-testid={`${testId}-status-disabled`}>
              Disabled
            </SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={sortValue}
          onValueChange={(value) => {
            const [sort, order] = value.split(":") as [S, "asc" | "desc"];
            onChange({ ...list, sort, order, page: 1 });
          }}
        >
          <SelectTrigger className="flex-1 md:hidden" aria-label="Sort" data-testid={`${testId}-sort`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {sortChoices.map((c) => (
              <SelectItem key={c.value} value={c.value}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
