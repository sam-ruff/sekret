import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export interface Column<T> {
  /** Plain label, also shown beside each value on narrow screens. */
  header: ReactNode;
  /** Replaces the header in the wide table only, such as a sort button. */
  heading?: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
  /** Row actions: right-aligned on wide screens and pinned beside the card title on narrow ones. */
  actions?: boolean;
  /** Mark the column that titles each card on narrow screens. */
  primary?: boolean;
}

interface ResponsiveTableProps<T> {
  rows: readonly T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  rowTestId?: (row: T) => string;
  onRowClick?: (row: T) => void;
  className?: string;
}

/** A table on wide screens that becomes a list of stacked cards on narrow ones, from a single DOM. */
export function ResponsiveTable<T>({ rows, columns, rowKey, rowTestId, onRowClick, className }: ResponsiveTableProps<T>) {
  return (
    <div className={cn("md:overflow-hidden md:rounded-xl md:border md:bg-card", className)}>
      <table className="w-full text-sm">
        <thead className="hidden border-b bg-muted/40 md:table-header-group">
          <tr>
            {columns.map((c, i) => (
              <th
                key={i}
                className={cn("h-10 px-4 text-left text-xs font-medium text-muted-foreground", c.className)}
              >
                {c.actions ? <span className="sr-only">Actions</span> : (c.heading ?? c.header)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="flex flex-col gap-2 md:table-row-group">
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              data-testid={rowTestId?.(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={cn(
                "grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-2 rounded-xl border bg-card p-4 md:table-row md:rounded-none md:border-0 md:border-b md:bg-transparent md:p-0 md:last:border-b-0",
                onRowClick && "cursor-pointer transition-colors hover:bg-muted/50",
              )}
            >
              {columns.map((c, i) => (
                <td
                  key={i}
                  className={cn(
                    "col-span-2 flex min-w-0 items-center justify-between gap-4 md:table-cell md:px-4 md:py-3 md:align-middle",
                    c.primary && "col-span-1 col-start-1 row-start-1 font-medium",
                    c.actions && "col-span-1 col-start-2 row-start-1 justify-end self-start",
                    c.className,
                  )}
                >
                  {!c.primary && !c.actions && (
                    <span className="shrink-0 text-xs text-muted-foreground md:hidden">{c.header}</span>
                  )}
                  <div className={cn("min-w-0", c.actions ? "flex items-center justify-end gap-2" : "md:contents")}>
                    {c.cell(row)}
                  </div>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
