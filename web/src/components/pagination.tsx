import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { pageCount, pageSummary, PAGE_SIZE } from "@/lib/list-params";

interface PaginationProps {
  page: number;
  shown: number;
  total: number;
  pageSize?: number;
  busy?: boolean;
  onPage: (page: number) => void;
  /** The URL query these results belong to, so tests can tell fresh results from the previous ones. */
  filters?: string;
  testId?: string;
}

export function Pagination({ page, shown, total, pageSize = PAGE_SIZE, busy, onPage, filters, testId = "pagination" }: PaginationProps) {
  const pages = pageCount(total, pageSize);
  return (
    <div
      className="flex items-center justify-between gap-3 text-sm"
      data-testid={testId}
      data-fetching={!!busy}
      data-filters={filters}
    >
      <p className="flex items-center gap-2 text-muted-foreground tabular-nums" data-testid={`${testId}-summary`}>
        {pageSummary(page, shown, total, pageSize)}
        {busy && <Spinner className="size-3.5" />}
      </p>
      {pages > 1 && (
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => onPage(page - 1)}
            aria-label="Previous page"
            data-testid={`${testId}-previous`}
          >
            <ChevronLeft />
            <span className="hidden sm:inline">Previous</span>
          </Button>
          <span className="px-2 text-xs text-muted-foreground tabular-nums">
            {page} / {pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= pages}
            onClick={() => onPage(page + 1)}
            aria-label="Next page"
            data-testid={`${testId}-next`}
          >
            <span className="hidden sm:inline">Next</span>
            <ChevronRight />
          </Button>
        </div>
      )}
    </div>
  );
}
