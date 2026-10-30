import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { SortOrder } from "@/api/types";
import { cn } from "@/lib/utils";

interface SortHeaderProps {
  label: string;
  active: boolean;
  order: SortOrder;
  onToggle: () => void;
  testId?: string;
}

/** A column heading that sorts by its column; the arrow shows the current direction. */
export function SortHeader({ label, active, order, onToggle, testId }: SortHeaderProps) {
  const Icon = !active ? ArrowUpDown : order === "asc" ? ArrowUp : ArrowDown;
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        "-mx-1 inline-flex items-center gap-1 rounded-md px-1 py-0.5 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
        active && "text-foreground",
      )}
      aria-label={`Sort by ${label.toLowerCase()}`}
      data-testid={testId}
      data-active={active}
      data-order={active ? order : undefined}
    >
      {label}
      <Icon className={cn("size-3.5", !active && "opacity-50")} />
    </button>
  );
}
