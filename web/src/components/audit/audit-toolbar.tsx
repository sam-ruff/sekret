import { ArrowDownWideNarrow, ArrowUpNarrowWide, CalendarDays, Search, X } from "lucide-react";
import { useState } from "react";
import type { Environment } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useSearchText } from "@/hooks/use-search-text";
import {
  ACTION_CATEGORIES,
  DATE_PRESETS,
  dateRangeLabel,
  presetRange,
  type ActorKind,
  type AuditFilters,
} from "@/lib/audit-filters";
import { cn } from "@/lib/utils";

const ALL = "all";

interface AuditToolbarProps {
  filters: AuditFilters;
  onChange: (next: AuditFilters) => void;
  scope: "project" | "org";
  /** Offered as a filter on project pages. */
  environments?: Environment[];
}

function SearchBox({ value, onSearch }: { value: string; onSearch: (q: string) => void }) {
  const [text, setText] = useSearchText(value, onSearch);
  return (
    <InputGroup className="min-w-0 lg:max-w-xs">
      <InputGroupAddon>
        <Search />
      </InputGroupAddon>
      <InputGroupInput
        placeholder="Search actions, people, keys, addresses"
        aria-label="Search the audit log"
        value={text}
        onChange={(e) => setText(e.target.value)}
        data-testid="audit-search"
      />
      {text && (
        <InputGroupAddon align="inline-end">
          <InputGroupButton size="icon-xs" aria-label="Clear search" onClick={() => setText("")}>
            <X />
          </InputGroupButton>
        </InputGroupAddon>
      )}
    </InputGroup>
  );
}

function DateRange({ from, to, onChange }: { from: string; to: string; onChange: (from: string, to: string) => void }) {
  const [open, setOpen] = useState(false);
  const label = dateRangeLabel(from, to);
  const active = from !== "" || to !== "";
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn("min-w-0 justify-start font-normal", active && "border-primary/50 text-foreground")}
          data-testid="audit-date"
        >
          <CalendarDays />
          <span className="truncate">{label}</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 max-w-[calc(100vw-2rem)] gap-3 p-3" data-testid="audit-date-panel">
        <div className="grid grid-cols-2 gap-1.5">
          {DATE_PRESETS.map((preset) => {
            const range = presetRange(preset);
            const selected = range.from === from && range.to === to;
            return (
              <Button
                key={preset.id}
                variant={selected ? "secondary" : "ghost"}
                size="sm"
                className="justify-start"
                onClick={() => {
                  onChange(range.from, range.to);
                  setOpen(false);
                }}
                data-testid={`audit-date-${preset.id}`}
              >
                {preset.label}
              </Button>
            );
          })}
        </div>
        <div className="grid grid-cols-2 gap-2 border-t pt-3">
          <Field className="gap-1.5">
            <FieldLabel htmlFor="audit-from" className="text-xs">
              From
            </FieldLabel>
            <Input
              id="audit-from"
              type="date"
              value={from}
              max={to || undefined}
              onChange={(e) => onChange(e.target.value, to)}
              data-testid="audit-from"
            />
          </Field>
          <Field className="gap-1.5">
            <FieldLabel htmlFor="audit-to" className="text-xs">
              To
            </FieldLabel>
            <Input
              id="audit-to"
              type="date"
              value={to}
              min={from || undefined}
              onChange={(e) => onChange(from, e.target.value)}
              data-testid="audit-to"
            />
          </Field>
        </div>
        {active && (
          <Button
            variant="ghost"
            size="sm"
            className="self-end"
            onClick={() => {
              onChange("", "");
              setOpen(false);
            }}
            data-testid="audit-date-clear"
          >
            Any time
          </Button>
        )}
      </PopoverContent>
    </Popover>
  );
}

export function AuditToolbar({ filters, onChange, scope, environments }: AuditToolbarProps) {
  const set = (patch: Partial<AuditFilters>) => onChange({ ...filters, ...patch });
  const categories = ACTION_CATEGORIES.filter((c) => scope === "org" || c.scope !== "org");
  const newestFirst = filters.order === "desc";
  const withEnvironments = (environments?.length ?? 0) > 0;

  return (
    <div className="flex flex-col gap-2 lg:flex-row lg:flex-wrap lg:items-center" data-testid="audit-toolbar">
      <SearchBox value={filters.q} onSearch={(q) => set({ q })} />
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center">
        <Select value={filters.action || ALL} onValueChange={(v) => set({ action: v === ALL ? "" : v })}>
          <SelectTrigger className="w-full sm:w-44" aria-label="Action" data-testid="audit-action-filter">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All actions</SelectItem>
            {categories.map((c) => (
              <SelectItem key={c.prefix} value={c.prefix} data-testid={`audit-action-${c.prefix.replace(/\.$/, "")}`}>
                {c.label}
              </SelectItem>
            ))}
            {filters.action && !categories.some((c) => c.prefix === filters.action) && (
              <SelectItem value={filters.action}>
                <span className="font-mono text-xs">{filters.action}</span>
              </SelectItem>
            )}
          </SelectContent>
        </Select>
        <Select value={filters.actorKind || ALL} onValueChange={(v) => set({ actorKind: v === ALL ? "" : (v as ActorKind) })}>
          <SelectTrigger className="w-full sm:w-36" aria-label="Actor" data-testid="audit-actor-kind">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Anyone</SelectItem>
            <SelectItem value="user" data-testid="audit-actor-kind-user">
              People
            </SelectItem>
            <SelectItem value="identity" data-testid="audit-actor-kind-identity">
              Machines
            </SelectItem>
          </SelectContent>
        </Select>
        {environments && withEnvironments && (
          <Select value={filters.environment || ALL} onValueChange={(v) => set({ environment: v === ALL ? "" : v })}>
            <SelectTrigger className="w-full sm:w-40" aria-label="Environment" data-testid="audit-environment">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All environments</SelectItem>
              {environments.map((e) => (
                <SelectItem key={e.slug} value={e.slug} data-testid={`audit-environment-${e.slug}`}>
                  {e.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <DateRange from={filters.from} to={filters.to} onChange={(from, to) => set({ from, to })} />
        <Button
          variant="outline"
          className={cn("justify-start font-normal", withEnvironments && "col-span-2 sm:col-span-1")}
          onClick={() => set({ order: newestFirst ? "asc" : "desc" })}
          aria-label={newestFirst ? "Newest first; show oldest first" : "Oldest first; show newest first"}
          data-testid="audit-order"
          data-order={filters.order}
        >
          {newestFirst ? <ArrowDownWideNarrow /> : <ArrowUpNarrowWide />}
          {newestFirst ? "Newest first" : "Oldest first"}
        </Button>
      </div>
    </div>
  );
}
