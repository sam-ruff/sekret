import { Check, ChevronsUpDown } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Spinner } from "@/components/ui/spinner";
import { useIdentityPage, useUserPage } from "@/hooks/queries";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { cn } from "@/lib/utils";

export interface PrincipalOption {
  id: string;
  /** Shown first: a user's email, or an identity's name. */
  label: string;
  hint?: string;
  /** A user's display name, or an identity's name. */
  name?: string;
}

const RESULTS = 20;

interface PrincipalPickerProps {
  kind: "user" | "identity";
  selected: PrincipalOption | undefined;
  onSelect: (option: PrincipalOption) => void;
  /** False when the caller may not list this kind of principal. */
  canList?: boolean;
  id?: string;
  testId?: string;
}

/** A searchable choice of user or machine identity that asks the server for matches as you type. */
export function PrincipalPicker({ kind, selected, onSelect, canList = true, id, testId }: PrincipalPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search.trim(), 250);
  const query = { ...(q ? { q } : {}), status: "active" as const, limit: RESULTS };
  const users = useUserPage({ ...query, sort: "name" }, open && canList && kind === "user");
  const identities = useIdentityPage({ ...query, sort: "name" }, open && canList && kind === "identity");

  const page = kind === "user" ? users : identities;
  // Users lead with their email, as the access list names them, so a look-alike name cannot pass for someone.
  const fetched: (PrincipalOption & { searchable: string[] })[] =
    kind === "user"
      ? (users.data?.items ?? []).map((u) => ({
          id: u.id,
          label: u.email || u.name,
          hint: u.email && u.name ? u.name : undefined,
          name: u.name || u.email,
          searchable: [u.name, u.email, u.id, ...u.groups],
        }))
      : (identities.data?.items ?? []).map((i) => ({
          id: i.id,
          label: i.name,
          hint: i.description || undefined,
          name: i.name,
          searchable: [i.name, i.description, i.id],
        }));
  const total = page.data?.total ?? 0;
  const noun = kind === "user" ? "user" : "machine identity";
  const settling = q !== search.trim() || page.isFetching;
  // What is on screen narrows as you type, until the server has answered for the text typed.
  const typed = search.trim().toLowerCase();
  const options =
    typed && settling ? fetched.filter((o) => o.searchable.some((text) => text.toLowerCase().includes(typed))) : fetched;
  // The highlighted option follows the results, so Enter picks the first match on screen.
  const [active, setActive] = useState("");
  const firstId = options[0]?.id ?? "";
  const [shownFirst, setShownFirst] = useState(firstId);
  if (shownFirst !== firstId) {
    setShownFirst(firstId);
    setActive(firstId);
  }
  const pick = (option: PrincipalOption) => {
    onSelect(option);
    setOpen(false);
    setSearch("");
  };

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setSearch("");
      }}
    >
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between font-normal"
          data-testid={testId}
        >
          <span className={cn("truncate", !selected && "text-muted-foreground")}>
            {selected ? selected.label : `Choose a ${noun}`}
            {selected && kind === "user" && selected.hint && (
              <span className="text-muted-foreground"> · {selected.hint}</span>
            )}
          </span>
          <ChevronsUpDown className="opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-(--radix-popover-trigger-width) min-w-64 p-0" align="start">
        <Command
          shouldFilter={false}
          value={active}
          onValueChange={setActive}
          onKeyDown={(event) => {
            // Enter waits for the search to catch up, so it never picks a stale match.
            if (event.key === "Enter" && settling) event.preventDefault();
          }}
        >
          <CommandInput
            value={search}
            onValueChange={setSearch}
            placeholder={kind === "user" ? "Search name, email or group" : "Search identities"}
            aria-busy={settling}
            data-testid={testId ? `${testId}-search` : undefined}
          />
          <CommandList>
            {!canList && <div className="px-3 py-4 text-sm text-muted-foreground">You cannot list these.</div>}
            {canList && page.isPending && (
              <div className="flex items-center gap-2 px-3 py-4 text-sm text-muted-foreground">
                <Spinner /> Loading
              </div>
            )}
            {canList && page.isSuccess && !settling && <CommandEmpty>No {noun} matches.</CommandEmpty>}
            {canList && page.isSuccess && settling && (
              <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground" data-testid="principal-searching">
                <Spinner /> Searching
              </div>
            )}
            {options.length > 0 && (
              <CommandGroup>
                {options.map((o) => (
                  <CommandItem
                    key={o.id}
                    value={o.id}
                    onSelect={() => pick(o)}
                    data-testid={`principal-option-${o.name ?? o.label}`}
                  >
                    <Check className={cn(selected?.id === o.id ? "opacity-100" : "opacity-0")} />
                    <div className="min-w-0">
                      <div className="truncate">{o.label}</div>
                      {o.hint && <div className="truncate text-xs text-muted-foreground">{o.hint}</div>}
                    </div>
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
          </CommandList>
          {total > options.length && (
            <p className="border-t px-3 py-2 text-xs text-muted-foreground" data-testid="principal-more">
              Showing {options.length} of {total}. Keep typing to narrow it down.
            </p>
          )}
        </Command>
      </PopoverContent>
    </Popover>
  );
}
