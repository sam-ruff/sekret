import { X } from "lucide-react";
import { useState, type KeyboardEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ListInputProps {
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  id?: string;
  testId?: string;
  /** Applied to each entry before adding, e.g. lower-casing tags. */
  normalise?: (entry: string) => string;
  validate?: (entry: string) => string | undefined;
  mono?: boolean;
  disabled?: boolean;
}

/** Chips for a list of strings; Enter, comma or blur adds the typed entry. */
export function ListInput({
  value,
  onChange,
  placeholder,
  id,
  testId,
  normalise = (s) => s.trim(),
  validate,
  mono,
  disabled,
}: ListInputProps) {
  const [draft, setDraft] = useState("");
  const [problem, setProblem] = useState<string>();

  const commit = () => {
    const entry = normalise(draft);
    if (!entry) return;
    const issue = validate?.(entry);
    if (issue) {
      setProblem(issue);
      return;
    }
    if (!value.includes(entry)) onChange([...value, entry]);
    setDraft("");
    setProblem(undefined);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      commit();
      return;
    }
    if (event.key === "Backspace" && draft === "" && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div className="space-y-1">
      <div
        className={cn(
          "flex min-h-8 flex-wrap items-center gap-1 rounded-lg border border-input bg-transparent px-1.5 py-1 focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 dark:bg-input/30",
          problem && "border-destructive",
          disabled && "opacity-50",
        )}
        data-testid={testId}
      >
        {value.map((entry) => (
          <Badge key={entry} variant="secondary" className={cn("h-6 gap-1 pr-1", mono && "font-mono")}>
            {entry}
            {!disabled && (
              <button
                type="button"
                onClick={() => onChange(value.filter((v) => v !== entry))}
                aria-label={`Remove ${entry}`}
                className="relative rounded-sm opacity-60 after:absolute after:-inset-1.5 after:content-[''] hover:opacity-100"
              >
                <X className="size-3" />
              </button>
            )}
          </Badge>
        ))}
        <input
          id={id}
          value={draft}
          disabled={disabled}
          onChange={(e) => {
            setDraft(e.target.value);
            setProblem(undefined);
          }}
          onKeyDown={onKeyDown}
          onBlur={commit}
          placeholder={value.length === 0 ? placeholder : undefined}
          className={cn("h-6 min-w-24 flex-1 bg-transparent px-1 text-sm outline-none placeholder:text-muted-foreground", mono && "font-mono")}
          data-testid={testId ? `${testId}-input` : undefined}
        />
      </div>
      {problem && <p className="text-xs text-destructive">{problem}</p>}
    </div>
  );
}
