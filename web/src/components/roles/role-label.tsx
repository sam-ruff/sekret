import { Badge } from "@/components/ui/badge";

/** A role by its display name, with its ID underneath when the two differ. */
export function RoleLabel({ name, id }: { name: string; id: string }) {
  return (
    <span className="inline-flex min-w-0 flex-col items-start gap-0.5" data-testid="role-label">
      <Badge variant="secondary" className="max-w-full">
        <span className="truncate first-letter:uppercase" data-testid="role-label-name">
          {name}
        </span>
      </Badge>
      {name !== id && (
        <span className="truncate font-mono text-[0.7rem] text-muted-foreground" data-testid="role-label-id">
          {id}
        </span>
      )}
    </span>
  );
}
