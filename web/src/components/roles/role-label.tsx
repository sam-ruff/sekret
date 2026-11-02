import { Badge } from "@/components/ui/badge";

/**
 * A role by its display name. The ID, which the CLI takes, is in the tooltip rather than under
 * the name, so built-in and custom roles line up alike.
 */
export function RoleLabel({ name, id }: { name: string; id: string }) {
  return (
    <Badge variant="secondary" className="max-w-full" title={`Role ID: ${id}`} data-testid="role-label" data-role-id={id}>
      <span className="truncate first-letter:uppercase" data-testid="role-label-name">
        {name}
      </span>
    </Badge>
  );
}
