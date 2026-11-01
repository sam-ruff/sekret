import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/** Says why a form's submit button is disabled; point the button's `aria-describedby` at `id`. */
export function FormBlocker({
  id,
  testId,
  className,
  children,
}: {
  id: string;
  testId?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <p id={id} className={cn("text-sm text-muted-foreground", className)} data-testid={testId}>
      {children}
    </p>
  );
}
