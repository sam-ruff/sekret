import { AlertCircle, RotateCw } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "@/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/errors";

interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  testId?: string;
}

export function EmptyState({ icon, title, description, action, testId }: EmptyStateProps) {
  return (
    <Empty className="border bg-card/50 py-12" data-testid={testId}>
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon}</EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  );
}

function errorTitle(error: unknown): string {
  if (!(error instanceof ApiError)) return "That did not load";
  if (error.status === 404) return "Not found";
  if (error.status === 403) return "You do not have access";
  return "That did not load";
}

/** Retrying cannot fix a missing resource or a refused permission. */
function isPermanent(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.status === 404);
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <Alert variant="destructive" data-testid="error-state">
      <AlertCircle />
      <AlertTitle>{errorTitle(error)}</AlertTitle>
      <AlertDescription>
        <p>{errorMessage(error)}</p>
        {onRetry && !isPermanent(error) && (
          <Button variant="outline" size="sm" className="mt-2" onClick={onRetry}>
            <RotateCw />
            Try again
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}

export function ListSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" data-testid="loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-12 w-full rounded-lg" />
      ))}
    </div>
  );
}
