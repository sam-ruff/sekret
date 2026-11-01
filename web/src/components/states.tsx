import { AlertCircle, Compass, RotateCw } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
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
  /** Renders the title as a heading, for states that stand in for a whole page. */
  headingLevel?: 1 | 2;
}

export function EmptyState({ icon, title, description, action, testId, headingLevel }: EmptyStateProps) {
  const Heading = headingLevel === 1 ? "h1" : "h2";
  return (
    <Empty className="border bg-card/50 py-12" data-testid={testId}>
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon}</EmptyMedia>
        {headingLevel ? (
          <Heading data-slot="empty-title" className="font-heading text-base font-medium tracking-tight">
            {title}
          </Heading>
        ) : (
          <EmptyTitle>{title}</EmptyTitle>
        )}
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

/** A missing project, identity or environment, with a way back to somewhere that exists. */
export function MissingState({
  title,
  description,
  backTo,
  backLabel,
  testId = "missing",
  headingLevel = 1,
}: {
  title: string;
  description: string;
  backTo: string;
  backLabel: string;
  testId?: string;
  /** 1 when this stands in for the whole page, 2 inside a page that has its own title. */
  headingLevel?: 1 | 2;
}) {
  return (
    <EmptyState
      icon={<Compass />}
      title={title}
      headingLevel={headingLevel}
      description={description}
      action={
        <Button asChild>
          <Link to={backTo} data-testid={`${testId}-back`}>
            {backLabel}
          </Link>
        </Button>
      }
      testId={testId}
    />
  );
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
