import type { ReactNode } from "react";
import { usePageTitle } from "@/hooks/use-page-title";

interface PageHeaderProps {
  title: ReactNode;
  /** The browser tab's title, when `title` is not plain text. */
  documentTitle?: string;
  description?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ title, documentTitle, description, actions }: PageHeaderProps) {
  usePageTitle(documentTitle ?? (typeof title === "string" ? title : undefined));
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0 space-y-1">
        <h1 className="truncate text-2xl font-semibold" data-testid="page-title">
          {title}
        </h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
