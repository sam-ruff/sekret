import type { ReactNode } from "react";
import { ThemeToggle } from "@/components/layout/user-menu";
import { Logo } from "@/components/logo";
import { CardDescription, CardHeader } from "@/components/ui/card";
import { usePageTitle } from "@/hooks/use-page-title";
import { cn } from "@/lib/utils";

/** A centred page outside the app shell, for signing in, setup, unlocking and the checks before them. */
export function StandalonePage({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="relative flex min-h-svh items-center justify-center bg-gradient-to-b from-primary/10 via-background to-background px-4 py-16">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className={cn("w-full max-w-md", className)}>{children}</div>
    </div>
  );
}

interface StandaloneHeaderProps {
  title: string;
  /** The browser tab's title. */
  pageTitle: string;
  description?: ReactNode;
  /** Shown in the tile above the title; the sekret logo by default. */
  icon?: ReactNode;
}

/** The one header every standalone page uses: an icon tile, the page's h1 and a line of description. */
export function StandaloneHeader({ title, pageTitle, description, icon }: StandaloneHeaderProps) {
  usePageTitle(pageTitle);
  return (
    <CardHeader>
      <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary [&_svg]:size-5">
        {icon ?? <Logo title="sekret" />}
      </div>
      <h1 className="font-heading text-xl leading-snug font-medium" data-testid="standalone-title">
        {title}
      </h1>
      {description && <CardDescription>{description}</CardDescription>}
    </CardHeader>
  );
}
