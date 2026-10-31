import type { ReactNode } from "react";
import { ThemeToggle } from "@/components/layout/user-menu";
import { cn } from "@/lib/utils";

/** A centred page outside the app shell, for setup, unlocking and the checks before them. */
export function StandalonePage({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="relative flex min-h-svh justify-center bg-gradient-to-b from-primary/10 via-background to-background px-4 py-16 sm:items-center">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className={cn("w-full max-w-md", className)}>{children}</div>
    </div>
  );
}
