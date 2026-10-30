import { Link } from "react-router";
import type { Environment } from "@/api/types";
import { cn } from "@/lib/utils";

interface EnvTabsProps {
  envs: Environment[];
  current: string;
  hrefFor: (env: Environment) => string;
}

/** Environment switcher that scrolls horizontally on narrow screens. */
export function EnvTabs({ envs, current, hrefFor }: EnvTabsProps) {
  return (
    <nav
      className="-mx-4 overflow-x-auto px-4 md:mx-0 md:px-0"
      aria-label="Environments"
      data-testid="env-tabs"
    >
      <div className="inline-flex min-w-full gap-1 rounded-lg bg-muted p-1 md:min-w-0">
        {envs.map((env) => {
          const active = env.slug === current;
          return (
            <Link
              key={env.id}
              to={hrefFor(env)}
              aria-current={active ? "page" : undefined}
              data-testid={`env-tab-${env.slug}`}
              className={cn(
                "flex-1 rounded-md px-3 py-1.5 text-center text-sm font-medium whitespace-nowrap transition-colors md:flex-none",
                active ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {env.name}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
