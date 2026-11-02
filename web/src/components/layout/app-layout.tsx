import { useQuery } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { useEffect } from "react";
import { Link, Outlet, useLocation, useParams } from "react-router";
import { api } from "@/api/endpoints";
import { ErrorBoundary } from "@/components/error-boundary";
import { ProjectLogo } from "@/components/project-logo";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { keys, useMe, useProjects } from "@/hooks/queries";
import { broadcast } from "@/lib/tab-sync";
import { cn } from "@/lib/utils";
import { AppSidebar } from "./app-sidebar";
import { ThemeToggle, UserMenu } from "./user-menu";

const MAIN_CONTENT_ID = "main-content";

const ORG_SECTIONS: Record<string, string> = {
  identities: "Machine identities",
  users: "Users",
  access: "Access control",
  audit: "Audit log",
  server: "Server",
};

/** The organisation page in view, and the identity on an identity's own page. */
function OrgCrumbs({ section }: { section: string }) {
  const { id } = useParams();
  const identity = useQuery({ queryKey: keys.identity(id ?? ""), queryFn: () => api.identity(id ?? ""), enabled: !!id });
  const label = ORG_SECTIONS[section];
  if (!label) return null;
  // On phones an item's page drops the section, so the item's own name has room.
  return (
    <>
      <ChevronRight className={cn("size-3.5 shrink-0", id && "hidden sm:block")} />
      {id ? (
        <Link
          to={`/org/${section}`}
          className="-my-2 hidden min-w-0 truncate py-3 hover:text-foreground sm:inline"
          data-testid="topbar-section"
        >
          {label}
        </Link>
      ) : (
        <span className="truncate font-medium text-foreground" data-testid="topbar-section">
          {label}
        </span>
      )}
      {id && identity.data && (
        <>
          <ChevronRight className="size-3.5 shrink-0" />
          <span className="truncate font-medium text-foreground" data-testid="topbar-item">
            {identity.data.name}
          </span>
        </>
      )}
    </>
  );
}

function TopbarTitle() {
  const { project } = useParams();
  const { pathname } = useLocation();
  const { data: projects } = useProjects();
  const current = projects?.find((p) => p.slug === project || p.id === project);
  // Once the list has loaded, a slug that is not in it is not shown as if it were a project.
  const name = current?.name ?? (projects ? undefined : project);
  const orgSection = pathname.startsWith("/org/") ? pathname.split("/")[2] : undefined;
  const scope = /^\/org(\/|$)/.test(pathname) ? "Organisation" : /^\/projects(\/|$)/.test(pathname) ? "Projects" : null;

  if (!scope) {
    return (
      <nav className="flex min-w-0 flex-1 items-center gap-1 text-sm" aria-label="Location">
        <span className="truncate font-medium text-foreground" data-testid="topbar-scope">
          Not found
        </span>
      </nav>
    );
  }

  return (
    <nav className="flex min-w-0 flex-1 items-center gap-1 text-sm text-muted-foreground" aria-label="Location">
      <Link
        to={scope === "Projects" ? "/projects" : "/org/identities"}
        className="-my-2 shrink-0 py-3 hover:text-foreground"
        data-testid="topbar-scope"
      >
        {scope}
      </Link>
      {orgSection && <OrgCrumbs section={orgSection} />}
      {project && name && (
        <>
          <ChevronRight className="size-3.5 shrink-0" />
          <ProjectLogo url={current?.logo_url} className="size-5 rounded" fallback={null} testId="header-logo" />
          <span className="truncate font-medium text-foreground">{name}</span>
        </>
      )}
    </nav>
  );
}

/** Tells other tabs who is signed in here, so a tab still showing someone else's data drops it. */
function useAnnounceAccount(): void {
  const { data: me } = useMe();
  const user = me?.id;
  useEffect(() => {
    if (user) broadcast({ kind: "signed-in", user });
  }, [user]);
}

function SkipLink() {
  return (
    <a
      href={`#${MAIN_CONTENT_ID}`}
      className="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium shadow focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:ring-2 focus:ring-ring"
      data-testid="skip-link"
    >
      Skip to content
    </a>
  );
}

export function AppLayout() {
  useAnnounceAccount();
  const { pathname } = useLocation();
  return (
    <SidebarProvider>
      <SkipLink />
      <AppSidebar />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" data-testid="sidebar-trigger" />
          <div className="mr-1 h-5 w-px shrink-0 bg-border" aria-hidden />
          <TopbarTitle />
          <ThemeToggle />
          <UserMenu />
        </header>
        <main
          id={MAIN_CONTENT_ID}
          tabIndex={-1}
          className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 outline-none md:px-8 md:py-8"
        >
          <ErrorBoundary variant="section" resetKey={pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
