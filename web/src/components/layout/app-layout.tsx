import { ChevronRight } from "lucide-react";
import { useEffect } from "react";
import { Link, Outlet, useLocation, useParams } from "react-router";
import { ProjectLogo } from "@/components/project-logo";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { useMe, useProjects } from "@/hooks/queries";
import { broadcast } from "@/lib/tab-sync";
import { AppSidebar } from "./app-sidebar";
import { ThemeToggle, UserMenu } from "./user-menu";

const MAIN_CONTENT_ID = "main-content";

function TopbarTitle() {
  const { project } = useParams();
  const { pathname } = useLocation();
  const { data: projects } = useProjects();
  const current = projects?.find((p) => p.slug === project || p.id === project);
  const name = current?.name ?? project;
  const scope = pathname.startsWith("/org") ? "Organisation" : "Projects";

  return (
    <nav className="flex min-w-0 flex-1 items-center gap-1 text-sm text-muted-foreground" aria-label="Location">
      <Link to={scope === "Projects" ? "/projects" : "/org/identities"} className="shrink-0 hover:text-foreground">
        {scope}
      </Link>
      {project && (
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
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
