import { ChevronRight } from "lucide-react";
import { Link, Outlet, useLocation, useParams } from "react-router";
import { ProjectLogo } from "@/components/project-logo";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { useProjects } from "@/hooks/queries";
import { AppSidebar } from "./app-sidebar";
import { ThemeToggle, UserMenu } from "./user-menu";

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

export function AppLayout() {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" data-testid="sidebar-trigger" />
          <div className="mr-1 h-5 w-px shrink-0 bg-border" aria-hidden />
          <TopbarTitle />
          <ThemeToggle />
          <UserMenu />
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 md:px-8 md:py-8">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
