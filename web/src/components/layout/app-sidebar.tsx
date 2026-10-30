import {
  Bot,
  Camera,
  ChevronsUpDown,
  FolderKey,
  KeyRound,
  LayoutGrid,
  Layers,
  ScrollText,
  Settings,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";
import { Link, useLocation, useParams } from "react-router";
import { Logo } from "@/components/logo";
import { ProjectLogo } from "@/components/project-logo";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from "@/components/ui/sidebar";
import { useProjects } from "@/hooks/queries";
import { useOrgPermissions } from "@/hooks/use-permissions";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  testId: string;
  /** Extra path prefixes that should also mark the item active. */
  match?: string;
  /** Only active on its own path, not on pages beneath it. */
  exact?: boolean;
}

function isActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.to) return true;
  if (item.exact) return false;
  return pathname.startsWith(`${item.match ?? item.to}/`);
}

function NavGroup({ label, items }: { label: string; items: NavItem[] }) {
  const { pathname } = useLocation();
  const { setOpenMobile } = useSidebar();
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => {
          const active = isActive(item, pathname);
          return (
            <SidebarMenuItem key={item.to}>
              <SidebarMenuButton asChild isActive={active} tooltip={item.label}>
                <Link to={item.to} onClick={() => setOpenMobile(false)} data-testid={item.testId}>
                  <item.icon />
                  <span>{item.label}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          );
        })}
      </SidebarMenu>
    </SidebarGroup>
  );
}

function ProjectSwitcher({ current }: { current?: string }) {
  const { data: projects } = useProjects();
  const { setOpenMobile } = useSidebar();
  const project = projects?.find((p) => p.slug === current || p.id === current);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton size="lg" data-testid="project-switcher" className="data-[state=open]:bg-sidebar-accent">
          <div className="flex aspect-square size-8 items-center justify-center text-primary">
            <ProjectLogo
              url={project?.logo_url}
              className="size-8 rounded-md"
              testId="switcher-logo"
              // The menu button sizes every nested svg to size-4, so this needs to win over it.
              fallback={<Logo className="size-7!" />}
            />
          </div>
          <div className="grid flex-1 text-left text-sm leading-tight">
            <span className="truncate font-semibold">sekret</span>
            <span className="truncate text-xs text-muted-foreground">{project?.name ?? "All projects"}</span>
          </div>
          <ChevronsUpDown className="ml-auto" />
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-(--radix-dropdown-menu-trigger-width) min-w-56">
        <DropdownMenuLabel className="text-xs text-muted-foreground">Projects</DropdownMenuLabel>
        {(projects ?? []).map((p) => (
          <DropdownMenuItem key={p.id} asChild>
            <Link to={`/projects/${p.slug}/secrets`} onClick={() => setOpenMobile(false)} data-testid={`switcher-project-${p.slug}`}>
              <ProjectLogo url={p.logo_url} className="size-4 rounded-sm" fallback={<FolderKey />} />
              <span className="truncate">{p.name}</span>
            </Link>
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/projects" onClick={() => setOpenMobile(false)}>
            <LayoutGrid />
            All projects
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppSidebar() {
  const { project } = useParams();
  const org = useOrgPermissions();

  const projectItems: NavItem[] = project
    ? [
        { to: `/projects/${project}/secrets`, label: "Secrets", icon: KeyRound, testId: "nav-secrets" },
        { to: `/projects/${project}/overview`, label: "Overview", icon: Layers, testId: "nav-overview" },
        { to: `/projects/${project}/snapshots`, label: "Snapshots", icon: Camera, testId: "nav-snapshots" },
        { to: `/projects/${project}/audit`, label: "Audit log", icon: ScrollText, testId: "nav-project-audit" },
        { to: `/projects/${project}/settings`, label: "Settings", icon: Settings, testId: "nav-settings" },
      ]
    : [];

  const orgItems: NavItem[] = [
    { to: "/projects", label: "Projects", icon: LayoutGrid, testId: "nav-projects", exact: true },
    ...(org.can("identities", "read")
      ? [{ to: "/org/identities", label: "Machine identities", icon: Bot, testId: "nav-identities" }]
      : []),
    ...(org.can("org-members", "read")
      ? [
          { to: "/org/users", label: "Users", icon: Users, testId: "nav-users" },
          { to: "/org/access", label: "Access control", icon: ShieldCheck, testId: "nav-access" },
        ]
      : []),
    ...(org.can("org-audit-log", "read")
      ? [{ to: "/org/audit", label: "Audit log", icon: ScrollText, testId: "nav-org-audit" }]
      : []),
  ];

  return (
    <Sidebar collapsible="icon" data-testid="sidebar">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <ProjectSwitcher current={project} />
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {projectItems.length > 0 && <NavGroup label="Project" items={projectItems} />}
        <NavGroup label="Organisation" items={orgItems} />
      </SidebarContent>
      <SidebarRail />
    </Sidebar>
  );
}
