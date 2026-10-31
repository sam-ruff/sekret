import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import { flushSync } from "react-dom";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { ApiError, isSealError } from "@/api/client";
import { ErrorBoundary } from "@/components/error-boundary";
import { AppLayout } from "@/components/layout/app-layout";
import { forgetAllButStatus } from "@/hooks/queries";
import { StatusGate } from "@/components/sys/status-gate";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { beginLeaving } from "@/lib/leaving";
import { forgetWhenHidden } from "@/lib/page-lifecycle";
import { ThemeProvider } from "@/lib/theme";
import { CliLoginPage } from "@/pages/cli-login-page";
import { LoginPage } from "@/pages/login-page";
import { NotFoundPage } from "@/pages/not-found-page";
import { AccessPage } from "@/pages/org/access-page";
import { IdentitiesPage } from "@/pages/org/identities-page";
import { IdentityPage } from "@/pages/org/identity-page";
import { OrgAuditPage } from "@/pages/org/org-audit-page";
import { ServerPage } from "@/pages/org/server-page";
import { UsersPage } from "@/pages/org/users-page";
import { OverviewPage } from "@/pages/project/overview-page";
import { ProjectAuditPage } from "@/pages/project/project-audit-page";
import { SecretsPage } from "@/pages/project/secrets-page";
import { SettingsPage } from "@/pages/project/settings-page";
import { SnapshotsPage } from "@/pages/project/snapshots-page";
import { ProjectsPage } from "@/pages/projects-page";
import { SetupPage } from "@/pages/setup-page";
import { UnlockPage } from "@/pages/unlock-page";

function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (count, error) => {
          if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
          if (isSealError(error)) return false;
          return count < 2;
        },
        refetchOnWindowFocus: false,
      },
      // A finished mutation can hold a passphrase, a value or a client secret; drop it once unused.
      mutations: { gcTime: 0 },
    },
  });
}

const queryClient = createQueryClient();

function AppRoutes() {
  return (
    <Routes>
      <Route path="/setup" element={<SetupPage />} />
      <Route path="/unlock" element={<UnlockPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/cli-login" element={<CliLoginPage />} />
      <Route element={<AppLayout />}>
        <Route index element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/projects/:project" element={<Navigate to="secrets" replace />} />
        <Route path="/projects/:project/secrets/:env?" element={<SecretsPage />} />
        <Route path="/projects/:project/overview" element={<OverviewPage />} />
        <Route path="/projects/:project/snapshots/:env?" element={<SnapshotsPage />} />
        <Route path="/projects/:project/audit" element={<ProjectAuditPage />} />
        <Route path="/projects/:project/settings/:tab?" element={<SettingsPage />} />
        <Route path="/org" element={<Navigate to="/org/identities" replace />} />
        <Route path="/org/identities" element={<IdentitiesPage />} />
        <Route path="/org/identities/:id/:tab?" element={<IdentityPage />} />
        <Route path="/org/users" element={<UsersPage />} />
        <Route path="/org/access/:tab?" element={<AccessPage />} />
        <Route path="/org/audit" element={<OrgAuditPage />} />
        <Route path="/org/server" element={<ServerPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

/** Empties the screen and the cache in the same task, before the browser stores the page away. */
function forgetEverything(): void {
  flushSync(() => beginLeaving());
  forgetAllButStatus(queryClient);
}

export function App() {
  useEffect(() => forgetWhenHidden(forgetEverything), []);
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={300}>
          <ErrorBoundary onError={() => forgetAllButStatus(queryClient)}>
            <BrowserRouter>
              <StatusGate>
                <AppRoutes />
              </StatusGate>
            </BrowserRouter>
          </ErrorBoundary>
          <Toaster richColors closeButton position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
