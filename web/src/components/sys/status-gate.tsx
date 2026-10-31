import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { onSealResponse, redirectToLogin } from "@/api/client";
import { ErrorState } from "@/components/states";
import { Spinner } from "@/components/ui/spinner";
import { forgetAllButStatus, keys, useSysStatus } from "@/hooks/queries";
import { gateRedirect } from "@/lib/sys-gate";
import { listen } from "@/lib/tab-sync";
import { StandalonePage } from "./standalone-page";

/**
 * Checks whether the server is set up and unlocked before anything else loads, and sends the
 * browser to the setup or unlock page when it is not, including when it is sealed mid-session.
 * Whenever the server turns out to be locked, every cached query but the status is dropped and the
 * pages unmount, so no secret or revealed value stays on screen or in memory.
 */
export function StatusGate({ children }: { children: ReactNode }) {
  const status = useSysStatus();
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const [rechecking, setRechecking] = useState(false);

  useEffect(
    () =>
      onSealResponse(() => {
        setRechecking(true);
        forgetAllButStatus(queryClient);
        void queryClient.invalidateQueries({ queryKey: keys.sysStatus }).finally(() => setRechecking(false));
      }),
    [queryClient],
  );

  useEffect(
    () =>
      listen((message) => {
        forgetAllButStatus(queryClient);
        if (message === "signed-out") {
          redirectToLogin();
          return;
        }
        void queryClient.invalidateQueries({ queryKey: keys.sysStatus });
      }),
    [queryClient],
  );

  const locked = status.data !== undefined && status.data.state !== "unsealed";
  useEffect(() => {
    if (locked) forgetAllButStatus(queryClient);
  }, [locked, queryClient]);

  const target = status.data ? gateRedirect(status.data.state, location) : null;

  useEffect(() => {
    if (target) void navigate(target, { replace: true });
  }, [target, navigate]);

  if (status.error && !status.data) {
    return (
      <StandalonePage>
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      </StandalonePage>
    );
  }
  if (!status.data || target || rechecking) {
    return (
      <div className="flex min-h-svh items-center justify-center" data-testid="status-gate-loading">
        <Spinner className="size-6 text-muted-foreground" />
      </div>
    );
  }
  return children;
}
