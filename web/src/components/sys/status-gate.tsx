import { useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { onSealResponse } from "@/api/client";
import { ErrorState } from "@/components/states";
import { Spinner } from "@/components/ui/spinner";
import { keys, useSysStatus } from "@/hooks/queries";
import { gateRedirect } from "@/lib/sys-gate";
import { StandalonePage } from "./standalone-page";

/**
 * Checks whether the server is set up and unlocked before anything else loads, and sends the
 * browser to the setup or unlock page when it is not, including when it is sealed mid-session.
 */
export function StatusGate({ children }: { children: ReactNode }) {
  const status = useSysStatus();
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(
    () => onSealResponse(() => void queryClient.invalidateQueries({ queryKey: keys.sysStatus })),
    [queryClient],
  );

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
  if (!status.data || target) {
    return (
      <div className="flex min-h-svh items-center justify-center" data-testid="status-gate-loading">
        <Spinner className="size-6 text-muted-foreground" />
      </div>
    );
  }
  return children;
}
