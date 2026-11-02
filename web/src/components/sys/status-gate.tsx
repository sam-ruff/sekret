import { useQueryClient } from "@tanstack/react-query";
import { Fragment, useCallback, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { onSealResponse, redirectToLogin } from "@/api/client";
import type { Me } from "@/api/types";
import { ErrorState } from "@/components/states";
import { Spinner } from "@/components/ui/spinner";
import { forgetAllButStatus, keys, useSysStatus } from "@/hooks/queries";
import { clearCopiedSecret } from "@/lib/clipboard";
import { browserNavigation, isLeaving, subscribeLeaving } from "@/lib/leaving";
import { gateRedirect, UNLOCK_PATH, type UnlockState } from "@/lib/sys-gate";
import { listen } from "@/lib/tab-sync";
import { StandalonePage } from "./standalone-page";

function GateSpinner() {
  return (
    <div className="flex min-h-svh items-center justify-center" data-testid="status-gate-loading">
      <Spinner className="size-6 text-muted-foreground" />
    </div>
  );
}

/**
 * Checks whether the server is set up and unlocked before anything else loads, and sends the
 * browser to the setup or unlock page when it is not, including when it is sealed mid-session.
 * Whenever the server turns out to be locked, every cached query but the status is dropped and the
 * pages unmount, so no secret or revealed value stays on screen or in memory. The same happens
 * while the page is leaving, so a sign-out or a page the browser stores away shows nothing.
 */
export function StatusGate({ children }: { children: ReactNode }) {
  const status = useSysStatus();
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const [rechecking, setRechecking] = useState(false);
  // Bumped to remount the pages, since rendered values outlive the cache they came from.
  const [generation, setGeneration] = useState(0);
  const leaving = useSyncExternalStore(subscribeLeaving, isLeaving);

  // Whether someone was signed in when the server was found locked, for the unlock page to say so.
  const hadSession = useRef(false);
  const forget = useCallback(() => {
    if (queryClient.getQueryData(keys.me) !== undefined) hadSession.current = true;
    forgetAllButStatus(queryClient);
  }, [queryClient]);

  const recheck = useCallback(() => {
    setRechecking(true);
    setGeneration((value) => value + 1);
    forget();
    void queryClient.invalidateQueries({ queryKey: keys.sysStatus }).finally(() => setRechecking(false));
  }, [queryClient, forget]);

  useEffect(() => onSealResponse(recheck), [recheck]);

  useEffect(
    () =>
      listen((message) => {
        if (isLeaving()) return;
        if (typeof message === "object") {
          // Another tab signed in; if as someone else, everything here belongs to the previous person.
          const shown = queryClient.getQueryData<Me>(keys.me);
          if (!shown || shown.id === message.user) return;
          forgetAllButStatus(queryClient);
          void clearCopiedSecret();
          browserNavigation.reload();
          return;
        }
        if (message === "signed-out") {
          forgetAllButStatus(queryClient);
          void redirectToLogin();
          return;
        }
        recheck();
      }),
    [queryClient, recheck],
  );

  const locked = status.data !== undefined && status.data.state !== "unsealed";
  useEffect(() => {
    if (locked) forget();
  }, [locked, forget]);

  const target = status.data ? gateRedirect(status.data.state, location) : null;

  useEffect(() => {
    if (!target || isLeaving()) return;
    const state: UnlockState | undefined = target.startsWith(UNLOCK_PATH) && hadSession.current ? { interrupted: true } : undefined;
    hadSession.current = false;
    void navigate(target, { replace: true, state });
  }, [target, navigate]);

  if (leaving) return <GateSpinner />;
  if (status.error && !status.data) {
    return (
      <StandalonePage>
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      </StandalonePage>
    );
  }
  if (!status.data || target || rechecking) return <GateSpinner />;
  return <Fragment key={generation}>{children}</Fragment>;
}
