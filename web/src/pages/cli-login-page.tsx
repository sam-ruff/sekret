import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, LogIn, ShieldAlert, Terminal, XCircle } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { ApiError, reauthUrl, startReauth } from "@/api/client";
import { api } from "@/api/endpoints";
import type { PendingCliLogin } from "@/api/types";
import { SecretInput } from "@/components/secret-field";
import { ErrorState } from "@/components/states";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { useApiMutation, useMe } from "@/hooks/queries";
import { codesMatch, isCompleteCode, normaliseUserCode } from "@/lib/cli-code";
import { formatDateTime, formatRelative } from "@/lib/format";

type Outcome = "pending" | "approved" | "cancelled";

const CODE_ERROR_ID = "cli-code-error";

function Detail({ label, children, testId }: { label: string; children: ReactNode; testId: string }) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:gap-4">
      <dt className="text-sm text-muted-foreground sm:w-32 sm:shrink-0">{label}</dt>
      <dd className="min-w-0 text-sm break-words" data-testid={testId}>
        {children}
      </dd>
    </div>
  );
}

/** Where and when the login was started, so a request someone else sent can be spotted. */
function RequestDetails({ request }: { request: PendingCliLogin }) {
  return (
    <dl className="divide-y rounded-xl border px-4" data-testid="cli-request">
      <Detail label="Requested from" testId="cli-request-ip">
        <span className="font-mono">{request.requested_from_ip}</span>
      </Detail>
      <Detail label="Program" testId="cli-request-agent">
        <span className="font-mono">{request.user_agent || "Not given"}</span>
      </Detail>
      <Detail label="Started" testId="cli-request-age">
        <span title={formatDateTime(request.created_at)}>{formatRelative(request.created_at)}</span>
      </Detail>
      <Detail label="Expires" testId="cli-request-expires">
        {formatDateTime(request.expires_at)}
      </Detail>
    </dl>
  );
}

export function CliLoginPage() {
  const [params] = useSearchParams();
  // The link's code finds the request to describe, but approving takes the code typed from the terminal.
  const linkCode = normaliseUserCode(params.get("code") ?? "");
  const { data: me } = useMe();
  const [outcome, setOutcome] = useState<Outcome>("pending");
  const [typed, setTyped] = useState("");
  const [reauthenticating, setReauthenticating] = useState(false);

  const lookupCode = linkCode || (isCompleteCode(typed) ? normaliseUserCode(typed) : "");
  const request = useQuery({
    queryKey: ["cli-login", lookupCode],
    queryFn: () => api.pendingCli(lookupCode),
    enabled: lookupCode !== "" && outcome === "pending",
    staleTime: Infinity,
  });

  const complete = isCompleteCode(typed);
  const mismatch = complete && linkCode !== "" && !codesMatch(typed, linkCode);
  const ready = complete && !mismatch && request.isSuccess;

  const approve = useApiMutation({
    mutationFn: (code: string) => api.approveCli(code),
    onSuccess: () => setOutcome("approved"),
    onError: (error) => {
      if (!(error instanceof ApiError) || error.code !== "reauthentication_required") return false;
      // The server wants a fresh sign-in first; it brings the browser back here afterwards.
      setReauthenticating(true);
      startReauth(reauthUrl(error, `/cli-login?code=${encodeURIComponent(lookupCode)}`));
      return true;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready && !approve.isPending && !reauthenticating) approve.mutate(normaliseUserCode(typed));
  };

  const unknown = request.error instanceof ApiError && request.error.status === 404;

  return (
    <StandalonePage className="max-w-lg">
      <Card data-testid="cli-login">
        <StandaloneHeader
          title="Approve command line sign-in"
          pageTitle="Approve CLI sign-in"
          icon={<Terminal />}
          description={me ? `The CLI will act as ${me.email || me.name}.` : "The CLI will act as you."}
        />
        <form onSubmit={submit} noValidate>
          <CardContent className="space-y-4">
            {outcome === "pending" && (
              <Alert className="border-warning/50 bg-warning/10" data-testid="cli-warning">
                <ShieldAlert className="text-warning" />
                <AlertTitle>Only approve a sign-in you started</AlertTitle>
                <AlertDescription>
                  Someone who sends you this link gets access as you if you approve it. Check the address and program
                  below are yours, then type the code your <code className="font-mono">sekret login</code> printed.
                </AlertDescription>
              </Alert>
            )}
            {outcome === "pending" && request.isPending && lookupCode !== "" && <Skeleton className="h-36 w-full" />}
            {outcome === "pending" && request.data && <RequestDetails request={request.data} />}
            {outcome === "pending" && unknown && (
              <Alert variant="destructive" data-testid="cli-unknown">
                <XCircle />
                <AlertTitle>No sign-in waiting for this code</AlertTitle>
                <AlertDescription>
                  It may have expired or been approved already. Run <code className="font-mono">sekret login</code>{" "}
                  again for a new one.
                </AlertDescription>
              </Alert>
            )}
            {outcome === "pending" && request.error && !unknown && (
              <ErrorState error={request.error} onRetry={() => void request.refetch()} />
            )}
            {outcome === "pending" && (
              <Field data-invalid={mismatch}>
                <FieldLabel htmlFor="cli-code">Code from your terminal</FieldLabel>
                <SecretInput
                  id="cli-code"
                  value={typed}
                  autoFocus
                  inputMode="text"
                  maxLength={12}
                  placeholder="XXXX-XXXX"
                  className="font-mono text-lg tracking-[0.2em] uppercase"
                  aria-invalid={mismatch}
                  aria-describedby={mismatch ? CODE_ERROR_ID : "cli-code-hint"}
                  onChange={(e) => setTyped(e.target.value)}
                  data-testid="cli-code-input"
                />
                {mismatch ? (
                  <FieldError id={CODE_ERROR_ID} data-testid="cli-code-mismatch">
                    That is not the code for this request. Check your terminal, and do not approve a code someone gave
                    you.
                  </FieldError>
                ) : (
                  <FieldDescription id="cli-code-hint">Eight letters and digits, as the CLI shows them.</FieldDescription>
                )}
              </Field>
            )}
            {outcome === "approved" && (
              <Alert className="border-success/50 bg-success/10" data-testid="cli-approved">
                <CheckCircle2 className="text-success" />
                <AlertTitle>Approved</AlertTitle>
                <AlertDescription>Return to your terminal. You can close this tab.</AlertDescription>
              </Alert>
            )}
            {reauthenticating && (
              <Alert data-testid="cli-reauth">
                <LogIn />
                <AlertTitle>Sign in again</AlertTitle>
                <AlertDescription>
                  Approving needs a fresh sign-in. You come back here afterwards to approve.
                </AlertDescription>
              </Alert>
            )}
            {outcome === "cancelled" && (
              <Alert data-testid="cli-cancelled">
                <XCircle />
                <AlertTitle>Cancelled</AlertTitle>
                <AlertDescription>Nothing was approved. The CLI request will expire on its own.</AlertDescription>
              </Alert>
            )}
          </CardContent>
          {outcome === "pending" && (
            <CardFooter className="mt-6 flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setOutcome("cancelled")} data-testid="cli-cancel">
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={!ready || approve.isPending || reauthenticating}
                data-testid="cli-approve"
              >
                {(approve.isPending || reauthenticating) && <Spinner />}
                Approve
              </Button>
            </CardFooter>
          )}
        </form>
      </Card>
    </StandalonePage>
  );
}
