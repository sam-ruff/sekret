import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Info, LogIn, ShieldAlert, Terminal, XCircle } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiError, reauthUrl, startReauth } from "@/api/client";
import { api } from "@/api/endpoints";
import type { PendingCliLogin } from "@/api/types";
import { FormBlocker } from "@/components/form-blocker";
import { SecretInput } from "@/components/secret-field";
import { ErrorState } from "@/components/states";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { useApiMutation, useMe } from "@/hooks/queries";
import { approveBlocker, codesMatch, isCompleteCode, normaliseUserCode } from "@/lib/cli-code";
import { formatDateTime, formatExpiry, formatRelative } from "@/lib/format";

type Outcome = "pending" | "approved" | "cancelled";

const CODE_ERROR_ID = "cli-code-error";
const APPROVE_BLOCKER_ID = "cli-approve-blocker";
/** Remembers, across the reauthentication round trip, which request it was for. */
const REAUTH_KEY = "sekret-cli-reauth";

function rememberReauth(code: string): void {
  try {
    window.sessionStorage.setItem(REAUTH_KEY, code);
  } catch {
    // Without storage the note after signing in again is simply not shown.
  }
}

/** Whether this page load is the return from signing in again for `code`. */
function returnedFromReauth(code: string): boolean {
  try {
    return window.sessionStorage.getItem(REAUTH_KEY) === code;
  } catch {
    return false;
  }
}

function forgetReauth(): void {
  try {
    window.sessionStorage.removeItem(REAUTH_KEY);
  } catch {
    // Nothing was stored.
  }
}

function Detail({ label, children, note, testId }: { label: ReactNode; children: ReactNode; note?: string; testId: string }) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:gap-4">
      <dt className="text-sm text-muted-foreground sm:w-40 sm:shrink-0">{label}</dt>
      <dd className="min-w-0 text-sm break-words">
        <div data-testid={testId}>{children}</div>
        {note && (
          <p className="text-xs text-muted-foreground" data-testid={`${testId}-note`}>
            {note}
          </p>
        )}
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
      <Detail label="Program" note="Reported by the requester, so it can be faked." testId="cli-request-agent">
        <span className="font-mono">{request.user_agent || "Not given"}</span>
      </Detail>
      <Detail label="Started" testId="cli-request-age">
        <span title={formatDateTime(request.created_at)}>{formatRelative(request.created_at)}</span>
      </Detail>
      <Detail label="Expires" testId="cli-request-expires">
        {formatExpiry(request.expires_at)}
      </Detail>
    </dl>
  );
}

/** Shown when the request came from somewhere other than this browser's address. */
function OtherAddress({ confirmed, onConfirm }: { confirmed: boolean; onConfirm: (on: boolean) => void }) {
  return (
    <Alert variant="destructive" data-testid="cli-other-address">
      <AlertTriangle />
      <AlertTitle>This sign-in came from a different network</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>
          The address above is not the one this browser uses. That is expected on a remote server or over a VPN, but it
          is also what it looks like when someone else sent you the link. Approve only if you ran{" "}
          <code className="font-mono">sekret login</code> yourself on that machine.
        </p>
        <label className="flex items-start gap-2 text-foreground">
          <Checkbox
            checked={confirmed}
            onCheckedChange={(on) => onConfirm(on === true)}
            className="mt-0.5"
            data-testid="cli-confirm-own"
          />
          <span>I started this sign-in myself on that machine</span>
        </label>
      </AlertDescription>
    </Alert>
  );
}

export function CliLoginPage() {
  const [params] = useSearchParams();
  // The link's code finds the request to describe, but approving takes the code typed from the terminal.
  const linkCode = normaliseUserCode(params.get("code") ?? "");
  const { data: me } = useMe();
  const [outcome, setOutcome] = useState<Outcome>("pending");
  const [typed, setTyped] = useState("");
  const [confirmedOwn, setConfirmedOwn] = useState(false);
  const [reauthenticating, setReauthenticating] = useState(false);
  const [signedInAgain] = useState(() => linkCode !== "" && returnedFromReauth(linkCode));
  useEffect(() => forgetReauth(), []);

  const lookupCode = linkCode || (isCompleteCode(typed) ? normaliseUserCode(typed) : "");
  const request = useQuery({
    queryKey: ["cli-login", lookupCode],
    queryFn: () => api.pendingCli(lookupCode),
    enabled: lookupCode !== "" && outcome === "pending",
    staleTime: Infinity,
  });

  const complete = isCompleteCode(typed);
  const mismatch = complete && linkCode !== "" && !codesMatch(typed, linkCode);
  const otherAddress = request.data?.same_address === false;
  const blocker = approveBlocker({ typed, mismatch, loaded: request.isSuccess, otherAddress, confirmedOwn });
  const ready = blocker === undefined;

  const approve = useApiMutation({
    mutationFn: (code: string) => api.approveCli(code),
    onSuccess: () => setOutcome("approved"),
    onError: (error) => {
      if (!(error instanceof ApiError) || error.code !== "reauthentication_required") return false;
      // The server wants a fresh sign-in first; it brings the browser back here afterwards.
      setReauthenticating(true);
      rememberReauth(lookupCode);
      startReauth(reauthUrl(error, `/cli-login?code=${encodeURIComponent(lookupCode)}`));
      return true;
    },
  });

  const deny = useApiMutation({
    mutationFn: (code: string) => api.denyCli(code),
    onSuccess: () => setOutcome("cancelled"),
    onError: (error) => {
      // Already gone, so there is nothing left to refuse.
      if (!(error instanceof ApiError) || error.status !== 404) return false;
      setOutcome("cancelled");
      return true;
    },
  });

  const cancel = () => {
    if (lookupCode === "") {
      setOutcome("cancelled");
      return;
    }
    deny.mutate(lookupCode);
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready && !approve.isPending && !reauthenticating) approve.mutate(normaliseUserCode(typed));
  };

  const ended = request.error instanceof ApiError && request.error.status === 404;
  const asking = outcome === "pending" && !ended;
  const busy = approve.isPending || deny.isPending || reauthenticating;
  const who = me ? me.email || me.name : "you";
  const header = asking
    ? { title: "Approve command line sign-in", page: "Approve CLI sign-in", description: `The CLI will act as ${who}.` }
    : outcome === "approved"
      ? { title: "Command line sign-in approved", page: "CLI sign-in approved", description: `The CLI now acts as ${who}.` }
      : outcome === "cancelled"
        ? { title: "Command line sign-in denied", page: "CLI sign-in denied", description: "The CLI was not given access." }
        : { title: "Sign-in request ended", page: "CLI sign-in ended", description: "Nothing can be approved from this link." };
  const showBlocker = asking && blocker !== undefined && !request.error && !busy;

  return (
    <StandalonePage className="max-w-lg">
      <Card data-testid="cli-login">
        <StandaloneHeader title={header.title} pageTitle={header.page} icon={<Terminal />} description={header.description} />
        <form onSubmit={submit} noValidate>
          <CardContent className="space-y-4">
            {outcome === "pending" && ended && (
              <Alert data-testid="cli-unknown">
                <XCircle />
                <AlertTitle>This sign-in request has ended</AlertTitle>
                <AlertDescription>
                  It expired, was already used or refused, or the link is wrong. Run{" "}
                  <code className="font-mono">sekret login</code> again to get a new link.
                </AlertDescription>
              </Alert>
            )}
            {asking && signedInAgain && !reauthenticating && (
              <Alert data-testid="cli-signed-in-again">
                <Info />
                <AlertDescription>
                  You are signed in again. Type the code from your terminal once more to approve.
                </AlertDescription>
              </Alert>
            )}
            {asking && (
              <Alert className="border-warning/50 bg-warning/10" data-testid="cli-warning">
                <ShieldAlert className="text-warning" />
                <AlertTitle>Only approve a sign-in you started</AlertTitle>
                <AlertDescription data-testid="cli-warning-text">
                  {lookupCode === "" ? (
                    <>
                      Someone who sends you this link gets access as you if you approve it. Type the code your{" "}
                      <code className="font-mono">sekret login</code> printed, then check the address and program that
                      appear are yours.
                    </>
                  ) : (
                    <>
                      Someone who sends you this link gets access as you if you approve it. Check the address and program
                      below are yours, then type the code your <code className="font-mono">sekret login</code> printed.
                    </>
                  )}
                </AlertDescription>
              </Alert>
            )}
            {asking && request.isPending && lookupCode !== "" && <Skeleton className="h-36 w-full" />}
            {asking && request.data && <RequestDetails request={request.data} />}
            {asking && request.error && <ErrorState error={request.error} onRetry={() => void request.refetch()} />}
            {asking && (
              <Field data-invalid={mismatch}>
                <FieldLabel htmlFor="cli-code">Code from your terminal</FieldLabel>
                <SecretInput
                  id="cli-code"
                  value={typed}
                  autoFocus
                  inputMode="text"
                  maxLength={12}
                  placeholder="e.g. ABCD-1234"
                  className="font-mono text-lg tracking-[0.2em] uppercase placeholder:font-sans placeholder:text-sm placeholder:tracking-normal placeholder:normal-case placeholder:text-muted-foreground/70"
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
            {/* Next to the buttons, so the box that holds up Approve is hard to miss. */}
            {asking && otherAddress && <OtherAddress confirmed={confirmedOwn} onConfirm={setConfirmedOwn} />}
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
                <AlertTitle>Denied</AlertTitle>
                <AlertDescription>
                  {deny.isSuccess
                    ? "Nothing was approved, and the terminal that asked is told the sign-in was refused."
                    : "Nothing was approved."}
                </AlertDescription>
              </Alert>
            )}
            {!asking && !reauthenticating && (
              <Button asChild variant="outline" className="w-full" data-testid="cli-go-home">
                <Link to="/">Go to sekret</Link>
              </Button>
            )}
          </CardContent>
          {asking && (
            <CardFooter className="mt-6 flex flex-col items-stretch gap-2">
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={cancel} disabled={busy} data-testid="cli-cancel">
                  {deny.isPending && <Spinner />}
                  Deny
                </Button>
                <Button
                  type="submit"
                  disabled={!ready || busy}
                  aria-describedby={showBlocker ? APPROVE_BLOCKER_ID : undefined}
                  data-testid="cli-approve"
                >
                  {(approve.isPending || reauthenticating) && <Spinner />}
                  Approve
                </Button>
              </div>
              {showBlocker && (
                <FormBlocker id={APPROVE_BLOCKER_ID} testId="cli-approve-blocker" className="text-right">
                  {blocker}
                </FormBlocker>
              )}
            </CardFooter>
          )}
        </form>
      </Card>
    </StandalonePage>
  );
}
