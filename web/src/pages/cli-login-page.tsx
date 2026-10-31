import { CheckCircle2, LogIn, ShieldAlert, Terminal, XCircle } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { ApiError, reauthUrl, startReauth } from "@/api/client";
import { api } from "@/api/endpoints";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { useApiMutation, useMe } from "@/hooks/queries";

type Outcome = "pending" | "approved" | "cancelled";

export function CliLoginPage() {
  const [params] = useSearchParams();
  const code = (params.get("code") ?? "").trim().toUpperCase();
  const { data: me } = useMe();
  const [outcome, setOutcome] = useState<Outcome>("pending");

  const [reauthenticating, setReauthenticating] = useState(false);

  const approve = useApiMutation({
    mutationFn: () => api.approveCli(code),
    onSuccess: () => setOutcome("approved"),
    onError: (error) => {
      if (!(error instanceof ApiError) || error.code !== "reauthentication_required") return false;
      // The server wants a fresh sign-in first; it brings the browser back here afterwards.
      setReauthenticating(true);
      startReauth(reauthUrl(error, `/cli-login?code=${encodeURIComponent(code)}`));
      return true;
    },
  });

  return (
    <StandalonePage>
      <Card data-testid="cli-login">
        <StandaloneHeader
          title="Approve command line sign-in"
          pageTitle="Approve CLI sign-in"
          icon={<Terminal />}
          description={me ? `The CLI will act as ${me.email || me.name}.` : "The CLI will act as you."}
        />
        <CardContent className="space-y-4">
          {code ? (
            <div className="rounded-xl border bg-muted/50 p-4 text-center">
              <div className="text-xs text-muted-foreground">Code</div>
              <div className="font-mono text-3xl font-semibold tracking-[0.2em]" data-testid="cli-code">
                {code}
              </div>
            </div>
          ) : (
            <Alert variant="destructive">
              <XCircle />
              <AlertTitle>No code supplied</AlertTitle>
              <AlertDescription>Open the link printed by the CLI, which includes the code.</AlertDescription>
            </Alert>
          )}
          {outcome === "pending" && code && (
            <Alert className="border-warning/50 bg-warning/10" data-testid="cli-warning">
              <ShieldAlert className="text-warning" />
              <AlertTitle>Check before approving</AlertTitle>
              <AlertDescription>
                Only approve this if you just ran <code className="font-mono">sekret login</code> yourself and the code
                matches your terminal.
              </AlertDescription>
            </Alert>
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
        {outcome === "pending" && code && (
          <CardFooter className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setOutcome("cancelled")} data-testid="cli-cancel">
              Cancel
            </Button>
            <Button onClick={() => approve.mutate()} disabled={approve.isPending || reauthenticating} data-testid="cli-approve">
              {(approve.isPending || reauthenticating) && <Spinner />}
              Approve
            </Button>
          </CardFooter>
        )}
      </Card>
    </StandalonePage>
  );
}
