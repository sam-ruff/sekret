import { CheckCircle2, ShieldAlert, Terminal, XCircle } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { api } from "@/api/endpoints";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { useApiMutation, useMe } from "@/hooks/queries";

type Outcome = "pending" | "approved" | "cancelled";

export function CliLoginPage() {
  const [params] = useSearchParams();
  const code = (params.get("code") ?? "").trim().toUpperCase();
  const { data: me } = useMe();
  const [outcome, setOutcome] = useState<Outcome>("pending");

  const approve = useApiMutation({
    mutationFn: () => api.approveCli(code),
    onSuccess: () => setOutcome("approved"),
  });

  return (
    <div className="flex min-h-svh items-center justify-center bg-gradient-to-b from-primary/10 via-background to-background px-4">
      <Card className="w-full max-w-md" data-testid="cli-login">
        <CardHeader>
          <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <Terminal className="size-5" />
          </div>
          <CardTitle className="text-xl">Approve command line sign-in</CardTitle>
          <CardDescription>
            {me ? `The CLI will act as ${me.email || me.name}.` : "The CLI will act as you."}
          </CardDescription>
        </CardHeader>
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
            <Button onClick={() => approve.mutate()} disabled={approve.isPending} data-testid="cli-approve">
              {approve.isPending && <Spinner />}
              Approve
            </Button>
          </CardFooter>
        )}
      </Card>
    </div>
  );
}
