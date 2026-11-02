import { AlertCircle, ClipboardX, ExternalLink, LogIn } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { startSignIn } from "@/api/client";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { useAuthConfig } from "@/hooks/queries";
import { dismissNotClearedNotice, hasNotClearedNotice } from "@/lib/clipboard";
import { DOCS_URL } from "@/lib/links";
import { loginErrorText } from "@/lib/login-errors";

export function LoginPage() {
  const [params] = useSearchParams();
  const error = loginErrorText(params.get("error"));
  const returnTo = params.get("return_to") ?? "/";
  const { data: config, isPending } = useAuthConfig();
  const [leaving, setLeaving] = useState(false);
  const [clipboardNotice] = useState(() => hasNotClearedNotice());

  useEffect(() => {
    if (clipboardNotice) dismissNotClearedNotice();
  }, [clipboardNotice]);

  const signIn = () => {
    setLeaving(true);
    startSignIn(returnTo);
  };

  return (
    <StandalonePage className="max-w-sm">
      <Card className="shadow-lg shadow-primary/5" data-testid="login-card">
        <StandaloneHeader
          title="Sign in to sekret"
          pageTitle="Sign in"
          description="Sign in with your organisation account to manage secrets."
        />
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive" data-testid="login-error">
              <AlertCircle />
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {clipboardNotice && (
            <Alert data-testid="clipboard-not-cleared">
              <ClipboardX />
              <AlertTitle>Clear your clipboard</AlertTitle>
              <AlertDescription>
                A secret you copied may still be on the clipboard, because the browser would not let sekret clear it.
              </AlertDescription>
            </Alert>
          )}
          {isPending ? (
            <Skeleton className="h-9 w-full" />
          ) : config?.oidc_enabled === false ? (
            <Alert data-testid="oidc-disabled">
              <AlertCircle />
              <AlertTitle>No sign-in provider yet</AlertTitle>
              <AlertDescription>
                <p>
                  This server has no sign-in provider yet. Use the admin token with the CLI, or see the{" "}
                  <a
                    href={`${DOCS_URL}configuration/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
                    data-testid="oidc-docs-link"
                  >
                    configuration guide
                    <ExternalLink className="size-3" aria-hidden />
                    <span className="sr-only">(opens in a new tab)</span>
                  </a>
                  .
                </p>
              </AlertDescription>
            </Alert>
          ) : (
            <Button size="lg" className="w-full" onClick={signIn} disabled={leaving} data-testid="sign-in">
              {leaving ? <Spinner /> : <LogIn />}
              Sign in
            </Button>
          )}
        </CardContent>
      </Card>
    </StandalonePage>
  );
}
