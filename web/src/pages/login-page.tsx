import { AlertCircle, LogIn } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { startSignIn } from "@/api/client";
import { ThemeToggle } from "@/components/layout/user-menu";
import { Logo } from "@/components/logo";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { useAuthConfig } from "@/hooks/queries";

export function LoginPage() {
  const [params] = useSearchParams();
  const error = params.get("error");
  const returnTo = params.get("return_to") ?? "/";
  const { data: config, isPending } = useAuthConfig();
  const [leaving, setLeaving] = useState(false);

  const signIn = () => {
    setLeaving(true);
    startSignIn(returnTo);
  };

  return (
    <div className="relative flex min-h-svh items-center justify-center bg-gradient-to-b from-primary/10 via-background to-background px-4">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <Card className="w-full max-w-sm shadow-lg shadow-primary/5" data-testid="login-card">
        <CardHeader className="items-center text-center">
          <Logo className="mx-auto mb-2 size-14 text-primary" title="sekret" />
          <CardTitle className="text-xl">Sign in to sekret</CardTitle>
          <CardDescription>Secrets for your projects, kept in one place.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive" data-testid="login-error">
              <AlertCircle />
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {isPending ? (
            <Skeleton className="h-9 w-full" />
          ) : config?.oidc_enabled === false ? (
            <Alert data-testid="oidc-disabled">
              <AlertCircle />
              <AlertTitle>Browser sign-in is not set up</AlertTitle>
              <AlertDescription>
                This server has no OpenID Connect provider configured. Ask your administrator to enable it.
              </AlertDescription>
            </Alert>
          ) : (
            <Button size="lg" className="w-full" onClick={signIn} disabled={leaving} data-testid="sign-in">
              {leaving ? <Spinner /> : <LogIn />}
              Sign in with Keycloak
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
