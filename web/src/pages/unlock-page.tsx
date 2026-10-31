import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, LockKeyhole, LockOpen } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import { StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { keys, useSysStatus } from "@/hooks/queries";
import { errorMessage } from "@/lib/errors";
import { unlockPolicyLine } from "@/lib/sys-gate";

export function UnlockPage() {
  const { data: status } = useSysStatus();
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [passphrase, setPassphrase] = useState("");

  const unseal = useMutation({
    mutationFn: () => api.unseal(passphrase),
    onSuccess: async (next) => {
      // Anything that failed while sealed is fetched again; the status gate then returns to where the user was going.
      await queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] !== keys.sysStatus[0] });
      queryClient.setQueryData(keys.sysStatus, next);
    },
    onError: () => input.current?.select(),
  });

  const error = unseal.error;
  const wrong = error instanceof ApiError && error.code === "invalid_passphrase";
  const limited = error instanceof ApiError && error.status === 429;
  const policyLine = status ? unlockPolicyLine(status) : null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (passphrase && !unseal.isPending) unseal.mutate();
  };

  return (
    <StandalonePage>
      <Card className="shadow-lg shadow-primary/5" data-testid="unlock-card">
        <CardHeader>
          <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <LockKeyhole className="size-5" />
          </div>
          <CardTitle className="text-xl">Unlock sekret</CardTitle>
          <CardDescription>sekret restarted and needs its passphrase to decrypt secrets.</CardDescription>
        </CardHeader>
        <form onSubmit={submit} noValidate>
          <CardContent className="space-y-4">
            <Field data-invalid={wrong}>
              <FieldLabel htmlFor="unlock-passphrase">Passphrase</FieldLabel>
              <Input
                ref={input}
                id="unlock-passphrase"
                type="password"
                autoComplete="current-password"
                autoFocus
                value={passphrase}
                aria-invalid={wrong}
                onChange={(e) => setPassphrase(e.target.value)}
                data-testid="unlock-passphrase"
              />
              {wrong && <FieldError data-testid="unlock-wrong">That passphrase is wrong.</FieldError>}
            </Field>
            {limited && (
              <Alert variant="destructive" data-testid="unlock-limited">
                <AlertCircle />
                <AlertTitle>Too many attempts</AlertTitle>
                <AlertDescription>Wait a minute, then try again.</AlertDescription>
              </Alert>
            )}
            {error && !wrong && !limited && (
              <Alert variant="destructive" data-testid="unlock-error">
                <AlertCircle />
                <AlertTitle>Unlocking failed</AlertTitle>
                <AlertDescription>{errorMessage(error)}</AlertDescription>
              </Alert>
            )}
            {policyLine && (
              <p className="text-sm text-muted-foreground" data-testid="unlock-policy">
                {policyLine}
              </p>
            )}
          </CardContent>
          <CardFooter className="mt-6">
            <Button type="submit" size="lg" className="w-full" disabled={!passphrase || unseal.isPending} data-testid="unlock-submit">
              {unseal.isPending ? <Spinner /> : <LockOpen />}
              Unlock
            </Button>
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}
