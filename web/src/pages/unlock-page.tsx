import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, LockKeyhole, LockOpen, Timer } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import { PassphraseAccountField } from "@/components/sys/passphrase-fields";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { PassphraseInput } from "@/components/secret-field";
import { Spinner } from "@/components/ui/spinner";
import { keys } from "@/hooks/queries";
import { useCountdown } from "@/hooks/use-countdown";
import { useIdle } from "@/hooks/use-idle";
import { backoffSeconds, errorMessage } from "@/lib/errors";
import { signOut } from "@/lib/session";

const INPUT_ERROR_ID = "unlock-passphrase-error";

export function UnlockPage() {
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const interrupted = params.has("return_to");
  const input = useRef<HTMLInputElement>(null);
  const [passphrase, setPassphrase] = useState("");
  const [empty, setEmpty] = useState(false);
  const [backoffUntil, setBackoffUntil] = useState(0);
  const waitSeconds = useCountdown(backoffUntil);
  useIdle(passphrase !== "", () => setPassphrase(""));

  const unseal = useMutation({
    mutationFn: () => api.unseal(passphrase),
    gcTime: 0,
    onSuccess: async (next) => {
      setPassphrase("");
      // Anything that failed while sealed is fetched again; the status gate then returns to where the user was going.
      await queryClient.invalidateQueries({ predicate: (query) => query.queryKey[0] !== keys.sysStatus[0] });
      queryClient.setQueryData(keys.sysStatus, next);
    },
    onError: (error) => {
      const seconds = backoffSeconds(error);
      if (seconds !== null) setBackoffUntil(Date.now() + seconds * 1000);
      input.current?.select();
    },
  });

  const { isSuccess: unlocked, reset: resetUnseal } = unseal;
  useEffect(() => {
    if (unlocked) resetUnseal();
  }, [unlocked, resetUnseal]);

  const error = unseal.error instanceof ApiError ? unseal.error : null;
  const wrong = error?.code === "invalid_passphrase";
  const backingOff = error?.code === "passphrase_backoff";
  const busy = error?.code === "kdf_busy";
  const limited = error?.status === 429 && !backingOff && !busy;
  const foreignKey = error?.code === "root_key_not_recognised";
  const otherError = unseal.error && !wrong && !foreignKey && error?.status !== 429 ? unseal.error : null;
  const waiting = backingOff && waitSeconds > 0;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!passphrase) {
      setEmpty(true);
      input.current?.focus();
      return;
    }
    if (!unseal.isPending && !waiting) unseal.mutate();
  };

  const inputError = wrong ? "That passphrase is wrong." : empty && !passphrase ? "Enter the passphrase to unlock." : null;

  return (
    <StandalonePage>
      <Card className="shadow-lg shadow-primary/5" data-testid="unlock-card">
        <StandaloneHeader
          title="Unlock sekret"
          pageTitle="Unlock"
          description={
            <span data-testid="unlock-description">
              {interrupted && "The server was locked while you were using it. "}
              The server is locked, so secrets cannot be read. Someone with the server passphrase needs to unlock it.
            </span>
          }
          icon={<LockKeyhole />}
        />
        <form onSubmit={submit} noValidate>
          <CardContent className="space-y-4">
            <PassphraseAccountField />
            <Field data-invalid={!!inputError}>
              <FieldLabel htmlFor="unlock-passphrase">Passphrase</FieldLabel>
              <PassphraseInput
                ref={input}
                id="unlock-passphrase"
                autoComplete="current-password"
                autoFocus
                value={passphrase}
                aria-invalid={!!inputError}
                aria-describedby={inputError ? INPUT_ERROR_ID : undefined}
                onChange={(e) => setPassphrase(e.target.value)}
                data-testid="unlock-passphrase"
              />
              {inputError && (
                <FieldError id={INPUT_ERROR_ID} data-testid={wrong ? "unlock-wrong" : "unlock-empty"}>
                  {inputError}
                </FieldError>
              )}
            </Field>
            {waiting && (
              <Alert variant="destructive" data-testid="unlock-backoff">
                <Timer />
                <AlertTitle>Too many wrong passphrases</AlertTitle>
                <AlertDescription id="unlock-wait">
                  Wait a few seconds, then try again.{" "}
                  {/* Read out once by the alert; a number changing every second would be read every second. */}
                  <span aria-hidden data-testid="unlock-countdown-text">
                    <span data-testid="unlock-countdown">{waitSeconds}</span> {waitSeconds === 1 ? "second" : "seconds"}{" "}
                    left.
                  </span>
                </AlertDescription>
              </Alert>
            )}
            {backingOff && !waiting && (
              <Alert role="status" aria-live="polite" data-testid="unlock-backoff-over">
                <Timer />
                <AlertDescription>You can try again now.</AlertDescription>
              </Alert>
            )}
            {busy && (
              <Alert data-testid="unlock-busy">
                <Timer />
                <AlertTitle>Please wait</AlertTitle>
                <AlertDescription>{errorMessage(error)}</AlertDescription>
              </Alert>
            )}
            {limited && (
              <Alert variant="destructive" data-testid="unlock-limited">
                <AlertCircle />
                <AlertTitle>Too many attempts</AlertTitle>
                <AlertDescription>Wait a minute, then try again.</AlertDescription>
              </Alert>
            )}
            {foreignKey && (
              <Alert variant="destructive" data-testid="unlock-key-not-recognised">
                <AlertCircle />
                <AlertTitle>The server does not recognise this key</AlertTitle>
                <AlertDescription>
                  <p>
                    This passphrase opened a key this server does not recognise, usually because the database was
                    replaced or restored. The server stays locked. If the database was restored on purpose, run{" "}
                    <code className="font-mono">sekret admin reset-epoch</code> on the host, then unlock again.
                  </p>
                </AlertDescription>
              </Alert>
            )}
            {otherError && (
              <Alert variant="destructive" data-testid="unlock-error">
                <AlertCircle />
                <AlertTitle>Unlocking failed</AlertTitle>
                <AlertDescription>{errorMessage(otherError)}</AlertDescription>
              </Alert>
            )}
          </CardContent>
          <CardFooter className="mt-6 flex-col gap-2">
            <Button
              type="submit"
              size="lg"
              className="w-full"
              disabled={unseal.isPending || waiting}
              aria-describedby={waiting ? "unlock-wait" : undefined}
              data-testid="unlock-submit"
            >
              {unseal.isPending ? <Spinner /> : <LockOpen />}
              Unlock
            </Button>
            <Button
              type="button"
              variant="link"
              size="sm"
              className="text-muted-foreground"
              onClick={() => void signOut(queryClient)}
              data-testid="unlock-sign-out"
            >
              Sign out
            </Button>
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}
