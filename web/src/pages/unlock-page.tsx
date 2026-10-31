import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, LockKeyhole, LockOpen, Timer } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import { PassphraseAccountField } from "@/components/sys/passphrase-fields";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { keys, useSysStatus } from "@/hooks/queries";
import { useCountdown } from "@/hooks/use-countdown";
import { backoffSeconds, errorMessage } from "@/lib/errors";
import { unlockPolicyLine } from "@/lib/sys-gate";

const INPUT_ERROR_ID = "unlock-passphrase-error";

export function UnlockPage() {
  const { data: status } = useSysStatus();
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [passphrase, setPassphrase] = useState("");
  const [empty, setEmpty] = useState(false);
  const [backoffUntil, setBackoffUntil] = useState(0);
  const waitSeconds = useCountdown(backoffUntil);

  const unseal = useMutation({
    mutationFn: () => api.unseal(passphrase),
    onSuccess: async (next) => {
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

  const error = unseal.error instanceof ApiError ? unseal.error : null;
  const wrong = error?.code === "invalid_passphrase";
  const backingOff = error?.code === "passphrase_backoff";
  const busy = error?.code === "kdf_busy";
  const limited = error?.status === 429 && !backingOff && !busy;
  const otherError = unseal.error && !wrong && error?.status !== 429 ? unseal.error : null;
  const waiting = backingOff && waitSeconds > 0;
  const policyLine = status ? unlockPolicyLine(status) : null;

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
          description="sekret is locked. Enter the passphrase to decrypt secrets."
          icon={<LockKeyhole />}
        />
        <form onSubmit={submit} noValidate>
          <CardContent className="space-y-4">
            <PassphraseAccountField />
            <Field data-invalid={!!inputError}>
              <FieldLabel htmlFor="unlock-passphrase">Passphrase</FieldLabel>
              <Input
                ref={input}
                id="unlock-passphrase"
                type="password"
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
            {backingOff && (
              <Alert variant="destructive" data-testid="unlock-backoff">
                <Timer />
                <AlertTitle>Too many wrong passphrases</AlertTitle>
                <AlertDescription id="unlock-wait">
                  {waiting ? (
                    <span>
                      Try again in <span data-testid="unlock-countdown">{waitSeconds}</span>{" "}
                      {waitSeconds === 1 ? "second" : "seconds"}.
                    </span>
                  ) : (
                    "You can try again now."
                  )}
                </AlertDescription>
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
            {otherError && (
              <Alert variant="destructive" data-testid="unlock-error">
                <AlertCircle />
                <AlertTitle>Unlocking failed</AlertTitle>
                <AlertDescription>{errorMessage(otherError)}</AlertDescription>
              </Alert>
            )}
            {policyLine && (
              <p className="text-sm text-muted-foreground" data-testid="unlock-policy">
                {policyLine}
              </p>
            )}
          </CardContent>
          <CardFooter className="mt-6">
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
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}
