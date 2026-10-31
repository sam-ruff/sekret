import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Info, LogIn, ShieldAlert, Terminal } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { InitResponse, SysStatus, UnlockPolicy } from "@/api/types";
import { CopyButton } from "@/components/copy-button";
import { Logo } from "@/components/logo";
import { PassphraseFields } from "@/components/sys/passphrase-fields";
import { StrengthFeedback } from "@/components/sys/passphrase-meter";
import { StandalonePage } from "@/components/sys/standalone-page";
import { ConfiguredPolicy, UnlockDocsLink, UnlockPolicyCards } from "@/components/sys/unlock-policy-cards";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { keys, useSysStatus } from "@/hooks/queries";
import { usePassphraseStrength } from "@/hooks/use-passphrase-strength";
import { errorMessage } from "@/lib/errors";
import { passphraseProblem } from "@/lib/passphrase";
import { DOCS_URL } from "@/lib/links";

export function SetupPage() {
  const { data: status } = useSysStatus();
  const [created, setCreated] = useState<InitResponse | null>(null);

  if (created) return <AdminTokenCard token={created.admin_token} />;
  if (!status) return null;
  if (status.state !== "uninitialised") return <AlreadySetUp />;
  if (!status.web_setup) return <SetupDisabled />;
  return <SetupForm status={status} onCreated={setCreated} />;
}

function SetupHeader({ title, description }: { title: string; description: string }) {
  return (
    <CardHeader>
      <Logo className="mb-2 size-10 text-primary" title="sekret" />
      <CardTitle className="text-xl">{title}</CardTitle>
      <CardDescription>{description}</CardDescription>
    </CardHeader>
  );
}

function SetupForm({ status, onCreated }: { status: SysStatus; onCreated: (response: InitResponse) => void }) {
  const queryClient = useQueryClient();
  const [setupCode, setSetupCode] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [policy, setPolicy] = useState<UnlockPolicy>("manual");
  const strength = usePassphraseStrength(passphrase);

  const init = useMutation({
    mutationFn: () =>
      api.init({
        setup_code: setupCode.trim(),
        mode: "passphrase",
        passphrase,
        unlock_policy: status.configured ? null : policy,
      }),
    onSuccess: (response) => {
      queryClient.setQueryData(keys.sysStatus, response.status);
      onCreated(response);
    },
    onError: (error) => {
      // Someone else finished setup, or it was turned off; the status shows which.
      if (error instanceof ApiError && (error.status === 409 || error.status === 403)) {
        void queryClient.invalidateQueries({ queryKey: keys.sysStatus });
      }
    },
  });

  const error = init.error instanceof ApiError ? init.error : null;
  const codeError = error?.code === "invalid_setup_code" ? error : null;
  const weak = error?.code === "weak_passphrase" ? error : null;
  const otherError = init.error && !codeError && !weak ? init.error : null;
  const problem = passphraseProblem(passphrase, confirm, strength);
  const ready = setupCode.trim() !== "" && !problem && !init.isPending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) init.mutate();
  };

  return (
    <StandalonePage className="max-w-xl">
      <Card className="shadow-lg shadow-primary/5" data-testid="setup-card">
        <SetupHeader
          title="Set up sekret"
          description="Choose the passphrase that protects every secret on this server, and how it unlocks after a restart."
        />
        <form onSubmit={submit} noValidate>
          <CardContent>
            <FieldGroup>
              <Field data-invalid={!!codeError}>
                <FieldLabel htmlFor="setup-code">Setup code</FieldLabel>
                <Input
                  id="setup-code"
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono"
                  placeholder="XXXX-XXXX-XXXX"
                  value={setupCode}
                  aria-invalid={!!codeError}
                  onChange={(e) => setSetupCode(e.target.value)}
                  data-testid="setup-code"
                />
                {codeError ? (
                  <FieldError data-testid="setup-code-error">{errorMessage(codeError)}</FieldError>
                ) : (
                  <FieldDescription>
                    The server prints it in its log at start, and writes it to the setup code file if one is configured.
                  </FieldDescription>
                )}
              </Field>

              <PassphraseFields
                idPrefix="setup"
                label="Passphrase"
                passphrase={passphrase}
                confirm={confirm}
                strength={strength}
                onPassphraseChange={setPassphrase}
                onConfirmChange={setConfirm}
              />
              {weak && (
                <Alert variant="destructive" data-testid="setup-weak">
                  <AlertCircle />
                  <AlertTitle>The server refused this passphrase</AlertTitle>
                  <AlertDescription>
                    {weak.strength ? <StrengthFeedback strength={weak.strength} /> : errorMessage(weak)}
                  </AlertDescription>
                </Alert>
              )}
              <p className="flex gap-2 rounded-md bg-muted/60 px-3 py-2 text-sm text-muted-foreground" data-testid="no-recovery">
                <Info className="mt-0.5 size-4 shrink-0" />
                There is no recovery. If you forget this passphrase, the secrets cannot be decrypted.
              </p>

              <FieldSet>
                <FieldLegend>After a restart</FieldLegend>
                {status.configured ? (
                  <ConfiguredPolicy policy={status.unlock_policy} testId="setup-policy-configured" />
                ) : (
                  <UnlockPolicyCards idPrefix="setup" value={policy} onChange={setPolicy} />
                )}
                <UnlockDocsLink />
              </FieldSet>

              {otherError && (
                <Alert variant="destructive" data-testid="setup-error">
                  <AlertCircle />
                  <AlertTitle>Setup did not finish</AlertTitle>
                  <AlertDescription>{errorMessage(otherError)}</AlertDescription>
                </Alert>
              )}
            </FieldGroup>
          </CardContent>
          <CardFooter className="mt-6">
            <Button type="submit" size="lg" className="w-full" disabled={!ready} data-testid="setup-submit">
              {init.isPending && <Spinner />}
              Set up sekret
            </Button>
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}

function AdminTokenCard({ token }: { token: string }) {
  const navigate = useNavigate();
  return (
    <StandalonePage className="max-w-xl">
      <Card className="shadow-lg shadow-primary/5" data-testid="setup-done">
        <SetupHeader title="sekret is set up" description="The server is unlocked and ready to use." />
        <CardContent className="space-y-4">
          <Alert className="border-warning/50 bg-warning/10">
            <ShieldAlert className="text-warning" />
            <AlertTitle>This admin token is shown once</AlertTitle>
            <AlertDescription>
              It is short-lived and acts as an organisation admin. Store it somewhere safe, or skip it if an admin will
              sign in through your identity provider.
            </AlertDescription>
          </Alert>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">Admin token</p>
            <div className="flex items-center gap-1 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
              <code className="min-w-0 flex-1 font-mono text-sm break-all" data-testid="admin-token">
                {token}
              </code>
              <CopyButton value={token} label="Copy admin token" testId="admin-token-copy" />
            </div>
            <p className="text-xs text-muted-foreground">
              Use it with the CLI by setting <code className="font-mono">SEKRET_TOKEN</code>.
            </p>
          </div>
        </CardContent>
        <CardFooter>
          <Button size="lg" className="w-full" onClick={() => void navigate("/login")} data-testid="setup-continue">
            <LogIn />
            Continue to sign in
          </Button>
        </CardFooter>
      </Card>
    </StandalonePage>
  );
}

function AlreadySetUp() {
  const navigate = useNavigate();
  return (
    <StandalonePage>
      <Card data-testid="setup-already">
        <SetupHeader title="Already set up" description="This server has been set up. Sign in to use it." />
        <CardFooter>
          <Button className="w-full" onClick={() => void navigate("/login")}>
            <LogIn />
            Continue to sign in
          </Button>
        </CardFooter>
      </Card>
    </StandalonePage>
  );
}

function SetupDisabled() {
  return (
    <StandalonePage>
      <Card data-testid="setup-disabled">
        <CardHeader>
          <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <Terminal className="size-5" />
          </div>
          <CardTitle className="text-xl">Set up on the host</CardTitle>
          <CardDescription>
            This server is set up from its configuration. Run <code className="font-mono">sekret admin init</code> on
            the host, or see the{" "}
            <a
              href={`${DOCS_URL}getting-started/`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary underline-offset-4 hover:underline"
            >
              getting started guide
            </a>
            .
          </CardDescription>
        </CardHeader>
      </Card>
    </StandalonePage>
  );
}
