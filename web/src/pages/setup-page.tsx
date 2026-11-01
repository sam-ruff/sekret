import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, ArrowRight, ExternalLink, Eye, FileKey, Info, LogIn, ShieldAlert, Terminal } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { InitResponse, SysStatus, UnlockPolicy } from "@/api/types";
import { CopyButton } from "@/components/copy-button";
import { PassphraseAccountField, PassphraseFields } from "@/components/sys/passphrase-fields";
import { StrengthFeedback } from "@/components/sys/passphrase-meter";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { ConfiguredPolicy, UnlockDocsLink, UnlockPolicyCards } from "@/components/sys/unlock-policy-cards";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { SecretInput } from "@/components/secret-field";
import { Spinner } from "@/components/ui/spinner";
import { keys, useAuthConfig, useSealWatch, useSysStatus } from "@/hooks/queries";
import { useIdle } from "@/hooks/use-idle";
import { usePassphraseStrength } from "@/hooks/use-passphrase-strength";
import { errorMessage } from "@/lib/errors";
import { formatExpiry } from "@/lib/format";
import { DOCS_URL } from "@/lib/links";
import { passphraseProblem, problemText } from "@/lib/passphrase";

/** What the person keeps from setup; the mutation's own copy is dropped straight away. */
interface Created {
  token: string;
  expiresAt?: number;
}

export function SetupPage() {
  const { data: status } = useSysStatus();
  const [created, setCreated] = useState<Created | null>(null);

  if (created) return <AdminTokenCard created={created} />;
  if (!status) return null;
  if (status.state !== "uninitialised") return <AlreadySetUp />;
  if (!status.web_setup) return <SetupDisabled />;
  return <SetupForm status={status} onCreated={setCreated} />;
}

const CODE_ERROR_ID = "setup-code-error";
const CODE_HINT_ID = "setup-code-hint";

function SetupForm({ status, onCreated }: { status: SysStatus; onCreated: (created: Created) => void }) {
  const queryClient = useQueryClient();
  const codeInput = useRef<HTMLInputElement>(null);
  const keyFile = status.seal_mode === "key-file";
  const [setupCode, setSetupCode] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [policy, setPolicy] = useState<UnlockPolicy>("manual");
  const strength = usePassphraseStrength(keyFile ? "" : passphrase);
  useIdle(setupCode !== "" || passphrase !== "" || confirm !== "", () => {
    setSetupCode("");
    setPassphrase("");
    setConfirm("");
  });

  const init = useMutation({
    mutationFn: () =>
      api.init(
        keyFile
          ? { setup_code: setupCode.trim(), mode: "key-file" }
          : {
              setup_code: setupCode.trim(),
              mode: "passphrase",
              passphrase,
              unlock_policy: status.configured ? null : policy,
            },
      ),
    // The response holds the admin token; keep it only in the card's state.
    gcTime: 0,
    onSuccess: (response: InitResponse) => {
      onCreated({ token: response.admin_token, expiresAt: response.admin_token_expires_at });
      init.reset();
      queryClient.setQueryData(keys.sysStatus, response.status);
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "invalid_setup_code") codeInput.current?.focus();
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
  const problem = keyFile ? undefined : passphraseProblem(passphrase, confirm, strength);
  const blocker = setupCode.trim() === "" ? "Enter the setup code to continue." : problem ? problemText(problem) : null;
  const ready = !blocker && !init.isPending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) init.mutate();
  };

  return (
    <StandalonePage className="max-w-xl">
      <Card className="shadow-lg shadow-primary/5" data-testid="setup-card">
        <StandaloneHeader
          title="Set up sekret"
          pageTitle="Set up"
          description={
            keyFile
              ? "This server keeps its root key in a file, so there is no passphrase to choose."
              : "Choose the passphrase that protects every secret on this server, and how it unlocks after a restart."
          }
        />
        <form onSubmit={submit} noValidate>
          <CardContent>
            <FieldGroup>
              <Field data-invalid={!!codeError}>
                <FieldLabel htmlFor="setup-code">Setup code</FieldLabel>
                <SecretInput
                  ref={codeInput}
                  id="setup-code"
                  className="font-mono"
                  placeholder="XXXX-XXXX-XXXX"
                  value={setupCode}
                  aria-invalid={!!codeError}
                  aria-describedby={codeError ? CODE_ERROR_ID : CODE_HINT_ID}
                  onChange={(e) => setSetupCode(e.target.value)}
                  data-testid="setup-code"
                />
                {codeError ? (
                  <FieldError id={CODE_ERROR_ID} data-testid="setup-code-error">
                    That setup code is wrong. Check the latest one in the server log.
                  </FieldError>
                ) : (
                  <FieldDescription id={CODE_HINT_ID}>
                    The server prints it in its log when it starts, and writes it to the setup code file if one is set.
                    Restarting the server makes a new code.
                  </FieldDescription>
                )}
              </Field>

              {keyFile ? (
                <p className="flex gap-2 rounded-md bg-muted/60 px-3 py-2 text-sm text-muted-foreground" data-testid="setup-key-file">
                  <FileKey className="mt-0.5 size-4 shrink-0" aria-hidden />
                  The server configuration names a root key file. Setup creates the key in that file and unlocks with it
                  at every start. Keep a copy of the file somewhere safe: backups cannot be restored without it.
                </p>
              ) : (
                <>
                  <PassphraseAccountField />
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
                    <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
                    There is no recovery. If you forget this passphrase, the secrets cannot be decrypted. Store it in a
                    password manager.
                  </p>

                  <FieldSet>
                    <FieldLegend>After a restart</FieldLegend>
                    {status.configured ? (
                      <ConfiguredPolicy policy={status.unlock_policy} testId="setup-policy-configured" />
                    ) : (
                      <UnlockPolicyCards
                        idPrefix="setup"
                        value={policy}
                        onChange={setPolicy}
                        rememberAvailable={status.remember_available}
                      />
                    )}
                    <UnlockDocsLink />
                  </FieldSet>
                </>
              )}

              {otherError && (
                <Alert variant="destructive" data-testid="setup-error">
                  <AlertCircle />
                  <AlertTitle>Setup did not finish</AlertTitle>
                  <AlertDescription className="break-words">{errorMessage(otherError)}</AlertDescription>
                </Alert>
              )}
            </FieldGroup>
          </CardContent>
          <CardFooter className="mt-6 flex-col items-stretch gap-2">
            <Button
              type="submit"
              size="lg"
              className="w-full"
              disabled={!ready}
              aria-describedby={blocker ? "setup-blocker" : undefined}
              data-testid="setup-submit"
            >
              {init.isPending && <Spinner />}
              Set up sekret
            </Button>
            {blocker && (
              <p id="setup-blocker" className="text-center text-sm text-muted-foreground" data-testid="setup-blocker">
                {blocker}
              </p>
            )}
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}

function NoSignInProvider() {
  return (
    <Alert data-testid="setup-no-oidc">
      <Info />
      <AlertTitle>Web sign-in is not set up yet</AlertTitle>
      <AlertDescription>
        <p>
          This server has no sign-in provider, so nobody can sign in to the web interface yet. Use the admin token with
          the CLI for now. To turn on web sign-in, set <code className="font-mono">oidc.issuer</code> and the client
          secret in the server configuration, then restart the server. See{" "}
          <a
            href={`${DOCS_URL}configuration/#signing-in-with-oidc`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
            data-testid="setup-oidc-docs-link"
          >
            signing in with OIDC
            <ExternalLink className="size-3" aria-hidden />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
          .
        </p>
      </AlertDescription>
    </Alert>
  );
}

function AdminTokenCard({ created }: { created: Created }) {
  const navigate = useNavigate();
  const { data: config } = useAuthConfig();
  const noProvider = config?.oidc_enabled === false;
  const expiry = created.expiresAt ? `expires ${formatExpiry(created.expiresAt)}` : "expires after a while";
  const snippet = (token: string) => `export SEKRET_URL=${window.location.origin}\nexport SEKRET_TOKEN=${token}`;
  // The token cannot be shown again, so idling masks it rather than dropping it; a seal still takes the page away.
  const [masked, setMasked] = useState(false);
  useIdle(!masked, () => setMasked(true));
  useSealWatch(true);
  return (
    <StandalonePage className="max-w-xl">
      <Card className="shadow-lg shadow-primary/5" data-testid="setup-done">
        <StandaloneHeader title="sekret is set up" pageTitle="Set up" description="The server is unlocked and ready to use." />
        <CardContent className="space-y-4">
          <Alert className="border-warning/50 bg-warning/10">
            <ShieldAlert className="text-warning" />
            <AlertTitle>Save the admin token</AlertTitle>
            <AlertDescription data-testid="admin-token-help">
              Copy this token now. It is shown once and {expiry}. It lets the CLI act as an organisation admin, for
              example to add users or set up sign-in.
              {!noProvider && " The web interface signs you in through your identity provider."}
            </AlertDescription>
          </Alert>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">Admin token</p>
            <div className="flex items-center gap-1 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
              <code className="min-w-0 flex-1 font-mono text-sm break-all" data-testid="admin-token">
                {masked ? "•".repeat(24) : created.token}
              </code>
              {masked && (
                <Button variant="ghost" size="sm" onClick={() => setMasked(false)} data-testid="admin-token-show">
                  <Eye />
                  Show
                </Button>
              )}
              <CopyButton value={created.token} label="Copy admin token" testId="admin-token-copy" sensitive />
            </div>
          </div>
          <div className="space-y-1.5">
            <p className="flex items-center gap-1.5 text-sm font-medium">
              <Terminal className="size-4" aria-hidden />
              Use it with the CLI
            </p>
            <div className="flex items-start gap-1 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
              <pre className="min-w-0 flex-1 overflow-x-auto py-1 font-mono text-xs" data-testid="admin-token-cli">
                {snippet("<token>")}
              </pre>
              <CopyButton
                value={snippet(created.token)}
                label="Copy these commands with the token"
                testId="admin-token-cli-copy"
                sensitive
              />
            </div>
          </div>
          {noProvider && <NoSignInProvider />}
        </CardContent>
        <CardFooter>
          <Button size="lg" className="w-full" onClick={() => void navigate("/login")} data-testid="setup-continue">
            I have saved it, continue
            <ArrowRight />
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
        <StandaloneHeader title="Already set up" pageTitle="Set up" description="This server has been set up. Sign in to use it." />
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
        <StandaloneHeader
          title="Set up on the host"
          pageTitle="Set up"
          icon={<Terminal />}
          description={
            <>
              Web setup is turned off. Run <code className="font-mono">sekret admin init</code> on the host, then restart
              the server. Reload this page once it is done.
            </>
          }
        />
      </Card>
    </StandalonePage>
  );
}
