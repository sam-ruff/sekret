import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, Download, ExternalLink, Lock } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SealMode, SysStatus, UnlockPolicy } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { ErrorState } from "@/components/states";
import { PassphraseAccountField, PassphraseFields } from "@/components/sys/passphrase-fields";
import { StrengthFeedback } from "@/components/sys/passphrase-meter";
import { ConfiguredPolicy, UnlockDocsLink, UnlockPolicyCards } from "@/components/sys/unlock-policy-cards";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { PassphraseInput } from "@/components/secret-field";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation, useSealWatch, useSysStatus } from "@/hooks/queries";
import { useIdle } from "@/hooks/use-idle";
import { usePassphraseStrength } from "@/hooks/use-passphrase-strength";
import { useIsOrgAdmin, useOrgPermissions } from "@/hooks/use-permissions";
import { EpochMarkStaleAlert } from "@/components/sys/epoch-mark-stale";
import { errorMessage, isEpochMarkStale } from "@/lib/errors";
import { DOCS_URL } from "@/lib/links";
import { passphraseProblem, problemText } from "@/lib/passphrase";
import { broadcast } from "@/lib/tab-sync";
import { keyFileOverride, POLICY_NAMES, UNSEALED_BY_NAMES } from "@/lib/sys-gate";

const NO_ACCESS = new ApiError("Only organisation admins and backup readers can see this page.", 403, "forbidden");

export function ServerPage() {
  const org = useOrgPermissions();
  const admin = useIsOrgAdmin();
  const canBackup = org.can("backups", "read");
  // Kept here because the policy card starts afresh whenever the saved policy changes.
  const [policyMarkStale, setPolicyMarkStale] = useState(false);
  // The public status says only whether the server is locked; admins read the rest from the detail.
  const publicStatus = useSysStatus(true);
  const detail = useQuery({
    queryKey: keys.sysStatusDetail,
    queryFn: api.sysStatusDetail,
    enabled: org.ready && admin,
    staleTime: 0,
  });
  const status = admin ? detail : publicStatus;

  if (org.ready && !admin && !canBackup) {
    return (
      <div className="space-y-6">
        <PageHeader title="Server" />
        <div className="max-w-3xl">
          <ErrorState error={NO_ACCESS} />
        </div>
      </div>
    );
  }
  const header = admin ? (
    <PageHeader title="Server" description="Locking, unlocking and backups for this sekret server." />
  ) : (
    <PageHeader title="Server" description="See whether this sekret server is unlocked and download encrypted backups." />
  );
  if (org.ready && status.error && !status.data) {
    return (
      <div className="space-y-6">
        {header}
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      </div>
    );
  }
  if (!status.data || !org.ready) {
    return (
      <div className="space-y-6">
        {header}
        <Skeleton className="h-40 max-w-3xl rounded-xl" />
      </div>
    );
  }

  const passphraseMode = status.data.seal_mode === "passphrase";
  return (
    <div className="space-y-6">
      {header}
      <div className="grid max-w-3xl gap-6">
        <StatusCard status={status.data} admin={admin} canLock={admin && passphraseMode} />
        {admin && passphraseMode && (
          <UnlockPolicyCard
            key={status.data.unlock_policy ?? ""}
            status={status.data}
            markStale={policyMarkStale}
            onMarkStale={setPolicyMarkStale}
          />
        )}
        {admin && passphraseMode && <ChangePassphraseCard />}
        {canBackup && <BackupCard mode={status.data.seal_mode ?? null} />}
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:items-center sm:gap-4">
      <dt className="text-sm text-muted-foreground sm:w-40 sm:shrink-0">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function StatusCard({ status, admin, canLock }: { status: SysStatus; admin: boolean; canLock: boolean }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const seal = useApiMutation({
    mutationFn: api.seal,
    // The status gate sees the locked state, clears the cache and moves to the unlock page, here and in other tabs.
    onSuccess: (next) => {
      queryClient.setQueryData(keys.sysStatus, next);
      broadcast("sealed");
    },
  });

  const policy = status.unlock_policy;
  return (
    <Card data-testid="server-status">
      <CardHeader>
        <CardTitle>Status</CardTitle>
        <CardDescription data-testid="server-status-help">
          {admin ? "How this server keeps its root key." : "Whether the server is unlocked."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <dl className="divide-y">
          <Row label="State">
            <Badge variant={status.state === "unsealed" ? "secondary" : "destructive"} data-testid="server-state">
              {status.state === "unsealed" ? "Unlocked" : "Locked"}
            </Badge>
          </Row>
          {status.seal_mode && (
            <Row label="Protected by">
              <span data-testid="server-mode">{status.seal_mode === "key-file" ? "Key file" : "Passphrase"}</span>
            </Row>
          )}
          {status.unsealed_by && (
            <Row label="Unlocked by">
              <span data-testid="server-unsealed-by">{UNSEALED_BY_NAMES[status.unsealed_by]}</span>
            </Row>
          )}
          {policy && (
            <Row label="Unlock policy">
              <span data-testid="server-policy">
                {POLICY_NAMES[policy]}
                {status.configured && <span className="text-muted-foreground"> (set in configuration)</span>}
              </span>
            </Row>
          )}
          <Row label="Version">
            <span className="font-mono" data-testid="server-version">
              {status.version}
            </span>
          </Row>
        </dl>
        {keyFileOverride(status) && (
          <Alert className="border-warning/50 bg-warning/10" data-testid="server-key-file-override">
            <AlertTriangle className="text-warning" />
            <AlertTitle>A key file unlocked this server</AlertTitle>
            <AlertDescription>
              The server is set up with a passphrase, but a root key file given at start unlocked it without one. Anyone
              who can read that file can unlock the server. Remove the key file from the configuration unless that is
              intended.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
      {canLock && (
        <CardFooter className="flex-col items-stretch gap-3 border-t sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium">Lock the server</p>
            <p className="text-sm text-muted-foreground" data-testid="lock-help">
              Locking drops the key from memory straight away. Everything that reads secrets gets errors until someone
              unlocks it with the passphrase. The CLI and the docs call this sealing.
            </p>
          </div>
          <Button variant="outline" className="shrink-0" onClick={() => setConfirming(true)} data-testid="seal-now">
            <Lock />
            Lock now
          </Button>
        </CardFooter>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Lock the server now?"
        description={`Applications and people get errors until someone unlocks it with the passphrase. You will go to the unlock page.${
          status.remembered ? " A remembered unlock still unlocks it after a restart." : ""
        }`}
        confirmLabel="Lock now"
        destructive
        onConfirm={() => seal.mutateAsync()}
        testId="seal-dialog"
      />
    </Card>
  );
}

/** Errors the policy dialog shows next to its passphrase field rather than as a toast. */
function isPassphraseError(error: unknown): error is ApiError {
  return (
    error instanceof ApiError &&
    (error.code === "invalid_passphrase" || error.code === "passphrase_required" || error.status === 429)
  );
}

function UnlockPolicyCard({
  status,
  markStale,
  onMarkStale,
}: {
  status: SysStatus;
  /** The last policy change was saved but the seal mark outside the database is behind. */
  markStale: boolean;
  onMarkStale: (stale: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const current = status.unlock_policy ?? "manual";
  const [policy, setPolicy] = useState<UnlockPolicy>(current);
  const [confirming, setConfirming] = useState(false);
  const [forgetting, setForgetting] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [empty, setEmpty] = useState(false);

  const save = useApiMutation({
    mutationFn: (confirmWith: string | undefined) => {
      onMarkStale(false);
      return api.setUnlockPolicy(policy, confirmWith);
    },
    // The passphrase is the mutation's variable, so it must not linger in the mutation cache.
    gcTime: 0,
    onSuccess: (next) => {
      setPassphrase("");
      queryClient.setQueryData(keys.sysStatusDetail, next);
      save.reset();
    },
    onError: (error) => {
      if (!isEpochMarkStale(error)) return isPassphraseError(error);
      // The policy did change; only the mark outside the database is behind.
      onMarkStale(true);
      setPassphrase("");
      setConfirming(false);
      toast.warning("Unlock policy saved, but the host needs a repair");
      void queryClient.invalidateQueries({ queryKey: keys.sysStatusDetail });
      save.reset();
      return true;
    },
    success: "Unlock policy saved",
  });
  const forget = useApiMutation({
    mutationFn: api.forgetUnlock,
    onSuccess: (next) => queryClient.setQueryData(keys.sysStatusDetail, next),
    success: "Remembered unlock forgotten",
  });

  // Anything but manual lets the server unlock without a person, so the server wants the passphrase.
  const weakens = policy !== "manual";
  const onSave = () => {
    if (!weakens) {
      save.mutate(undefined);
      return;
    }
    save.reset();
    setEmpty(false);
    setPassphrase("");
    setConfirming(true);
  };
  const confirmSave = async () => {
    if (!passphrase) {
      setEmpty(true);
      throw new Error("no passphrase");
    }
    try {
      await save.mutateAsync(passphrase);
    } catch (error) {
      // Saved, with a repair needed on the host; the card says so once the dialog closes.
      if (isEpochMarkStale(error)) return;
      throw error;
    }
  };

  const dialogError = isPassphraseError(save.error) ? save.error : null;
  const fieldError = empty && !passphrase ? "Enter the current passphrase." : dialogError ? passphraseErrorText(dialogError) : null;

  return (
    <Card data-testid="server-unlock-policy">
      <CardHeader>
        <CardTitle>Unlock policy</CardTitle>
        <CardDescription>How the server gets unlocked after it starts.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {markStale && <EpochMarkStaleAlert change="The unlock policy" testId="policy-mark-stale" />}
        {status.configured ? (
          <ConfiguredPolicy policy={status.unlock_policy} testId="server-policy-configured" />
        ) : (
          <UnlockPolicyCards
            idPrefix="server"
            value={policy}
            onChange={setPolicy}
            disabled={save.isPending}
            rememberAvailable={status.remember_available}
          />
        )}
        {current === "remember" && (
          <div
            className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between"
            data-testid="server-remembered-box"
          >
            <div className="space-y-1 text-sm">
              <p className="font-medium" data-testid="server-remembered">
                {status.remembered ? "Remembered: yes, it unlocks itself after a restart" : "Remembered: no"}
              </p>
              <p className="text-muted-foreground">
                {status.remembered
                  ? "Locking the server does not forget this. Forget it to make the next restart need the passphrase."
                  : "Unlocking with the passphrase remembers it again."}
              </p>
            </div>
            {status.remembered && (
              <Button
                variant="outline"
                className="shrink-0"
                disabled={forget.isPending}
                onClick={() => setForgetting(true)}
                data-testid="forget-unlock"
              >
                Forget remembered unlock
              </Button>
            )}
          </div>
        )}
        <UnlockDocsLink />
      </CardContent>
      {!status.configured && (
        <CardFooter className="flex-col items-end gap-2">
          <Button disabled={policy === current || save.isPending} onClick={onSave} data-testid="policy-save">
            {save.isPending && !confirming && <Spinner />}
            Save policy
          </Button>
          {policy === current && (
            <p className="text-sm text-muted-foreground" data-testid="policy-save-hint">
              Choose a different policy to save.
            </p>
          )}
        </CardFooter>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={(open) => {
          setConfirming(open);
          if (open) return;
          setPassphrase("");
          if (!save.isPending) save.reset();
        }}
        title={`Switch to ${POLICY_NAMES[policy]}?`}
        description="Confirm with the current passphrase. This lets the server unlock without a person."
        confirmLabel="Save policy"
        onConfirm={confirmSave}
        testId="policy-dialog"
      >
        <PassphraseAccountField />
        <Field data-invalid={!!fieldError}>
          <FieldLabel htmlFor="policy-passphrase">Current passphrase</FieldLabel>
          <PassphraseInput
            id="policy-passphrase"
            autoComplete="current-password"
            autoFocus
            value={passphrase}
            aria-invalid={!!fieldError}
            aria-describedby={fieldError ? "policy-passphrase-error" : undefined}
            onChange={(e) => setPassphrase(e.target.value)}
            data-testid="policy-passphrase"
          />
          {fieldError && (
            <FieldError id="policy-passphrase-error" data-testid="policy-passphrase-error">
              {fieldError}
            </FieldError>
          )}
        </Field>
      </ConfirmDialog>
      <ConfirmDialog
        open={forgetting}
        onOpenChange={setForgetting}
        title="Forget the remembered unlock?"
        description="The key file is deleted. After the next restart someone has to unlock the server with the passphrase."
        confirmLabel="Forget"
        destructive
        onConfirm={() => forget.mutateAsync()}
        testId="forget-dialog"
      />
    </Card>
  );
}

function passphraseErrorText(error: ApiError): string {
  if (error.code === "invalid_passphrase") return "That passphrase is wrong.";
  return errorMessage(error);
}

const CURRENT_ERROR_ID = "current-passphrase-error";

function ChangePassphraseCard() {
  const [current, setCurrent] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const strength = usePassphraseStrength(passphrase);
  // Typed passphrases are cleared when nobody is using the page, like revealed values.
  const typed = current !== "" || passphrase !== "" || confirm !== "";
  useSealWatch(typed);
  useIdle(typed, () => {
    setCurrent("");
    setPassphrase("");
    setConfirm("");
    toast.info("Cleared the passphrase fields after three idle minutes.");
  });

  const queryClient = useQueryClient();
  const [markStale, setMarkStale] = useState(false);
  const done = () => {
    setCurrent("");
    setPassphrase("");
    setConfirm("");
    change.reset();
  };
  const change = useMutation({
    mutationFn: () => api.changePassphrase({ current, new: passphrase }),
    gcTime: 0,
    onMutate: () => setMarkStale(false),
    onSuccess: () => {
      toast.success("Passphrase changed");
      done();
    },
    onError: (error) => {
      if (!isEpochMarkStale(error)) return;
      // The passphrase did change; only the mark outside the database is behind.
      setMarkStale(true);
      toast.warning("Passphrase changed, but the host needs a repair");
      void queryClient.invalidateQueries({ queryKey: keys.sysStatusDetail });
      done();
    },
  });

  const error = change.error instanceof ApiError ? change.error : null;
  const wrong = error?.code === "invalid_passphrase" ? error : null;
  const weak = error?.code === "weak_passphrase" ? error : null;
  const keyFile = error?.code === "root_key_file_in_use" ? error : null;
  const otherError = change.error && !wrong && !weak && !keyFile ? change.error : null;
  const problem = passphraseProblem(passphrase, confirm, strength);
  const blocker = current === "" ? "Enter the current passphrase to continue." : problem ? problemText(problem) : null;
  const ready = !blocker && !change.isPending;

  const [confirming, setConfirming] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) setConfirming(true);
  };

  return (
    <Card data-testid="server-passphrase">
      <CardHeader>
        <CardTitle>Change passphrase</CardTitle>
        <CardDescription className="space-y-2" data-testid="change-passphrase-help">
          <p className="font-medium text-foreground">
            Every secret is re-encrypted. Backups made before this still need the old passphrase.
          </p>
          <ul className="list-disc space-y-0.5 pl-5">
            <li>The old passphrase stops working on this server.</li>
            <li>A remembered unlock is forgotten, so the next restart needs the new passphrase.</li>
            <li>If the server reads its passphrase from a file, update that file too.</li>
          </ul>
        </CardDescription>
      </CardHeader>
      <form onSubmit={submit} noValidate>
        <CardContent>
          <FieldGroup>
            {markStale && <EpochMarkStaleAlert change="The new passphrase" testId="change-mark-stale" />}
            <PassphraseAccountField />
            <Field data-invalid={!!wrong}>
              <FieldLabel htmlFor="current-passphrase">Current passphrase</FieldLabel>
              <PassphraseInput
                id="current-passphrase"
                autoComplete="current-password"
                value={current}
                aria-invalid={!!wrong}
                aria-describedby={wrong ? CURRENT_ERROR_ID : undefined}
                onChange={(e) => setCurrent(e.target.value)}
                data-testid="current-passphrase"
              />
              {wrong && (
                <FieldError id={CURRENT_ERROR_ID} data-testid="current-passphrase-wrong">
                  That passphrase is wrong.
                </FieldError>
              )}
            </Field>
            <PassphraseFields
              idPrefix="change"
              label="New passphrase"
              passphrase={passphrase}
              confirm={confirm}
              strength={strength}
              onPassphraseChange={setPassphrase}
              onConfirmChange={setConfirm}
            />
            {weak && (
              <Alert variant="destructive" data-testid="change-weak">
                <AlertCircle />
                <AlertTitle>The server refused this passphrase</AlertTitle>
                <AlertDescription>
                  {weak.strength ? <StrengthFeedback strength={weak.strength} /> : errorMessage(weak)}
                </AlertDescription>
              </Alert>
            )}
            {keyFile && (
              <Alert variant="destructive" data-testid="change-key-file">
                <AlertCircle />
                <AlertTitle>Change it on the host instead</AlertTitle>
                <AlertDescription>
                  <p>
                    This server also starts from a root key file, which would still hold the old key, so the passphrase
                    cannot be changed here. Remove the key file, restart, unlock with the passphrase, then change it
                    here or with <code className="font-mono">sekret sys change-passphrase</code>.
                  </p>
                  <a
                    href={`${DOCS_URL}security/#changing-the-passphrase`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 underline underline-offset-2"
                    data-testid="change-key-file-docs"
                  >
                    Changing the passphrase
                    <ExternalLink className="size-3.5" aria-hidden />
                    <span className="sr-only">(opens in a new tab)</span>
                  </a>
                </AlertDescription>
              </Alert>
            )}
            {otherError && (
              <Alert variant="destructive" data-testid="change-error">
                <AlertCircle />
                <AlertTitle>The passphrase was not changed</AlertTitle>
                <AlertDescription>{errorMessage(otherError)}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </CardContent>
        <CardFooter className="mt-6 flex-col items-end gap-2">
          <Button
            type="submit"
            disabled={!ready}
            aria-describedby={blocker ? "change-blocker" : undefined}
            data-testid="change-submit"
          >
            {change.isPending && <Spinner />}
            Change passphrase
          </Button>
          {blocker && (
            <p id="change-blocker" className="text-sm text-muted-foreground" data-testid="change-blocker">
              {blocker}
            </p>
          )}
        </CardFooter>
      </form>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Change the passphrase now?"
        description="Every secret is re-encrypted. Backups made before this still need the old passphrase, so keep it with them."
        confirmLabel="Change passphrase"
        onConfirm={async () => {
          if (ready) change.mutate();
        }}
        testId="change-passphrase-dialog"
      />
    </Card>
  );
}

function saveFile(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const BACKUP_RESTORE_NEEDS: Record<SealMode | "unknown", string> = {
  passphrase: "Restoring it needs the passphrase that was in use when it was made.",
  "key-file": "Restoring it needs the server's root key file.",
  unknown: "Restoring it needs the passphrase or root key file that was in use when it was made.",
};

/** `mode` is null when the caller may not see how the server is protected. */
function BackupCard({ mode }: { mode: SealMode | null }) {
  const download = useApiMutation({
    mutationFn: api.backup,
    onSuccess: ({ blob, filename }) => saveFile(blob, filename),
  });

  return (
    <Card data-testid="server-backup">
      <CardHeader>
        <CardTitle>Backup</CardTitle>
        <CardDescription>
          An encrypted copy of the database. {BACKUP_RESTORE_NEEDS[mode ?? "unknown"]}
        </CardDescription>
      </CardHeader>
      <CardFooter className="justify-end">
        <Button variant="outline" disabled={download.isPending} onClick={() => download.mutate()} data-testid="backup-download">
          {download.isPending ? <Spinner /> : <Download />}
          Download encrypted backup
        </Button>
      </CardFooter>
    </Card>
  );
}
