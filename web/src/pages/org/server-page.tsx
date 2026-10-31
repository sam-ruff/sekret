import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Download, Lock } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SysStatus, UnlockPolicy } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { ErrorState } from "@/components/states";
import { PassphraseFields } from "@/components/sys/passphrase-fields";
import { StrengthFeedback } from "@/components/sys/passphrase-meter";
import { ConfiguredPolicy, UnlockDocsLink, UnlockPolicyCards } from "@/components/sys/unlock-policy-cards";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation, useSysStatus } from "@/hooks/queries";
import { usePassphraseStrength } from "@/hooks/use-passphrase-strength";
import { useIsOrgAdmin, useOrgPermissions } from "@/hooks/use-permissions";
import { errorMessage } from "@/lib/errors";
import { passphraseProblem } from "@/lib/passphrase";
import { POLICY_NAMES } from "@/lib/sys-gate";

const NO_ACCESS = new ApiError("Only organisation admins and backup readers can see this page.", 403, "forbidden");

export function ServerPage() {
  const status = useSysStatus(true);
  const org = useOrgPermissions();
  const admin = useIsOrgAdmin();
  const canBackup = org.can("backups", "read");

  const header = <PageHeader title="Server" description="Sealing, unlocking and backups for this sekret server." />;
  if (org.ready && !admin && !canBackup) {
    return (
      <div className="space-y-6">
        {header}
        <ErrorState error={NO_ACCESS} />
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
        <StatusCard status={status.data} canSeal={admin && passphraseMode} />
        {admin && passphraseMode && <UnlockPolicyCard key={status.data.unlock_policy ?? ""} status={status.data} />}
        {admin && passphraseMode && <ChangePassphraseCard />}
        {canBackup && <BackupCard passphraseMode={passphraseMode} />}
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

function StatusCard({ status, canSeal }: { status: SysStatus; canSeal: boolean }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const seal = useApiMutation({
    mutationFn: api.seal,
    // The status gate sees the sealed state and moves to the unlock page.
    onSuccess: (next) => queryClient.setQueryData(keys.sysStatus, next),
  });

  const policy = status.unlock_policy;
  return (
    <Card data-testid="server-status">
      <CardHeader>
        <CardTitle>Status</CardTitle>
        <CardDescription>How this server keeps its root key.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="divide-y">
          <Row label="State">
            <Badge variant={status.state === "unsealed" ? "secondary" : "destructive"} data-testid="server-state">
              {status.state === "unsealed" ? "Unlocked" : "Sealed"}
            </Badge>
          </Row>
          <Row label="Root key">
            <span data-testid="server-mode">{status.seal_mode === "key-file" ? "Key file" : "Passphrase"}</span>
          </Row>
          {policy && (
            <Row label="Unlock policy">
              <span data-testid="server-policy">
                {POLICY_NAMES[policy]}
                {status.configured && <span className="text-muted-foreground"> (set in configuration)</span>}
              </span>
            </Row>
          )}
          {policy === "remember" && (
            <Row label="Remembered">
              <span data-testid="server-remembered">{status.remembered ? "Yes, it unlocks itself after a restart" : "No"}</span>
            </Row>
          )}
          <Row label="Version">
            <span className="font-mono" data-testid="server-version">
              {status.version}
            </span>
          </Row>
        </dl>
      </CardContent>
      {canSeal && (
        <CardFooter className="justify-end">
          <Button variant="outline" onClick={() => setConfirming(true)} data-testid="seal-now">
            <Lock />
            Seal now
          </Button>
        </CardFooter>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Seal the server?"
        description="sekret drops its root key from memory. Every application and person gets an error until someone unlocks it with the passphrase."
        confirmLabel="Seal now"
        destructive
        onConfirm={() => seal.mutateAsync()}
        testId="seal-dialog"
      />
    </Card>
  );
}

function UnlockPolicyCard({ status }: { status: SysStatus }) {
  const queryClient = useQueryClient();
  const current = status.unlock_policy ?? "manual";
  const [policy, setPolicy] = useState<UnlockPolicy>(current);

  const save = useApiMutation({
    mutationFn: () => api.setUnlockPolicy(policy),
    onSuccess: (next) => queryClient.setQueryData(keys.sysStatus, next),
    success: "Unlock policy saved",
  });
  const forget = useApiMutation({
    mutationFn: api.forgetUnlock,
    onSuccess: (next) => queryClient.setQueryData(keys.sysStatus, next),
    success: "Remembered unlock forgotten",
  });

  return (
    <Card data-testid="server-unlock-policy">
      <CardHeader>
        <CardTitle>Unlock policy</CardTitle>
        <CardDescription>How the server gets unlocked after it starts.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {status.configured ? (
          <ConfiguredPolicy policy={status.unlock_policy} testId="server-policy-configured" />
        ) : (
          <UnlockPolicyCards idPrefix="server" value={policy} onChange={setPolicy} disabled={save.isPending} />
        )}
        {status.remembered && (
          <div
            className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between"
            data-testid="server-remembered-box"
          >
            <p className="text-sm text-muted-foreground">
              The server keeps a key file so it can unlock itself after a restart. Forgetting deletes it, so the next
              start needs the passphrase.
            </p>
            <Button
              variant="outline"
              className="shrink-0"
              disabled={forget.isPending}
              onClick={() => forget.mutate()}
              data-testid="forget-unlock"
            >
              {forget.isPending && <Spinner />}
              Forget remembered unlock
            </Button>
          </div>
        )}
        <UnlockDocsLink />
      </CardContent>
      {!status.configured && (
        <CardFooter className="justify-end">
          <Button disabled={policy === current || save.isPending} onClick={() => save.mutate()} data-testid="policy-save">
            {save.isPending && <Spinner />}
            Save policy
          </Button>
        </CardFooter>
      )}
    </Card>
  );
}

function ChangePassphraseCard() {
  const [current, setCurrent] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const strength = usePassphraseStrength(passphrase);

  const change = useMutation({
    mutationFn: () => api.changePassphrase({ current, new: passphrase }),
    onSuccess: () => {
      toast.success("Passphrase changed");
      setCurrent("");
      setPassphrase("");
      setConfirm("");
    },
  });

  const error = change.error instanceof ApiError ? change.error : null;
  const wrong = error?.code === "invalid_passphrase" ? error : null;
  const weak = error?.code === "weak_passphrase" ? error : null;
  const otherError = change.error && !wrong && !weak ? change.error : null;
  const ready = current !== "" && !passphraseProblem(passphrase, confirm, strength) && !change.isPending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (ready) change.mutate();
  };

  return (
    <Card data-testid="server-passphrase">
      <CardHeader>
        <CardTitle>Change passphrase</CardTitle>
        <CardDescription>Backups made before the change still open with the old passphrase.</CardDescription>
      </CardHeader>
      <form onSubmit={submit} noValidate>
        <CardContent>
          <FieldGroup>
            <Field data-invalid={!!wrong}>
              <FieldLabel htmlFor="current-passphrase">Current passphrase</FieldLabel>
              <Input
                id="current-passphrase"
                type="password"
                autoComplete="current-password"
                value={current}
                aria-invalid={!!wrong}
                onChange={(e) => setCurrent(e.target.value)}
                data-testid="current-passphrase"
              />
              {wrong && <FieldError data-testid="current-passphrase-wrong">That passphrase is wrong.</FieldError>}
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
            {otherError && (
              <Alert variant="destructive" data-testid="change-error">
                <AlertCircle />
                <AlertTitle>The passphrase was not changed</AlertTitle>
                <AlertDescription>{errorMessage(otherError)}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </CardContent>
        <CardFooter className="mt-6 justify-end">
          <Button type="submit" disabled={!ready} data-testid="change-submit">
            {change.isPending && <Spinner />}
            Change passphrase
          </Button>
        </CardFooter>
      </form>
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

function BackupCard({ passphraseMode }: { passphraseMode: boolean }) {
  const download = useApiMutation({
    mutationFn: api.backup,
    onSuccess: ({ blob, filename }) => saveFile(blob, filename),
  });

  return (
    <Card data-testid="server-backup">
      <CardHeader>
        <CardTitle>Backup</CardTitle>
        <CardDescription>
          {passphraseMode
            ? "An encrypted copy of the database. Restoring it needs the passphrase that was in use when it was made."
            : "An encrypted copy of the database. Restoring it needs the server's root key file."}
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
