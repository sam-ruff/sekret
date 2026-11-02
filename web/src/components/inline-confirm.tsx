import { useId, useState, type ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

interface InlineConfirmProps {
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  /** Stays busy until this settles; the caller closes the prompt on success. */
  onConfirm: () => Promise<unknown>;
  onCancel: () => void;
  testId: string;
}

/**
 * A confirmation shown inside a sheet or dialog that is already open. A second modal on top of a
 * modal leaves two focus traps and two Escape handlers fighting, so the question sits in place.
 * The host closes it on Escape.
 */
export function InlineConfirm({ title, description, confirmLabel, destructive, onConfirm, onCancel, testId }: InlineConfirmProps) {
  const [busy, setBusy] = useState(false);
  const titleId = useId();
  const descriptionId = useId();

  const confirm = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await onConfirm();
    } catch {
      // The caller's mutation already reported the error.
    } finally {
      setBusy(false);
    }
  };

  return (
    <Alert role="alertdialog" aria-modal="false" aria-labelledby={titleId} aria-describedby={descriptionId} data-testid={testId}>
      <AlertTitle id={titleId}>{title}</AlertTitle>
      <AlertDescription>
        <p id={descriptionId}>{description}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" onClick={onCancel} disabled={busy} autoFocus data-testid="confirm-cancel">
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            variant={destructive ? "destructive" : "default"}
            onClick={() => void confirm()}
            disabled={busy}
            data-testid="confirm-action"
          >
            {busy && <Spinner />}
            {confirmLabel}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
}
