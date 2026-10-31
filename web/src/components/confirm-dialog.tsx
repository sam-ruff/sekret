import { useState, type FormEvent, type ReactNode } from "react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  /** Fields inside the dialog; pressing Enter in one confirms, as the confirm button is the form's submit. */
  children?: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  confirmDisabled?: boolean;
  /** The action cannot go ahead, so only a Close button is shown. */
  blocked?: boolean;
  /** The dialog stays open with a spinner until this settles, and closes only on success. */
  onConfirm: () => Promise<unknown>;
  /** Where focus goes on close, for dialogs opened from a menu. */
  onCloseAutoFocus?: (event: Event) => void;
  testId?: string;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel,
  destructive,
  confirmDisabled,
  blocked,
  onConfirm,
  onCloseAutoFocus,
  testId = "confirm-dialog",
}: ConfirmDialogProps) {
  const [busy, setBusy] = useState(false);

  const confirm = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || confirmDisabled || blocked) return;
    setBusy(true);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch {
      // The caller's mutation already reported the error.
    } finally {
      setBusy(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <AlertDialogContent data-testid={testId} onCloseAutoFocus={onCloseAutoFocus}>
        <form onSubmit={(event) => void confirm(event)} noValidate className="grid gap-4">
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            {description && <AlertDialogDescription>{description}</AlertDialogDescription>}
          </AlertDialogHeader>
          {children}
          <AlertDialogFooter>
            <AlertDialogCancel type="button" disabled={busy} data-testid="confirm-cancel">
              {blocked ? "Close" : "Cancel"}
            </AlertDialogCancel>
            {!blocked && (
              <Button
                type="submit"
                variant={destructive ? "destructive" : "default"}
                disabled={busy || confirmDisabled}
                data-testid="confirm-action"
              >
                {busy && <Spinner />}
                {confirmLabel}
              </Button>
            )}
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
