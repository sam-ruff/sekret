import { useLayoutEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
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
import { focusInstead } from "@/lib/return-focus";

/** A select list or popover open within the dialog takes Escape for itself. */
function popupOpenInside(): boolean {
  return document.querySelector('[data-radix-popper-content-wrapper], [role="listbox"][data-state="open"]') !== null;
}

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
  // With no trigger, Radix has nowhere to return focus to, so it would land on the page body.
  const opener = useRef<HTMLElement | null>(null);
  const rememberOpener = () => {
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  };
  const returnFocus = (event: Event) => {
    if (onCloseAutoFocus) onCloseAutoFocus(event);
    else focusInstead(event, opener.current);
    opener.current = null;
  };

  // Radix shows an Escape to every open layer, so a sheet under this dialog would close with it.
  // Taking the key before Radix sees it closes only this dialog.
  // A layout effect, so the key is taken from the moment the dialog shows.
  useLayoutEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || popupOpenInside()) return;
      event.stopPropagation();
      event.preventDefault();
      if (!busy) onOpenChange(false);
    };
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [open, busy, onOpenChange]);

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
      <AlertDialogContent data-testid={testId} onOpenAutoFocus={rememberOpener} onCloseAutoFocus={returnFocus}>
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
