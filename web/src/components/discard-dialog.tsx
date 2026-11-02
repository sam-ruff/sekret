import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import type { DiscardPrompt } from "@/hooks/use-discard-guard";

/**
 * The same question shown inside a dialog that is already open. A second modal on top of a
 * modal leaves two focus traps fighting, so the prompt sits in the dialog instead.
 */
export function DiscardInline({ open, onKeep, onDiscard }: DiscardPrompt) {
  if (!open) return null;
  return (
    <Alert role="alertdialog" aria-modal="false" className="border-destructive/50" data-testid="discard-dialog">
      <AlertTitle>Discard changes?</AlertTitle>
      <AlertDescription>
        <p>What you entered here has not been saved.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" onClick={onKeep} autoFocus data-testid="discard-keep">
            Keep editing
          </Button>
          <Button type="button" variant="destructive" size="sm" onClick={onDiscard} data-testid="discard-confirm">
            Discard
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
}

/** "Discard changes?", shown by `useDiscardGuard` when a form with unsaved input is about to close. */
export function DiscardDialog({ open, onKeep, onDiscard }: DiscardPrompt) {
  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onKeep()}>
      <AlertDialogContent data-testid="discard-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle>Discard changes?</AlertDialogTitle>
          <AlertDialogDescription>What you entered here has not been saved.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel data-testid="discard-keep">Keep editing</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={onDiscard} data-testid="discard-confirm">
            Discard
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
