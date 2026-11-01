import { AlertTriangle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * Shown when a seal change answered `epoch_mark_stale`: the change itself is done, so this asks
 * for a repair on the host rather than a retry.
 */
export function EpochMarkStaleAlert({ change, testId }: { change: string; testId: string }) {
  return (
    <Alert className="border-warning/50 bg-warning/10" data-testid={testId}>
      <AlertTriangle className="text-warning" />
      <AlertTitle>{change} was saved, but the host needs a repair</AlertTitle>
      <AlertDescription>
        <p>
          sekret could not update its seal mark, a file kept outside the database. There is no need to try again. Ask
          whoever runs the server to check the server log, make that file writable, then stop the server and run{" "}
          <code className="font-mono">sekret admin reset-epoch</code> on the host.
        </p>
      </AlertDescription>
    </Alert>
  );
}
