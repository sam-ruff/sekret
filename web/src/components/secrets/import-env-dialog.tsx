import { AlertTriangle, FileUp } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "@/api/endpoints";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Spinner } from "@/components/ui/spinner";
import { SecretTextarea } from "@/components/secret-field";
import { useApiMutation } from "@/hooks/queries";
import { parseDotenv } from "@/lib/dotenv";

interface ImportEnvDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  project: string;
  env: string;
  envName: string;
  path: string;
  existingKeys: string[];
  invalidate: readonly (readonly unknown[])[];
}

const EXAMPLE = `# Paste the contents of a .env file
DATABASE_URL=postgres://localhost/app
API_TOKEN="quoted values keep # characters"`;

export function ImportEnvDialog({
  open,
  onOpenChange,
  project,
  env,
  envName,
  path,
  existingKeys,
  invalidate,
}: ImportEnvDialogProps) {
  const [text, setText] = useState("");
  // Pasted values never outlive the dialog, however it was closed.
  if (!open && text !== "") setText("");
  const parsed = useMemo(() => parseDotenv(text), [text]);
  const existing = new Set(existingKeys);
  const updates = parsed.entries.filter((e) => existing.has(e.key)).length;

  const write = useApiMutation({
    mutationFn: () =>
      api.batchWrite(project, env, {
        path,
        upserts: parsed.entries.map((e) => ({ key: e.key, value: e.value, comment: "", tags: null })),
        deletes: [],
      }),
    invalidate: [...invalidate],
    success: (r) =>
      `Imported: ${r.created.length} added, ${r.updated.length} updated, ${r.unchanged.length} unchanged`,
    onSuccess: () => {
      setText("");
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl" data-testid="import-env-dialog">
        <DialogHeader>
          <DialogTitle>Import from .env</DialogTitle>
          <DialogDescription>
            Secrets are written to {envName} in <span className="font-mono">{path}</span> in one change. Existing keys
            are updated.
          </DialogDescription>
        </DialogHeader>
        <SecretTextarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={EXAMPLE}
          rows={10}
          className="max-h-[50vh] font-mono text-sm"
          data-testid="import-env-text"
        />
        <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="import-env-summary">
          <Badge variant="secondary">{parsed.entries.length} found</Badge>
          {parsed.entries.length > 0 && (
            <>
              <Badge variant="outline">{parsed.entries.length - updates} new</Badge>
              <Badge variant="outline">{updates} existing</Badge>
            </>
          )}
        </div>
        {parsed.issues.length > 0 && (
          <div className="space-y-1 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm" data-testid="import-env-issues">
            <div className="flex items-center gap-2 font-medium">
              <AlertTriangle className="size-4 text-warning" />
              Some lines will be skipped
            </div>
            <ul className="space-y-0.5 text-muted-foreground">
              {parsed.issues.slice(0, 6).map((issue) => (
                <li key={issue.line}>
                  Line {issue.line}: {issue.message}
                </li>
              ))}
            </ul>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => write.mutate()}
            disabled={parsed.entries.length === 0 || write.isPending}
            data-testid="import-env-submit"
          >
            {write.isPending ? <Spinner /> : <FileUp />}
            Import {parsed.entries.length > 0 ? parsed.entries.length : ""}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
