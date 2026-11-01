import { AlertTriangle, FileUp, FolderOpen, Info } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { toast } from "sonner";
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
import { duplicateText, parseDotenv } from "@/lib/dotenv";
import { folderLabel } from "@/lib/paths";

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

/** Larger than any sensible .env file, so a wrong file is not read into the page. */
const MAX_FILE_BYTES = 1024 * 1024;

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
  const fileInput = useRef<HTMLInputElement>(null);
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
      write.reset();
    },
  });
  // A failed import still holds the parsed values; drop them once the dialog closes, by any route.
  const { reset: resetWrite, isPending: writing } = write;
  useEffect(() => {
    if (!open && !writing) resetWrite();
  }, [open, writing, resetWrite]);

  const chooseFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      toast.error("That file is too large to be a .env file.");
      return;
    }
    setText(await file.text());
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl" data-testid="import-env-dialog">
        <DialogHeader>
          <DialogTitle>Import from .env</DialogTitle>
          <DialogDescription data-testid="import-env-where">
            Secrets are written to {envName}, in folder <span className="font-mono">{folderLabel(path)}</span>, as one
            change. Existing keys are updated.
          </DialogDescription>
        </DialogHeader>
        <div className="flex justify-end">
          <input
            ref={fileInput}
            type="file"
            accept=".env,text/plain"
            className="hidden"
            onChange={(event) => void chooseFile(event)}
            data-testid="import-env-file"
          />
          <Button type="button" variant="outline" size="sm" onClick={() => fileInput.current?.click()} data-testid="import-env-choose">
            <FolderOpen />
            Choose file…
          </Button>
        </div>
        <SecretTextarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={EXAMPLE}
          rows={10}
          aria-label=".env contents"
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
        {parsed.duplicates.length > 0 && (
          <div className="space-y-1 rounded-lg border bg-muted/40 p-3 text-sm" data-testid="import-env-duplicates">
            <div className="flex items-center gap-2 font-medium">
              <Info className="size-4 text-muted-foreground" />
              Some keys are set more than once
            </div>
            <ul className="space-y-0.5 text-muted-foreground">
              {parsed.duplicates.slice(0, 6).map((duplicate) => (
                <li key={duplicate.key}>{duplicateText(duplicate)}</li>
              ))}
            </ul>
          </div>
        )}
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
