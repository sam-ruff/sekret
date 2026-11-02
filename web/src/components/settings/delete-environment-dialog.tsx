import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "@/api/endpoints";
import type { Environment } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Input } from "@/components/ui/input";
import { keys } from "@/hooks/queries";
import { environmentDeleteText } from "@/lib/environment-delete";

interface DeleteEnvironmentDialogProps {
  project: string;
  /** The environment to delete, or null when the dialog is closed. */
  env: Environment | null;
  onClose: () => void;
  onDelete: (env: Environment) => Promise<unknown>;
}

/**
 * Checks the environment is empty first, since the server refuses otherwise, then asks for its ID
 * to be typed: deleting it wipes the history and snapshots left behind, as final as deleting a project.
 */
export function DeleteEnvironmentDialog({ project, env, onClose, onDelete }: DeleteEnvironmentDialogProps) {
  const [typed, setTyped] = useState("");
  const slug = env?.slug ?? "";
  const contents = useQuery({
    queryKey: [...keys.secrets(project, slug, "/"), "recursive"],
    queryFn: () => api.secretsUnder({ project, env: slug, path: "/" }),
    enabled: env !== null,
    staleTime: 0,
  });
  const { blocked, text } = environmentDeleteText(contents.data?.secrets.length, contents.isError);

  return (
    <ConfirmDialog
      open={env !== null}
      onOpenChange={(open) => {
        if (open) return;
        setTyped("");
        onClose();
      }}
      title={blocked ? `${env?.name} is not empty` : `Delete ${env?.name}?`}
      description={
        <>
          <span data-testid="delete-env-contents">{text}</span>
          {blocked && (
            <>
              {" "}
              <Link to={`/projects/${project}/secrets/${slug}`} onClick={onClose} data-testid="delete-env-open">
                Open its secrets
              </Link>
            </>
          )}
          {!blocked && !contents.isPending && (
            <>
              {" "}
              Type <span className="font-mono font-semibold">{slug}</span> to confirm.
            </>
          )}
        </>
      }
      confirmLabel="Delete environment"
      destructive
      blocked={blocked}
      confirmDisabled={contents.isPending || typed !== slug || slug === ""}
      onConfirm={async () => {
        if (env) await onDelete(env);
      }}
      testId="delete-env-confirm"
    >
      {!blocked && !contents.isPending && (
        <Input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          className="font-mono"
          aria-label="Environment ID to confirm deletion"
          autoComplete="off"
          spellCheck={false}
          data-testid="delete-env-slug"
        />
      )}
    </ConfirmDialog>
  );
}
