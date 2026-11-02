import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "@/api/endpoints";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { keys } from "@/hooks/queries";
import { folderQuery } from "@/hooks/use-project-env";
import { folderLabel } from "@/lib/paths";

interface DeleteFolderDialogProps {
  project: string;
  env: string;
  /** The folder to delete, or null when the dialog is closed. */
  folder: string | null;
  onClose: () => void;
  onDelete: (folder: string) => Promise<unknown>;
}

function contentsText(count: number | undefined, failed: boolean): string {
  if (failed) return "sekret could not check what is inside. Only empty folders can be deleted.";
  if (count === undefined) return "Checking what is inside...";
  if (count === 0) return "The folder holds no secrets, so it and any empty folders inside it can be deleted.";
  const secrets = count === 1 ? "1 secret" : `${count} secrets`;
  return `It still holds ${secrets}, counting the folders inside it. Only empty folders can be deleted, so delete those secrets first.`;
}

/** Checks a folder's contents first, so a folder that cannot be deleted is never offered for deletion. */
export function DeleteFolderDialog({ project, env, folder, onClose, onDelete }: DeleteFolderDialogProps) {
  const path = folder ?? "/";
  const contents = useQuery({
    queryKey: [...keys.secrets(project, env, path), "recursive"],
    queryFn: () => api.secretsUnder({ project, env, path }),
    enabled: folder !== null,
    staleTime: 0,
  });
  const count = contents.data?.secrets.length;
  const blocked = count !== undefined && count > 0;

  return (
    <ConfirmDialog
      open={folder !== null}
      onOpenChange={(open) => !open && onClose()}
      title={blocked ? `${folderLabel(path)} is not empty` : `Delete folder ${folderLabel(path)}?`}
      description={
        <>
          <span data-testid="delete-folder-contents">{contentsText(count, contents.isError)}</span>
          {blocked && (
            <>
              {" "}
              <Link
                to={`/projects/${project}/secrets/${env}${folderQuery(path)}`}
                onClick={onClose}
                data-testid="delete-folder-open"
              >
                Open {folderLabel(path)}
              </Link>
            </>
          )}
        </>
      }
      confirmLabel="Delete folder"
      destructive
      blocked={blocked}
      confirmDisabled={contents.isPending}
      onConfirm={() => onDelete(path)}
      testId="delete-folder-dialog"
    />
  );
}
