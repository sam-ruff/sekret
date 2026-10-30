import { FolderKey, ImageUp, Trash2, TriangleAlert } from "lucide-react";
import { useRef, useState, type ChangeEvent } from "react";
import { api } from "@/api/endpoints";
import type { Project } from "@/api/types";
import { ProjectLogo } from "@/components/project-logo";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation } from "@/hooks/queries";
import { errorMessage } from "@/lib/errors";
import { checkLogoFile } from "@/lib/images";

const ACCEPT = "image/png,image/jpeg,image/gif,image/webp,image/svg+xml,.png,.jpg,.jpeg,.gif,.webp,.svg";

export function LogoCard({ project, canEdit }: { project: Project; canEdit: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [problem, setProblem] = useState<string>();
  const invalidate = [keys.projects, keys.project(project.slug)];
  const onError = (error: unknown) => {
    setProblem(errorMessage(error));
    return true;
  };

  const upload = useApiMutation({
    mutationFn: (file: File) => api.putLogo(project.slug, file),
    invalidate,
    success: "Logo updated",
    onError,
  });
  const remove = useApiMutation({
    mutationFn: () => api.deleteLogo(project.slug),
    invalidate,
    success: "Logo removed",
    onError,
  });

  const choose = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setProblem(undefined);
    const check = checkLogoFile(new Uint8Array(await file.arrayBuffer()));
    if (!check.ok) {
      setProblem(check.message);
      return;
    }
    upload.mutate(file);
  };

  const busy = upload.isPending || remove.isPending;
  const hasLogo = !!project.logo_url;

  return (
    <Card className="max-w-3xl" data-testid="logo-card">
      <CardHeader>
        <CardTitle>Logo</CardTitle>
        <CardDescription>Shown on the project card, in the project switcher and in the page header.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
          <div className="flex size-20 shrink-0 items-center justify-center overflow-hidden rounded-xl border bg-muted/40" data-testid="logo-preview">
            <ProjectLogo
              url={project.logo_url}
              className="size-full object-contain p-2"
              testId="logo-preview-image"
              fallback={<FolderKey className="size-7 text-muted-foreground" data-testid="logo-preview-empty" />}
            />
          </div>
          <div className="min-w-0 space-y-2">
            <p className="text-sm text-muted-foreground">
              PNG, JPEG, GIF, WebP or SVG, up to 512 KiB and 4096 by 4096 pixels. A square image works best.
            </p>
            {canEdit && (
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" disabled={busy} onClick={() => input.current?.click()} data-testid="logo-upload">
                  {upload.isPending ? <Spinner /> : <ImageUp />}
                  {hasLogo ? "Replace" : "Upload logo"}
                </Button>
                {hasLogo && (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      setProblem(undefined);
                      remove.mutate();
                    }}
                    data-testid="logo-remove"
                  >
                    {remove.isPending ? <Spinner /> : <Trash2 />}
                    Remove
                  </Button>
                )}
              </div>
            )}
            <input
              ref={input}
              type="file"
              accept={ACCEPT}
              className="sr-only"
              tabIndex={-1}
              aria-hidden
              onChange={(e) => void choose(e)}
              data-testid="logo-input"
            />
          </div>
        </div>
        {problem && (
          <Alert variant="destructive" data-testid="logo-error">
            <TriangleAlert />
            <AlertDescription>{problem}</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}
