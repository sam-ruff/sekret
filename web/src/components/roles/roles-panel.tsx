import { Eye, Lock, MoreHorizontal, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useRef, useState } from "react";
import type { PutRole, Role, Subject } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ResponsiveTable } from "@/components/responsive-table";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { upperFirst } from "@/lib/format";
import { focusInstead } from "@/lib/return-focus";
import { RoleEditor } from "./role-editor";

interface RolesPanelProps {
  roles: Role[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  subjects: readonly Subject[];
  environments?: string[];
  canCreate: boolean;
  canEdit: boolean;
  canDelete: boolean;
  onSave: (slug: string, body: PutRole) => Promise<unknown>;
  onDelete: (slug: string) => Promise<unknown>;
  /** What custom roles can do at this scope. */
  intro: string;
}

type EditorState = { mode: "new" } | { mode: "edit" | "view"; role: Role } | null;

export function RolesPanel({
  roles,
  loading,
  error,
  onRetry,
  subjects,
  environments,
  canCreate,
  canEdit,
  canDelete,
  onSave,
  onDelete,
  intro,
}: RolesPanelProps) {
  const [editor, setEditor] = useState<EditorState>(null);
  const [deleting, setDeleting] = useState<Role | null>(null);
  // Each row's menu button, so focus can go back to it once the editor opened from that menu closes.
  const triggers = useRef(new Map<string, HTMLElement>());
  const editorSlug = editor && editor.mode !== "new" ? editor.role.slug : undefined;

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted-foreground" data-testid="roles-intro">
          {intro}
        </p>
        {canCreate && (
          <Button onClick={() => setEditor({ mode: "new" })} data-testid="new-role">
            <Plus />
            New role
          </Button>
        )}
      </div>
      {error ? <ErrorState error={error} onRetry={onRetry} /> : null}
      {loading && <ListSkeleton rows={3} />}
      {roles && roles.length === 0 && <EmptyState icon={<ShieldCheck />} title="No roles" />}
      {roles && roles.length > 0 && (
        <ResponsiveTable
          rows={roles}
          rowKey={(r) => r.slug}
          rowTestId={(r) => `role-row-${r.slug}`}
          columns={[
            {
              header: "Role",
              primary: true,
              cell: (r) => (
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium first-letter:uppercase">{r.name}</span>
                    {r.builtin && (
                      <Badge variant="secondary">
                        <Lock /> Built-in
                      </Badge>
                    )}
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">{r.slug}</div>
                </div>
              ),
            },
            {
              header: "Description",
              long: true,
              cell: (r) => <span className="text-muted-foreground">{r.description || "No description"}</span>,
            },
            {
              header: "Rules",
              className: "md:w-20",
              cell: (r) => <Badge variant="outline">{r.rules.length}</Badge>,
            },
            {
              header: "",
              className: "md:w-12",
              actions: true,
              cell: (r) => (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      ref={(el) => {
                        if (el) triggers.current.set(r.slug, el);
                        else triggers.current.delete(r.slug);
                      }}
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Actions for ${upperFirst(r.name)}`}
                      data-testid={`role-actions-${r.slug}`}
                    >
                      <MoreHorizontal />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    {r.builtin || !canEdit ? (
                      <DropdownMenuItem onSelect={() => setEditor({ mode: "view", role: r })} data-testid="role-view">
                        <Eye />
                        View permissions
                      </DropdownMenuItem>
                    ) : (
                      <DropdownMenuItem onSelect={() => setEditor({ mode: "edit", role: r })} data-testid="role-edit">
                        <Pencil />
                        Edit
                      </DropdownMenuItem>
                    )}
                    {!r.builtin && canDelete && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(r)} data-testid="role-delete">
                          <Trash2 />
                          Delete
                        </DropdownMenuItem>
                      </>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              ),
            },
          ]}
        />
      )}
      {editor && (
        <RoleEditor
          key={editor.mode === "new" ? "new" : editor.role.slug}
          open
          onOpenChange={(open) => !open && setEditor(null)}
          role={editor.mode === "new" ? undefined : editor.role}
          readOnly={editor.mode === "view"}
          subjects={subjects}
          environments={environments}
          onSave={onSave}
          onCloseAutoFocus={(event) => focusInstead(event, triggers.current.get(editorSlug ?? ""))}
        />
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete the ${deleting?.name} role?`}
        description="Anyone holding only this role loses the access it granted."
        confirmLabel="Delete role"
        destructive
        onConfirm={() => onDelete(deleting?.slug ?? "")}
      />
    </div>
  );
}
