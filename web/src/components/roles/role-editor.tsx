import { Ban, Check, ChevronDown, Filter, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { PutRole, Role, Subject } from "@/api/types";
import { ACTIONS } from "@/api/types";
import { ListInput } from "@/components/list-input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DiscardInline } from "@/components/discard-dialog";
import { FormBlocker } from "@/components/form-blocker";
import { useDiscardGuard } from "@/hooks/use-discard-guard";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { isEscalation, errorMessage } from "@/lib/errors";
import { slugify } from "@/lib/format";
import { keyPatternCanMatch, pathPatternCanMatch } from "@/lib/glob";
import { cn } from "@/lib/utils";
import {
  ACTION_LABELS,
  SUBJECT_HINTS,
  SUBJECT_LABELS,
  actionsFor,
  blankRule,
  describeConditions,
  hasConditions,
  onlyDenies,
  toEditable,
  toRules,
  type EditableRule,
} from "./rule-model";

interface RoleEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Undefined when creating a role. */
  role?: Role;
  subjects: readonly Subject[];
  /** Environment slugs offered in the conditions builder; omit to hide conditions. */
  environments?: string[];
  readOnly?: boolean;
  onSave: (slug: string, body: PutRole) => Promise<unknown>;
  onCloseAutoFocus?: (event: Event) => void;
}

function ConditionsBuilder({
  rule,
  environments,
  onChange,
  readOnly,
}: {
  rule: EditableRule;
  environments: string[];
  onChange: (patch: Partial<EditableRule>) => void;
  readOnly?: boolean;
}) {
  const toggleEnv = (slug: string, on: boolean) =>
    onChange({ environments: on ? [...rule.environments, slug] : rule.environments.filter((e) => e !== slug) });

  return (
    <div className="grid gap-4 rounded-lg border bg-muted/30 p-3 md:grid-cols-2" data-testid={`conditions-${rule.subject}`}>
      <div className="space-y-2 md:col-span-2">
        <Label className="text-xs text-muted-foreground">Environments</Label>
        <div className="flex flex-wrap gap-3">
          {environments.map((slug) => (
            <label key={slug} className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={rule.environments.includes(slug)}
                disabled={readOnly}
                aria-label={`${SUBJECT_LABELS[rule.subject]} only in ${slug}`}
                onCheckedChange={(on) => toggleEnv(slug, on === true)}
                data-testid={`condition-env-${rule.subject}-${slug}`}
              />
              <span className="font-mono">{slug}</span>
            </label>
          ))}
          {environments.length === 0 && <span className="text-sm text-muted-foreground">No environments</span>}
        </div>
      </div>
      <div className="space-y-1.5">
        <Label className="text-xs text-muted-foreground">Folder paths</Label>
        <ListInput
          value={rule.paths}
          onChange={(paths) => onChange({ paths })}
          placeholder="e.g. /app/**"
          mono
          disabled={readOnly}
          validate={(p) =>
            pathPatternCanMatch(p)
              ? undefined
              : "This can never match: folders look like /payments or /payments/**, starting with / and without a trailing /"
          }
          testId={`condition-paths-${rule.subject}`}
        />
      </div>
      <div className="space-y-1.5">
        <Label className="text-xs text-muted-foreground">Secret keys</Label>
        <ListInput
          value={rule.keys}
          onChange={(keys) => onChange({ keys })}
          placeholder="e.g. DB_*"
          mono
          disabled={readOnly}
          validate={(k) =>
            keyPatternCanMatch(k)
              ? undefined
              : "This can never match: keys start with a letter or _ and hold only letters, digits, _, - and ."
          }
          testId={`condition-keys-${rule.subject}`}
        />
      </div>
      <div className="space-y-1.5 md:col-span-2">
        <Label className="text-xs text-muted-foreground">Tags (any of)</Label>
        <ListInput
          value={rule.tags}
          onChange={(tags) => onChange({ tags })}
          normalise={slugify}
          placeholder="e.g. database"
          disabled={readOnly}
          testId={`condition-tags-${rule.subject}`}
        />
      </div>
      <p className="text-xs text-muted-foreground md:col-span-2">
        In paths, <code>*</code> stays within one folder and <code>**</code> also matches sub-folders, so{" "}
        <code>/app/**</code> covers <code>/app</code> and everything below it. In keys,{" "}
        <code>*</code> matches anything. Empty lists mean anywhere.
      </p>
    </div>
  );
}

function RuleRow({
  rule,
  extra,
  environments,
  onChange,
  onRemove,
  readOnly,
}: {
  rule: EditableRule;
  extra: boolean;
  environments?: string[];
  onChange: (patch: Partial<EditableRule>) => void;
  onRemove?: () => void;
  readOnly?: boolean;
}) {
  const [showConditions, setShowConditions] = useState(hasConditions(rule));
  const testBase = `rule-${rule.subject}${extra ? "-extra" : ""}`;

  return (
    <div
      className={cn("space-y-3 border-b p-3 last:border-b-0 md:px-4", rule.effect === "deny" && "bg-destructive/5")}
      data-testid={testBase}
    >
      <div className="grid gap-3 md:grid-cols-[12rem_9rem_minmax(0,1fr)_auto] md:items-center">
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{SUBJECT_LABELS[rule.subject]}</div>
          {extra && <div className="text-xs text-muted-foreground">Additional rule</div>}
        </div>
        <ToggleGroup
          type="single"
          size="sm"
          variant="outline"
          spacing={0}
          value={rule.effect}
          disabled={readOnly}
          onValueChange={(value) => value && onChange({ effect: value as EditableRule["effect"] })}
          aria-label={`Allow or deny ${SUBJECT_LABELS[rule.subject]}`}
          data-testid={`${testBase}-effect`}
        >
          <ToggleGroupItem value="allow" className="px-2.5 text-xs" data-testid={`${testBase}-allow`}>
            {rule.effect === "allow" && <Check />}
            Allow
          </ToggleGroupItem>
          <ToggleGroupItem
            value="deny"
            className="px-2.5 text-xs data-[state=on]:border-destructive/60 data-[state=on]:bg-destructive/15 data-[state=on]:text-destructive data-[state=on]:hover:bg-destructive/20"
            data-testid={`${testBase}-deny`}
          >
            {rule.effect === "deny" && <Ban />}
            Deny
          </ToggleGroupItem>
        </ToggleGroup>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {actionsFor(rule).map((action) => (
            <label key={action} className="flex min-h-9 items-center gap-2 text-sm sm:min-h-0 sm:gap-1.5">
              <Checkbox
                checked={rule.actions.includes(action)}
                disabled={readOnly}
                aria-label={`${SUBJECT_LABELS[rule.subject]}${extra ? " (additional rule)" : ""}: ${ACTION_LABELS[action]}`}
                onCheckedChange={(on) =>
                  onChange({
                    actions: on === true ? ACTIONS.filter((a) => a === action || rule.actions.includes(a)) : rule.actions.filter((a) => a !== action),
                  })
                }
                data-testid={`${testBase}-${action}`}
              />
              {ACTION_LABELS[action]}
            </label>
          ))}
        </div>
        <div className="flex items-center gap-1 justify-self-end">
          {environments && (
            <Button
              type="button"
              variant={hasConditions(rule) ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setShowConditions(!showConditions)}
              data-testid={`${testBase}-conditions-toggle`}
            >
              <Filter />
              Conditions
              <ChevronDown className={cn("transition-transform", showConditions && "rotate-180")} />
            </Button>
          )}
          {onRemove && !readOnly && (
            <Button type="button" variant="ghost" size="icon-sm" onClick={onRemove} aria-label="Remove rule">
              <Trash2 />
            </Button>
          )}
        </div>
      </div>
      {SUBJECT_HINTS[rule.subject] && !extra && (
        <p className="text-xs text-muted-foreground" data-testid={`${testBase}-hint`}>
          {SUBJECT_HINTS[rule.subject]}
        </p>
      )}
      {hasConditions(rule) && !showConditions && (
        <p className="text-xs text-muted-foreground">Only {describeConditions(rule)}</p>
      )}
      {environments && showConditions && (
        <ConditionsBuilder rule={rule} environments={environments} onChange={onChange} readOnly={readOnly} />
      )}
    </div>
  );
}

/** The editable parts of the form, compared to tell whether anything is unsaved. */
function formSnapshot(name: string, slug: string, description: string, rows: EditableRule[]): string {
  return JSON.stringify({ name, slug, description, rules: toRules(rows) });
}

export function RoleEditor({
  open,
  onOpenChange,
  role,
  subjects,
  environments,
  readOnly,
  onSave,
  onCloseAutoFocus,
}: RoleEditorProps) {
  const isNew = !role;
  const [name, setName] = useState(role?.name ?? "");
  const [slug, setSlug] = useState(role?.slug ?? "");
  const [slugEdited, setSlugEdited] = useState(!!role);
  const [description, setDescription] = useState(role?.description ?? "");
  const [rows, setRows] = useState<EditableRule[]>(() => toEditable(role?.rules ?? [], subjects));
  const [problem, setProblem] = useState<{ escalation: boolean; message: string }>();
  const [busy, setBusy] = useState(false);
  const [initialForm] = useState(() => formSnapshot(name, slug, description, rows));
  const discard = useDiscardGuard(!readOnly && formSnapshot(name, slug, description, rows) !== initialForm);

  const update = (id: string, patch: Partial<EditableRule>) => {
    setProblem(undefined);
    setRows((current) => current.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  };

  const addRule = (subject: Subject) =>
    setRows((current) => {
      const lastIndex = current.map((r) => r.subject).lastIndexOf(subject);
      const next = [...current];
      next.splice(lastIndex + 1, 0, blankRule(subject, "deny"));
      return next;
    });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      await onSave(slug, { name: name.trim(), description, rules: toRules(rows) });
      onOpenChange(false);
    } catch (error) {
      setProblem({ escalation: isEscalation(error), message: errorMessage(error) });
    } finally {
      setBusy(false);
    }
  };

  const firstOfSubject = new Set<string>();
  const rules = toRules(rows);
  const grantCount = rules.length;
  const blocker = !name.trim() ? "Give the role a name to save it." : !slug ? "Give the role an ID to save it." : null;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (busy) return;
        if (next) onOpenChange(true);
        else discard.guard(() => onOpenChange(false));
      }}
    >
      <DialogContent
        className="max-h-[92svh] gap-0 overflow-hidden p-0 sm:max-w-5xl"
        onCloseAutoFocus={onCloseAutoFocus}
        data-testid="role-editor"
      >
        <form onSubmit={submit} className="flex max-h-[92svh] flex-col">
          <DialogHeader className="border-b p-4 sm:p-6">
            <DialogTitle>{readOnly ? role?.name : isNew ? "New role" : `Edit ${role?.name}`}</DialogTitle>
            <DialogDescription>
              {readOnly
                ? "Built-in roles cannot be changed. Copy what you need into a custom role."
                : "Tick what the role may do. Deny rules always win over allow rules."}
            </DialogDescription>
          </DialogHeader>
          {discard.prompt.open && (
            <div className="border-b p-4 sm:px-6">
              <DiscardInline {...discard.prompt} />
            </div>
          )}
          {/* Relative, so the checkboxes' hidden inputs stay inside the scrolling area rather than stretching the dialog. */}
          <div className="relative min-h-0 flex-1 space-y-6 overflow-y-auto p-4 sm:p-6">
            {!readOnly && (
              <div className="grid gap-4 md:grid-cols-3">
                <Field>
                  <FieldLabel htmlFor="role-name">Name</FieldLabel>
                  <Input
                    id="role-name"
                    value={name}
                    data-testid="role-name"
                    onChange={(e) => {
                      setName(e.target.value);
                      if (!slugEdited) setSlug(slugify(e.target.value));
                    }}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="role-slug">ID</FieldLabel>
                  <Input
                    id="role-slug"
                    value={slug}
                    disabled={!isNew}
                    className="font-mono"
                    data-testid="role-slug"
                    onChange={(e) => {
                      setSlugEdited(true);
                      setSlug(e.target.value.toLowerCase());
                    }}
                  />
                  <FieldDescription>Used by the CLI and API. It cannot change later.</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="role-description">Description</FieldLabel>
                  <Input id="role-description" value={description} onChange={(e) => setDescription(e.target.value)} />
                </Field>
              </div>
            )}

            {problem && (
              <Alert variant="destructive" data-testid={problem.escalation ? "role-escalation" : "role-error"}>
                <ShieldAlert />
                <AlertTitle>{problem.escalation ? "This role would grant more than you have" : "The role was not saved"}</AlertTitle>
                <AlertDescription>
                  <p>{problem.message}.</p>
                  {problem.escalation && (
                    <p>
                      You can only hand out access you hold yourself, without conditions or with exactly the same ones.
                      Untick the extra permissions or ask an administrator to create this role.
                    </p>
                  )}
                </AlertDescription>
              </Alert>
            )}

            {onlyDenies(rules) && (
              <Alert data-testid="role-deny-only">
                <Ban />
                <AlertDescription>
                  This role only takes access away. On its own it grants nothing, so give it alongside a role that allows
                  access.
                </AlertDescription>
              </Alert>
            )}

            <div className="overflow-hidden rounded-xl border" data-testid="permission-matrix">
              <div className="hidden grid-cols-[12rem_9rem_minmax(0,1fr)_auto] gap-3 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground md:grid">
                <span>Subject</span>
                <span>Effect</span>
                <span>Actions</span>
                <span />
              </div>
              {rows.map((rule) => {
                const extra = firstOfSubject.has(rule.subject);
                firstOfSubject.add(rule.subject);
                return (
                  <div key={rule.id}>
                    <RuleRow
                      rule={rule}
                      extra={extra}
                      environments={environments}
                      readOnly={readOnly}
                      onChange={(patch) => update(rule.id, patch)}
                      onRemove={extra ? () => setRows((current) => current.filter((r) => r.id !== rule.id)) : undefined}
                    />
                  </div>
                );
              })}
            </div>
            {!readOnly && (
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                <span>Need an exception, such as allow everywhere but deny production?</span>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button type="button" variant="outline" size="sm" data-testid="add-rule">
                      <Plus />
                      Add rule
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent
                    align="start"
                    collisionPadding={16}
                    className="w-56 max-h-[min(var(--radix-dropdown-menu-content-available-height),20rem)]"
                    data-testid="add-rule-menu"
                  >
                    {subjects.map((s) => (
                      <DropdownMenuItem key={s} onSelect={() => addRule(s)} data-testid={`add-rule-${s}`}>
                        {SUBJECT_LABELS[s]}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            )}
          </div>
          {/* One row on phones too, so the rules keep as much of the screen as possible. */}
          <DialogFooter className="m-0 flex-row flex-wrap justify-end border-t p-3 sm:items-center sm:p-4">
            <span className="mr-auto hidden text-sm text-muted-foreground sm:order-first sm:inline">
              <Badge variant="secondary">{grantCount}</Badge> {grantCount === 1 ? "rule" : "rules"}
            </span>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
              {readOnly ? "Close" : "Cancel"}
            </Button>
            {/* Under the buttons on phones, beside the rule count on wider screens. */}
            {!readOnly && blocker && (
              <FormBlocker id="role-blocker" testId="role-blocker" className="order-last w-full text-right sm:order-first sm:w-auto sm:text-left">
                {blocker}
              </FormBlocker>
            )}
            {!readOnly && (
              <Button
                type="submit"
                disabled={busy || !!blocker}
                aria-describedby={blocker ? "role-blocker" : undefined}
                data-testid="role-save"
              >
                {busy && <Spinner />}
                Save role
              </Button>
            )}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
