import { Info, Sparkles } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { Charset } from "@/api/types";
import { ListInput } from "@/components/list-input";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { isValidSecretKey } from "@/lib/dotenv";
import { slugify } from "@/lib/format";
import { DEFAULT_DRAFT, describeGenerator, generatorFromDraft, lengthProblem } from "@/lib/generation";
import { GeneratorFields } from "./generator-fields";

export interface SecretDraft {
  key: string;
  value: string;
  comment: string;
  tags: string[];
  /** Set when sekret should generate the value instead of saving the typed one. */
  generator?: { length: string; charset: Charset };
}

interface SecretEditorProps {
  initial: SecretDraft;
  /** New secrets get an editable key; existing ones keep theirs. */
  isNew: boolean;
  valueHidden?: boolean;
  /** The current value was generated, so typing a new one stops automatic rotation. */
  generated?: boolean;
  canGenerate?: boolean;
  busy: boolean;
  onSave: (draft: SecretDraft) => void;
  onCancel: () => void;
}

export function SecretEditor({ initial, isNew, valueHidden, generated, canGenerate = true, busy, onSave, onCancel }: SecretEditorProps) {
  const [draft, setDraft] = useState<SecretDraft>(initial);
  const keyProblem = draft.key && !isValidSecretKey(draft.key)
    ? "Start with a letter or underscore, then letters, digits, '_', '-' or '.'"
    : undefined;
  const generatorProblem = draft.generator ? lengthProblem(draft.generator.length) : undefined;
  const id = isNew ? "new" : initial.key;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!draft.key || keyProblem || generatorProblem) return;
    onSave(draft);
  };

  const startGenerating = () =>
    setDraft({ ...draft, tags: initial.tags, generator: { length: DEFAULT_DRAFT.length, charset: DEFAULT_DRAFT.charset } });

  return (
    <form
      onSubmit={submit}
      className="space-y-4 rounded-xl border border-primary/30 bg-card p-4 shadow-sm"
      data-testid={isNew ? "new-secret-form" : `edit-secret-${initial.key}`}
    >
      <FieldGroup className="gap-4">
        <div className="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <Field>
            <FieldLabel htmlFor={`key-${id}`}>Key</FieldLabel>
            <Input
              id={`key-${id}`}
              value={draft.key}
              disabled={!isNew}
              autoFocus={isNew}
              aria-invalid={!!keyProblem}
              className="font-mono"
              placeholder="DATABASE_URL"
              data-testid="secret-key-input"
              onChange={(e) => setDraft({ ...draft, key: e.target.value.trim() })}
            />
            {keyProblem && <p className="text-xs text-destructive">{keyProblem}</p>}
          </Field>
          <Field>
            <div className="flex items-center justify-between gap-2">
              <FieldLabel htmlFor={`value-${id}`}>Value</FieldLabel>
              {canGenerate &&
                (draft.generator ? (
                  <Button
                    type="button"
                    variant="link"
                    size="xs"
                    className="h-auto px-0"
                    onClick={() => setDraft({ ...draft, generator: undefined })}
                    data-testid="secret-type-value"
                  >
                    Type a value instead
                  </Button>
                ) : (
                  <Button type="button" variant="outline" size="xs" onClick={startGenerating} data-testid="secret-generate">
                    <Sparkles />
                    Generate
                  </Button>
                ))}
            </div>
            {draft.generator ? (
              <div className="space-y-3 rounded-lg border border-dashed bg-muted/30 p-3" data-testid="secret-generator">
                <p className="text-sm text-muted-foreground">
                  sekret generates{" "}
                  <span className="font-medium text-foreground" data-testid="secret-generator-summary">
                    {generatorProblem ? "a value" : describeGenerator(generatorFromDraft(draft.generator))}
                  </span>{" "}
                  when you save. You can reveal it afterwards.
                </p>
                <GeneratorFields
                  idPrefix={`generate-${id}`}
                  length={draft.generator.length}
                  charset={draft.generator.charset}
                  onChange={(generator) => setDraft({ ...draft, generator })}
                />
              </div>
            ) : (
              <Textarea
                id={`value-${id}`}
                value={draft.value}
                autoFocus={!isNew}
                rows={Math.min(8, Math.max(1, draft.value.split("\n").length))}
                className="min-h-8 font-mono text-sm"
                placeholder={valueHidden ? "You cannot read the current value; enter a replacement" : "Value"}
                data-testid="secret-value-input"
                onChange={(e) => setDraft({ ...draft, value: e.target.value })}
              />
            )}
            {generated && !draft.generator && (
              <FieldDescription className="flex items-start gap-1.5 text-xs" data-testid="secret-generated-warning">
                <Info className="mt-0.5 size-3.5 shrink-0" />
                The current value was generated by sekret. Saving here writes a value sekret did not generate, so automatic
                rotation stops until you generate again.
              </FieldDescription>
            )}
          </Field>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor={`comment-${id}`}>Comment</FieldLabel>
            <Input
              id={`comment-${id}`}
              value={draft.comment}
              placeholder="What this is for"
              data-testid="secret-comment-input"
              onChange={(e) => setDraft({ ...draft, comment: e.target.value })}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor={`tags-${id}`}>Tags</FieldLabel>
            {draft.generator ? (
              <p className="flex min-h-8 items-center text-xs text-muted-foreground" data-testid="secret-tags-locked">
                {isNew ? "Generated secrets start without tags." : "Tags stay as they are when generating."}
              </p>
            ) : (
              <ListInput
                id={`tags-${id}`}
                value={draft.tags}
                onChange={(tags) => setDraft({ ...draft, tags })}
                normalise={slugify}
                placeholder="Type a tag and press Enter"
                testId="secret-tags"
              />
            )}
          </Field>
        </div>
      </FieldGroup>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button type="submit" disabled={busy || !draft.key || !!keyProblem || !!generatorProblem} data-testid="secret-save">
          {busy && <Spinner />}
          {draft.generator ? (isNew ? "Generate secret" : "Generate new value") : isNew ? "Add secret" : "Save"}
        </Button>
      </div>
    </form>
  );
}
