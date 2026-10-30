import type { Charset } from "@/api/types";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { CHARSETS, daysProblem, lengthProblem, MAX_LENGTH, MAX_ROTATION_DAYS, MIN_LENGTH } from "@/lib/generation";

interface GeneratorFieldsProps {
  length: string;
  charset: Charset;
  onChange: (next: { length: string; charset: Charset }) => void;
  idPrefix: string;
  disabled?: boolean;
}

export function GeneratorFields({ length, charset, onChange, idPrefix, disabled }: GeneratorFieldsProps) {
  const problem = lengthProblem(length);
  return (
    <div className="grid grid-cols-[6rem_minmax(0,1fr)] gap-3">
      <Field className="gap-1.5">
        <FieldLabel htmlFor={`${idPrefix}-length`} className="text-xs">
          Length
        </FieldLabel>
        <Input
          id={`${idPrefix}-length`}
          type="number"
          inputMode="numeric"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={length}
          disabled={disabled}
          aria-invalid={!!problem}
          onChange={(e) => onChange({ length: e.target.value, charset })}
          data-testid={`${idPrefix}-length`}
        />
      </Field>
      <Field className="gap-1.5">
        <FieldLabel htmlFor={`${idPrefix}-charset`} className="text-xs">
          Characters
        </FieldLabel>
        <Select value={charset} disabled={disabled} onValueChange={(v) => onChange({ length, charset: v as Charset })}>
          <SelectTrigger id={`${idPrefix}-charset`} className="w-full" data-testid={`${idPrefix}-charset`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {CHARSETS.map((c) => (
              <SelectItem key={c.value} value={c.value} data-testid={`${idPrefix}-charset-${c.value}`}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      {problem ? (
        <FieldError className="col-span-2">{problem}</FieldError>
      ) : (
        <FieldDescription className="col-span-2 font-mono text-xs">
          {CHARSETS.find((c) => c.value === charset)?.hint}
        </FieldDescription>
      )}
    </div>
  );
}

interface RotationFieldProps {
  rotate: boolean;
  days: string;
  onChange: (next: { rotate: boolean; days: string }) => void;
  idPrefix: string;
  disabled?: boolean;
  hint?: string;
}

export function RotationField({ rotate, days, onChange, idPrefix, disabled, hint }: RotationFieldProps) {
  const problem = rotate ? daysProblem(days) : undefined;
  return (
    <div className="space-y-2">
      <Field orientation="horizontal">
        <Switch
          id={`${idPrefix}-rotate`}
          checked={rotate}
          disabled={disabled}
          onCheckedChange={(checked) => onChange({ rotate: checked, days })}
          data-testid={`${idPrefix}-rotate`}
        />
        <FieldLabel htmlFor={`${idPrefix}-rotate`} className="font-normal">
          Rotate automatically
        </FieldLabel>
      </Field>
      {rotate && (
        <div className="flex items-center gap-2 pl-1 text-sm">
          <span className="text-muted-foreground">Every</span>
          <Input
            aria-label="Days between rotations"
            type="number"
            inputMode="numeric"
            min={1}
            max={MAX_ROTATION_DAYS}
            value={days}
            disabled={disabled}
            aria-invalid={!!problem}
            className="w-20"
            onChange={(e) => onChange({ rotate, days: e.target.value })}
            data-testid={`${idPrefix}-days`}
          />
          <span className="text-muted-foreground">days</span>
        </div>
      )}
      {problem && <FieldError>{problem}</FieldError>}
      {hint && <FieldDescription>{hint}</FieldDescription>}
    </div>
  );
}
