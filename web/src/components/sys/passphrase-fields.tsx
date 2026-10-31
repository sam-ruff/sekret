import type { PassphraseStrength } from "@/api/types";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { PassphraseMeter } from "./passphrase-meter";

interface PassphraseFieldsProps {
  idPrefix: string;
  label: string;
  passphrase: string;
  confirm: string;
  strength: PassphraseStrength | null;
  onPassphraseChange: (value: string) => void;
  onConfirmChange: (value: string) => void;
  disabled?: boolean;
}

/** A new passphrase typed twice, with a live strength meter. */
export function PassphraseFields({
  idPrefix,
  label,
  passphrase,
  confirm,
  strength,
  onPassphraseChange,
  onConfirmChange,
  disabled,
}: PassphraseFieldsProps) {
  const mismatch = confirm !== "" && confirm !== passphrase;
  return (
    <>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-passphrase`}>{label}</FieldLabel>
        <Input
          id={`${idPrefix}-passphrase`}
          type="password"
          autoComplete="new-password"
          value={passphrase}
          disabled={disabled}
          onChange={(e) => onPassphraseChange(e.target.value)}
          data-testid={`${idPrefix}-passphrase`}
        />
        <PassphraseMeter strength={strength} testId={`${idPrefix}-meter`} />
      </Field>
      <Field data-invalid={mismatch}>
        <FieldLabel htmlFor={`${idPrefix}-confirm`}>Type it again</FieldLabel>
        <Input
          id={`${idPrefix}-confirm`}
          type="password"
          autoComplete="new-password"
          value={confirm}
          disabled={disabled}
          aria-invalid={mismatch}
          onChange={(e) => onConfirmChange(e.target.value)}
          data-testid={`${idPrefix}-confirm`}
        />
        {mismatch && <FieldError data-testid={`${idPrefix}-mismatch`}>The passphrases do not match.</FieldError>}
      </Field>
    </>
  );
}
