import type { PassphraseStrength } from "@/api/types";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { SecretInput } from "@/components/secret-field";
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
  const meterId = `${idPrefix}-meter`;
  const mismatchId = `${idPrefix}-mismatch`;
  return (
    <>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-passphrase`}>{label}</FieldLabel>
        <SecretInput
          id={`${idPrefix}-passphrase`}
          type="password"
          autoComplete="new-password"
          value={passphrase}
          disabled={disabled}
          aria-describedby={meterId}
          onChange={(e) => onPassphraseChange(e.target.value)}
          data-testid={`${idPrefix}-passphrase`}
        />
        <PassphraseMeter strength={strength} testId={meterId} id={meterId} />
      </Field>
      <Field data-invalid={mismatch}>
        <FieldLabel htmlFor={`${idPrefix}-confirm`}>Type it again</FieldLabel>
        <SecretInput
          id={`${idPrefix}-confirm`}
          type="password"
          autoComplete="new-password"
          value={confirm}
          disabled={disabled}
          aria-invalid={mismatch}
          aria-describedby={mismatch ? mismatchId : undefined}
          onChange={(e) => onConfirmChange(e.target.value)}
          data-testid={`${idPrefix}-confirm`}
        />
        {mismatch && (
          <FieldError id={mismatchId} data-testid={mismatchId}>
            The passphrases do not match.
          </FieldError>
        )}
      </Field>
    </>
  );
}

/**
 * A hidden username so a password manager labels the saved passphrase clearly instead of guessing
 * from nearby fields.
 */
export function PassphraseAccountField() {
  return (
    <input
      type="text"
      name="username"
      autoComplete="username"
      value={`sekret passphrase (${window.location.host})`}
      readOnly
      hidden
      data-testid="passphrase-account"
    />
  );
}
