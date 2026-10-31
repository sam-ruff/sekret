import { useState } from "react";
import type { PassphraseStrength } from "@/api/types";
import { MIN_PASSPHRASE_LENGTH } from "@/lib/passphrase";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { PassphraseInput } from "@/components/secret-field";
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
  const [left, setLeft] = useState(false);
  const mismatch = confirm !== "" && confirm !== passphrase;
  // Only once the person has moved on, so the error does not flash while they type.
  const short = left && passphrase !== "" && Array.from(passphrase).length < MIN_PASSPHRASE_LENGTH;
  const meterId = `${idPrefix}-meter`;
  const mismatchId = `${idPrefix}-mismatch`;
  const shortId = `${idPrefix}-short`;
  return (
    <>
      <Field data-invalid={short}>
        <FieldLabel htmlFor={`${idPrefix}-passphrase`}>{label}</FieldLabel>
        <PassphraseInput
          id={`${idPrefix}-passphrase`}
          autoComplete="new-password"
          value={passphrase}
          disabled={disabled}
          aria-invalid={short}
          aria-describedby={short ? `${shortId} ${meterId}` : meterId}
          onBlur={() => setLeft(true)}
          onChange={(e) => onPassphraseChange(e.target.value)}
          data-testid={`${idPrefix}-passphrase`}
        />
        {short && (
          <FieldError id={shortId} data-testid={shortId}>
            Use at least {MIN_PASSPHRASE_LENGTH} characters.
          </FieldError>
        )}
        <PassphraseMeter strength={strength} testId={meterId} id={meterId} />
      </Field>
      <Field data-invalid={mismatch}>
        <FieldLabel htmlFor={`${idPrefix}-confirm`}>Type it again</FieldLabel>
        <PassphraseInput
          id={`${idPrefix}-confirm`}
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
