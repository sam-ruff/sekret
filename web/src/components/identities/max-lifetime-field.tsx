import type { ReactNode } from "react";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { parseLifetime } from "./identity-model";

interface MaxLifetimeFieldProps {
  /** Prefixes the field's id and test ids, such as `k8s` or `oidc`. */
  idPrefix: string;
  label: string;
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
  /** What the valid lifetime means for this kind of token. */
  help: (seconds: number) => ReactNode;
}

/** The longest token lifetime an auth method accepts, in whole seconds. */
export function MaxLifetimeField({ idPrefix, label, value, disabled, onChange, help }: MaxLifetimeFieldProps) {
  const id = `${idPrefix}-max-lifetime`;
  const seconds = parseLifetime(value);
  return (
    <Field data-invalid={seconds === null}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        inputMode="numeric"
        value={value}
        disabled={disabled}
        className="w-full font-mono sm:w-40"
        aria-invalid={seconds === null}
        aria-describedby={seconds === null ? `${id}-error` : `${id}-help`}
        onChange={(e) => onChange(e.target.value)}
        data-testid={id}
      />
      {seconds === null ? (
        <FieldError id={`${id}-error`} data-testid={`${id}-error`}>
          Enter a whole number of seconds, from 1 up to 10 years.
        </FieldError>
      ) : (
        <FieldDescription id={`${id}-help`} data-testid={`${id}-help`}>
          {help(seconds)}
        </FieldDescription>
      )}
    </Field>
  );
}
