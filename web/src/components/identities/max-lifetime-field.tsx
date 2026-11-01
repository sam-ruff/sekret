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

/** The longest token lifetime an auth method accepts, as seconds or with a unit such as 1h. */
export function MaxLifetimeField({ idPrefix, label, value, disabled, onChange, help }: MaxLifetimeFieldProps) {
  const id = `${idPrefix}-max-lifetime`;
  const seconds = parseLifetime(value);
  return (
    <Field data-invalid={seconds === null}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
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
          Enter a duration such as 3600, 30m, 1h or 7d, from 1 second up to 10 years.
        </FieldError>
      ) : (
        <FieldDescription id={`${id}-help`} data-testid={`${id}-help`}>
          {help(seconds)}
        </FieldDescription>
      )}
    </Field>
  );
}
