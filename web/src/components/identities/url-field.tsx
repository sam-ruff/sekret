import type { ReactNode } from "react";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { outboundUrlProblem } from "./identity-model";

interface UrlFieldProps {
  id: string;
  label: string;
  value: string;
  placeholder?: string;
  disabled?: boolean;
  onChange: (value: string) => void;
  description?: ReactNode;
}

/** A URL the server will contact, flagged by the field when the server would refuse it. */
export function UrlField({ id, label, value, placeholder, disabled, onChange, description }: UrlFieldProps) {
  const problem = outboundUrlProblem(value);
  return (
    <Field data-invalid={problem !== undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        className="font-mono"
        aria-invalid={problem !== undefined}
        aria-describedby={problem ? `${id}-error` : undefined}
        onChange={(e) => onChange(e.target.value)}
        data-testid={id}
      />
      {problem ? (
        <FieldError id={`${id}-error`} data-testid={`${id}-error`}>
          {problem}
        </FieldError>
      ) : (
        description && <FieldDescription>{description}</FieldDescription>
      )}
    </Field>
  );
}
