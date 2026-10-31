import type { ComponentProps } from "react";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { SECRET_FIELD_ATTRIBUTES } from "@/lib/secret-field";

/** An input for a secret. Pass `autoComplete` to keep a password manager's hint, such as `current-password`. */
export function SecretInput(props: ComponentProps<typeof Input>) {
  return <Input {...SECRET_FIELD_ATTRIBUTES} {...props} spellCheck={false} autoCorrect="off" autoCapitalize="off" />;
}

export function SecretTextarea(props: ComponentProps<typeof Textarea>) {
  return (
    <Textarea
      {...SECRET_FIELD_ATTRIBUTES}
      {...props}
      autoComplete="off"
      spellCheck={false}
      autoCorrect="off"
      autoCapitalize="off"
    />
  );
}
