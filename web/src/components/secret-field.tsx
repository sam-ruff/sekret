import { Eye, EyeOff } from "lucide-react";
import { useState, type ComponentProps } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { PASSPHRASE_FIELD_ATTRIBUTES, SECRET_FIELD_ATTRIBUTES } from "@/lib/secret-field";
import { cn } from "@/lib/utils";

interface SecretInputProps extends ComponentProps<typeof Input> {
  /** Let password managers save and fill it, for the server passphrase. */
  passwordManager?: boolean;
}

/** An input for a secret. Pass `autoComplete` to keep a password manager's hint, such as `current-password`. */
export function SecretInput({ passwordManager, ...props }: SecretInputProps) {
  const attributes = passwordManager ? PASSPHRASE_FIELD_ATTRIBUTES : SECRET_FIELD_ATTRIBUTES;
  return <Input {...attributes} {...props} spellCheck={false} autoCorrect="off" autoCapitalize="off" />;
}

/**
 * A secret typed or pasted once and never shown, such as a token. It is a text field drawn as dots,
 * so browsers and password managers do not treat it as a login password.
 */
export function MaskedSecretInput({ className, ...props }: Omit<ComponentProps<typeof Input>, "type">) {
  return <SecretInput {...props} type="text" className={cn("[-webkit-text-security:disc]", className)} />;
}

interface PassphraseInputProps extends Omit<ComponentProps<typeof Input>, "type"> {
  "data-testid"?: string;
}

/** The server passphrase, hidden until the person chooses to show it. */
export function PassphraseInput({ className, disabled, ...props }: PassphraseInputProps) {
  const [shown, setShown] = useState(false);
  const testId = props["data-testid"];
  return (
    <div className="relative">
      <SecretInput
        {...props}
        passwordManager
        disabled={disabled}
        type={shown ? "text" : "password"}
        className={cn("pr-10", className)}
      />
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="absolute top-1/2 right-0.5 -translate-y-1/2 text-muted-foreground"
        aria-label={shown ? "Hide passphrase" : "Show passphrase"}
        aria-controls={props.id}
        disabled={disabled}
        onClick={() => setShown(!shown)}
        data-testid={testId ? `${testId}-toggle` : undefined}
      >
        {shown ? <EyeOff /> : <Eye />}
      </Button>
    </div>
  );
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
