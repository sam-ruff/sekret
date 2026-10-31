import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { clipboardGuard } from "@/lib/clipboard";
import { cn } from "@/lib/utils";

interface CopyButtonProps {
  /** The text, or a function that fetches it on demand (for values not yet revealed). */
  value: string | (() => Promise<string | null | undefined>);
  label?: string;
  className?: string;
  testId?: string;
  disabled?: boolean;
  /** A secret, cleared from the clipboard after a while if it is still there. */
  sensitive?: boolean;
}

async function writeClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

export function CopyButton({ value, label = "Copy", className, testId, disabled, sensitive }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const copy = async () => {
    try {
      const text = typeof value === "string" ? value : await value();
      if (text == null) return;
      await writeClipboard(text);
      if (sensitive) clipboardGuard().clearLater(text);
      setCopied(true);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Could not copy to the clipboard");
    }
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label={label}
          onClick={copy}
          disabled={disabled}
          data-testid={testId}
          className={cn("text-muted-foreground", className)}
        >
          {copied ? <Check className="text-success animate-in zoom-in-50" /> : <Copy />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copied" : label}</TooltipContent>
    </Tooltip>
  );
}
