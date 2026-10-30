import { CopyButton } from "@/components/copy-button";

interface SnippetProps {
  title: string;
  description?: string;
  code: string;
  testId?: string;
}

export function Snippet({ title, description, code, testId }: SnippetProps) {
  return (
    <section className="space-y-2" data-testid={testId}>
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      <div className="relative rounded-lg border bg-muted/40">
        <pre className="overflow-x-auto p-3 pr-12 font-mono text-xs leading-relaxed">{code}</pre>
        <div className="absolute top-1.5 right-1.5">
          <CopyButton value={code} label={`Copy ${title.toLowerCase()}`} testId={testId ? `${testId}-copy` : undefined} />
        </div>
      </div>
    </section>
  );
}
