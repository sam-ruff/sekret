import { ChevronRight, Info } from "lucide-react";
import { Link } from "react-router";
import type { AuthMethodKind, Identity } from "@/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  cliKubernetesSnippet,
  cliUniversalSnippet,
  githubActionsCliSnippet,
  githubActionsSnippet,
} from "./identity-model";
import { Snippet } from "./snippet";

interface SnippetSpec {
  method: AuthMethodKind;
  title: string;
  description: string;
  code: string;
  testId: string;
}

const METHOD_NAMES: Record<AuthMethodKind, string> = { universal: "universal", oidc: "OIDC", kubernetes: "Kubernetes" };

function snippets(server: string, id: string): SnippetSpec[] {
  return [
    {
      method: "universal",
      title: "CLI with universal auth",
      description: "The CLI reads the client secret from SEKRET_CLIENT_SECRET.",
      code: cliUniversalSnippet(server, id),
      testId: "snippet-cli-universal",
    },
    {
      method: "kubernetes",
      title: "CLI in Kubernetes",
      description: "Uses the pod's service account token.",
      code: cliKubernetesSnippet(server, id),
      testId: "snippet-cli-kubernetes",
    },
    {
      method: "oidc",
      title: "GitHub Actions",
      description: "Exchanges the workflow's OIDC token for a sekret token. The OIDC method must be bound to your repository.",
      code: githubActionsSnippet(server, id),
      testId: "snippet-github-actions",
    },
    {
      method: "oidc",
      title: "GitHub Actions with the CLI installed",
      description: "If the runner has the sekret CLI, it can fetch the OIDC token itself.",
      code: githubActionsCliSnippet(id),
      testId: "snippet-github-actions-cli",
    },
  ];
}

export function UsageSnippets({ identity }: { identity: Identity }) {
  const all = snippets(window.location.origin, identity.id);
  const ready = all.filter((s) => identity.auth_methods.includes(s.method));
  const notSetUp = all.filter((s) => !identity.auth_methods.includes(s.method));
  const authHref = `/org/identities/${identity.id}/auth`;

  return (
    <div className="space-y-6" data-testid="usage-snippets">
      <Alert>
        <Info />
        <AlertDescription>
          These are templates. Replace the placeholders in angle brackets, and make sure the identity is a member of the
          project with a suitable role, as listed under Project access. Identity id: <code className="font-mono" data-testid="usage-identity-id">{identity.id}</code>
        </AlertDescription>
      </Alert>
      {ready.length === 0 && (
        <p className="text-sm text-muted-foreground" data-testid="usage-no-methods">
          This identity has no way to sign in yet.{" "}
          <Link to={authHref} className="font-medium text-primary underline-offset-4 hover:underline">
            Set up an auth method
          </Link>{" "}
          to use one of the snippets below.
        </p>
      )}
      {ready.map((s) => (
        <Snippet key={s.testId} title={s.title} description={s.description} code={s.code} testId={s.testId} />
      ))}
      {notSetUp.length > 0 && (
        <Collapsible defaultOpen={ready.length === 0} className="space-y-4 rounded-lg border p-3" data-testid="usage-not-set-up">
          <CollapsibleTrigger asChild>
            <Button variant="ghost" size="sm" className="group -m-1 h-auto w-full justify-start gap-2 p-1 text-left whitespace-normal" data-testid="usage-not-set-up-toggle">
              <ChevronRight className="transition-transform group-data-[state=open]:rotate-90" />
              <span>
                <span className="font-medium">Methods not set up here</span>
                <span className="block text-xs font-normal text-muted-foreground">
                  {notSetUp.length === 1 ? "1 snippet needs" : `${notSetUp.length} snippets need`} an auth method this
                  identity does not have yet.
                </span>
              </span>
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-6">
            {notSetUp.map((s) => (
              <Snippet
                key={s.testId}
                title={s.title}
                description={`${s.description} Needs the ${METHOD_NAMES[s.method]} auth method, which is not set up.`}
                code={s.code}
                testId={s.testId}
              />
            ))}
            <Button asChild variant="outline" size="sm">
              <Link to={authHref} data-testid="usage-set-up-auth">
                Set up auth methods
              </Link>
            </Button>
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  );
}
