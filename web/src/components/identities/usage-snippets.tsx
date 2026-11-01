import { Info } from "lucide-react";
import type { Identity } from "@/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  cliKubernetesSnippet,
  cliUniversalSnippet,
  githubActionsCliSnippet,
  githubActionsSnippet,
} from "./identity-model";
import { Snippet } from "./snippet";

export function UsageSnippets({ identity }: { identity: Identity }) {
  const server = window.location.origin;
  const methods = identity.auth_methods;

  return (
    <div className="space-y-6" data-testid="usage-snippets">
      <Alert>
        <Info />
        <AlertDescription>
          These are templates. Replace the placeholders in angle brackets, and make sure the identity is a member of the
          project with a suitable role, as listed under Project access. Identity id: <code className="font-mono" data-testid="usage-identity-id">{identity.id}</code>
        </AlertDescription>
      </Alert>
      <Snippet
        title="CLI with universal auth"
        description={
          methods.includes("universal")
            ? "The CLI reads the client secret from SEKRET_CLIENT_SECRET."
            : "Enable universal auth on this identity first."
        }
        code={cliUniversalSnippet(server, identity.id)}
        testId="snippet-cli-universal"
      />
      <Snippet
        title="CLI in Kubernetes"
        description="Uses the pod's service account token. Needs the Kubernetes auth method."
        code={cliKubernetesSnippet(server, identity.id)}
        testId="snippet-cli-kubernetes"
      />
      <Snippet
        title="GitHub Actions"
        description="Exchanges the workflow's OIDC token for a sekret token. Needs the OIDC auth method bound to your repository."
        code={githubActionsSnippet(server, identity.id)}
        testId="snippet-github-actions"
      />
      <Snippet
        title="GitHub Actions with the CLI installed"
        description="If the runner has the sekret CLI, it can fetch the OIDC token itself."
        code={githubActionsCliSnippet(identity.id)}
        testId="snippet-github-actions-cli"
      />
    </div>
  );
}
