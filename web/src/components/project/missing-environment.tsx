import type { Environment } from "@/api/types";
import { MissingState } from "@/components/states";

/** An environment slug from the URL that does not exist, with a link to one that does. */
export function MissingEnvironment({
  name,
  first,
  hrefFor,
}: {
  name: string;
  first: Environment;
  hrefFor: (slug: string) => string;
}) {
  return (
    <MissingState
      title="Environment not found"
      description={`There is no environment called "${name}" in this project. It may have been renamed or deleted.`}
      backTo={hrefFor(first.slug)}
      backLabel={`Open ${first.name}`}
      testId="environment-missing"
      headingLevel={2}
    />
  );
}
