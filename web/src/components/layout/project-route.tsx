import { Outlet, useParams } from "react-router";
import { MissingState } from "@/components/states";
import { isNotFound } from "@/lib/errors";
import { useProject } from "@/hooks/queries";
import { PageTitleScope, usePageTitle } from "@/hooks/use-page-title";

function MissingProject({ slug }: { slug: string }) {
  usePageTitle("Project not found");
  return (
    <MissingState
      title="Project not found"
      description={`There is no project called "${slug}" that you can see. It may have been deleted or renamed, or you may not have access to it.`}
      backTo="/projects"
      backLabel="Back to projects"
      testId="project-missing"
    />
  );
}

/** Every project page, replaced by a way back when the project does not exist. */
export function ProjectRoute() {
  const { project = "" } = useParams();
  const query = useProject(project);
  if (isNotFound(query.error)) return <MissingProject slug={project} />;
  return (
    <PageTitleScope.Provider value={query.data?.name}>
      <Outlet />
    </PageTitleScope.Provider>
  );
}
