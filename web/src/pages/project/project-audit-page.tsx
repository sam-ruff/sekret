import { useParams } from "react-router";
import { api } from "@/api/endpoints";
import { AuditLog } from "@/components/audit/audit-log";
import { PageHeader } from "@/components/page-header";
import { keys, useEnvironments } from "@/hooks/queries";
import { useProjectPermissions } from "@/hooks/use-permissions";

export function ProjectAuditPage() {
  const { project = "" } = useParams();
  const environments = useEnvironments(project);
  const perms = useProjectPermissions(project);
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Who did what in this project." />
      <AuditLog
        queryKey={keys.projectAudit(project)}
        fetchPage={(q) => api.projectAudit(project, q)}
        scope="project"
        project={project}
        environments={environments.data}
        seesEverything={(environment) =>
          perms.can("secrets", "read", { environment }) && perms.can("environments", "read", { environment })
        }
      />
    </div>
  );
}
