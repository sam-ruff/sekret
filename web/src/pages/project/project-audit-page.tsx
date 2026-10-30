import { useParams } from "react-router";
import { api } from "@/api/endpoints";
import { AuditLog } from "@/components/audit/audit-log";
import { PageHeader } from "@/components/page-header";
import { keys, useEnvironments } from "@/hooks/queries";

export function ProjectAuditPage() {
  const { project = "" } = useParams();
  const environments = useEnvironments(project);
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Who did what in this project." />
      <AuditLog
        queryKey={keys.projectAudit(project)}
        fetchPage={(q) => api.projectAudit(project, q)}
        scope="project"
        environments={environments.data}
      />
    </div>
  );
}
