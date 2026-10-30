import { api } from "@/api/endpoints";
import { AuditLog } from "@/components/audit/audit-log";
import { PageHeader } from "@/components/page-header";
import { keys } from "@/hooks/queries";

export function OrgAuditPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Everything that happened across the organisation." />
      <AuditLog queryKey={keys.orgAudit} fetchPage={api.orgAudit} scope="org" />
    </div>
  );
}
