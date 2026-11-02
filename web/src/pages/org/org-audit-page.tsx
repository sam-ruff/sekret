import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import { AuditLog } from "@/components/audit/audit-log";
import { PageHeader } from "@/components/page-header";
import { ErrorState, ListSkeleton } from "@/components/states";
import { keys } from "@/hooks/queries";
import { useOrgPermissions } from "@/hooks/use-permissions";

const NO_ACCESS = new ApiError(
  "Only organisation admins, and people whose organisation role lets them read the audit log, can see this page.",
  403,
  "forbidden",
);

export function OrgAuditPage() {
  const org = useOrgPermissions();
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Everything that happened across the organisation." />
      {!org.ready ? (
        <ListSkeleton rows={6} />
      ) : org.can("org-audit-log", "read") ? (
        <AuditLog queryKey={keys.orgAudit} fetchPage={api.orgAudit} scope="org" />
      ) : (
        <div className="max-w-3xl" data-testid="audit-no-access">
          <ErrorState error={NO_ACCESS} />
        </div>
      )}
    </div>
  );
}
