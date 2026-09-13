import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { AuditEvent } from "../../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../../components/ui";
import { useHost } from "./shared";
import { useT } from "../../i18n";

export function HostAudit() {
  const t = useT();
  const host = useHost();
  const { data, error } = useQuery({
    queryKey: ["audit", host.id],
    queryFn: () => api.get<Collection<AuditEvent>>(`/api/v1/hosts/${host.id}/audit?limit=50`),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Empty>{t("You do not have permission to read this host's audit trail.")}</Empty>;
  }
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No events.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Result")}</th></tr></thead>
      <tbody>
        {data.items.map((event) => (
          <tr key={event.id}>
            <td><Time value={event.occurred_at} /></td>
            <td>{event.actor_id}</td>
            <td>{event.action}</td>
            <td><JobState state={event.outcome} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
