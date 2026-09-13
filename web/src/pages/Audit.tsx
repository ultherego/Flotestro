import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { AuditEvent } from "../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../components/ui";
import { useT } from "../i18n";

/** The audit trail. Denials are as visible as successes. */
export function Audit() {
  const t = useT();
  const [denialsOnly, setDenialsOnly] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["audit"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?limit=200"),
    retry: false,
  });

  if (error instanceof ApiError && error.forbidden) {
    return (
      <>
        <h1>{t("Audit")}</h1>
        <Empty>
          {t("You do not have permission to read the fleet-wide audit trail. A single host's audit trail is available in its own view.")}
        </Empty>
      </>
    );
  }
  if (error) return <ErrorBox error={error} />;

  const events = (data?.items ?? []).filter((event) => !denialsOnly || event.outcome === "denied");

  return (
    <>
      <h1>{t("Audit")}</h1>
      <p className="subtitle">{t("Every success and failure creates an event; so does every denial.")}</p>

      <div className="filters">
        <label>
          <input type="checkbox" checked={denialsOnly} onChange={(e) => setDenialsOnly(e.target.checked)} />
          {" "}{t("denials only")}
        </label>
      </div>

      {!events.length ? (
        <Empty>{t("No events.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Kind")}</th><th>{t("Operation")}</th><th>{t("Target")}</th><th>{t("Result")}</th><th>{t("Details")}</th></tr></thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td><Time value={event.occurred_at} /></td>
                <td>{event.actor_id}</td>
                <td>{event.actor_type}</td>
                <td>{event.action}</td>
                <td>{event.target_type ? `${event.target_type}/${(event.target_id ?? "").slice(0, 8)}` : "—"}</td>
                <td><JobState state={event.outcome} /></td>
                <td className="source">{digest(event.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function digest(detail: Record<string, unknown>): string {
  const interesting = ["reason", "action_type", "hostname", "state", "permission", "scope"];
  const parts = interesting
    .filter((key) => detail?.[key] !== undefined)
    .map((key) => `${key}=${String(detail[key])}`);
  return parts.join(" ").slice(0, 90);
}
