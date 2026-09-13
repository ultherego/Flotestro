import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { AuditEvent } from "../../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, useHost } from "./shared";
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

  // The listed events by outcome, and by who caused them; unknown until
  // the trail loads.
  const events = data?.items;
  const actors = Object.entries((events ?? []).reduce<Record<string, number>>((acc, event) => {
    acc[event.actor_id] = (acc[event.actor_id] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Audit")}
        description={t("Who did what on this host, from the audit trail.")}
      />
      <Widgets>
      <Summary
        title={t("Outcomes")}
        description={t("The last {n} events on this host, by how they ended.", { n: events?.length ?? 50 })}
        span={8}
        segments={[
          { label: t("success"), value: countWhere(events, (event) => event.outcome === "success"), tone: "ok" },
          { label: t("failure"), value: countWhere(events, (event) => event.outcome === "failure"), tone: "error" },
          { label: t("denied"), value: countWhere(events, (event) => event.outcome === "denied"), tone: "warn" },
        ]}
      />
      <Section title={t("By actor")} span={4} description={t("Who caused the most of them.")}>
        {!events ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : !actors.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No events.")}</p>
        ) : (
          <Breakdown items={actors.map(([actor, count]) => ({ label: actor, value: count }))} />
        )}
      </Section>
      <Section title={t("Audit")} count={data?.items.length} span={12} flush>
        {!data?.items.length ? (
          <Empty>{t("No events.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Result")}</th></tr></thead>
            <tbody>
              {data.items.map((event) => (
                <tr key={event.id}>
                  <td><Time value={event.occurred_at} /></td>
                  <td>{event.actor_id}</td>
                  <td className="hm-mono">{event.action}</td>
                  <td><JobState state={event.outcome} /></td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>
    </ModulePage>
  );
}
