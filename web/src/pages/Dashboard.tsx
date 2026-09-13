import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetSummary, Host } from "../lib/types";
import { ErrorBox, Time, Empty, JobState, ConnectionState } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid } from "../components/layout";
import { useT } from "../i18n";

/**
 * The dashboard shows only data that needs a decision. It is not a wall of
 * decorative charts: every tile leads to a specific action.
 */
export function Dashboard() {
  const t = useT();
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<FleetSummary>("/api/v1/fleet/summary"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const hosts = useQuery({
    queryKey: ["hosts"],
    queryFn: () => api.get<Collection<Host>>("/api/v1/hosts?limit=500"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const campaigns = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=20"),
  });
  const audit = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?limit=50"),
  });

  if (summary.error) return <ErrorBox error={summary.error} />;
  const s = summary.data;

  const needingAttention = (hosts.data?.items ?? []).filter(
    (host) =>
      host.connection_state !== "online" ||
      host.reboot_required === true ||
      (host.failed_units ?? 0) > 0 ||
      host.package_database_broken ||
      (host.identity.enrolled && host.identity.sssd_online === false),
  );

  const activeCampaigns = (campaigns.data?.items ?? []).filter((campaign) =>
    ["canary", "running", "paused", "awaiting_approval"].includes(campaign.state),
  );

  const denials = (audit.data?.items ?? []).filter((event) => event.outcome === "denied");

  // A count above zero on a tile that should read zero is the alarm; the
  // rest of the tiles are the fleet's size, not a state.
  const warnAbove = (value?: number) => ((value ?? 0) > 0 ? "warn" : undefined);
  const errorAbove = (value?: number) => ((value ?? 0) > 0 ? "error" : undefined);

  return (
    <>
      <PageHeader title={t("Fleet dashboard")} description={t("Only what needs a decision.")} />

      <StatGrid>
        <Stat label={t("Hosts")} value={s?.hosts} to="/hosts" />
        <Stat label={t("Online")} value={s?.online} />
        <Stat label={t("Offline")} value={s?.offline} tone={errorAbove(s?.offline)} />
        <Stat label={t("Active sessions")} value={s?.active_sessions} />
        <Stat label={t("Reboot required")} value={s?.reboot_required} tone={warnAbove(s?.reboot_required)} />
        <Stat label={t("With failed units")} value={s?.with_failed_units} tone={warnAbove(s?.with_failed_units)} />
        <Stat label={t("Security updates")} value={s?.hosts_with_security_updates} tone={warnAbove(s?.hosts_with_security_updates)} />
        <Stat label={t("Quarantined")} value={s?.quarantined_hosts} tone={errorAbove(s?.quarantined_hosts)} />
      </StatGrid>

      <Card
        title={t("Hosts needing attention")}
        actions={needingAttention.length > 0 && <span className="badge warn">{needingAttention.length}</span>}
        flush
      >
        {needingAttention.length === 0 ? (
          <Empty>{t("No host needs attention.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Host")}</th><th>{t("State")}</th><th>{t("Reason")}</th><th>{t("Last seen")}</th>
              </tr>
            </thead>
            <tbody>
              {needingAttention.map((host) => (
                <tr key={host.id}>
                  <td><Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link></td>
                  <td><ConnectionState state={host.connection_state} /></td>
                  <td>{attentionReasons(host, t).join(", ")}</td>
                  <td><Time value={host.last_seen_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card
        title={t("Campaigns in progress")}
        actions={activeCampaigns.length > 0 && <span className="badge">{activeCampaigns.length}</span>}
        flush
      >
        {activeCampaigns.length === 0 ? (
          <Empty>{t("No campaigns need attention.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr><th>{t("Name")}</th><th>{t("State")}</th><th>{t("Operation")}</th><th>{t("Pause reason")}</th></tr>
            </thead>
            <tbody>
              {activeCampaigns.map((campaign) => (
                <tr key={campaign.id}>
                  <td><Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link></td>
                  <td><JobState state={campaign.state} /></td>
                  <td className="mono">{campaign.action_type}</td>
                  <td>{campaign.pause_reason || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card
        title={t("Recent access denials")}
        actions={denials.length > 0 && <span className="badge error">{denials.length}</span>}
        flush
      >
        {denials.length === 0 ? (
          <Empty>{t("No denials in recent events.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Reason")}</th></tr></thead>
            <tbody>
              {denials.slice(0, 10).map((event) => (
                <tr key={event.id}>
                  <td><Time value={event.occurred_at} /></td>
                  <td className="mono">{event.actor_id}</td>
                  <td className="mono">{event.action}</td>
                  <td>{String(event.detail?.reason ?? "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function attentionReasons(host: Host, t: (text: string, params?: Record<string, string | number>) => string): string[] {
  const reasons: string[] = [];
  if (host.connection_state !== "online") reasons.push(t("no connection"));
  if (host.reboot_required) reasons.push(t("reboot required"));
  if ((host.failed_units ?? 0) > 0) reasons.push(t("{n} failed units", { n: host.failed_units ?? 0 }));
  if (host.package_database_broken) reasons.push(t("package database needs repair"));
  if (host.identity.enrolled && host.identity.sssd_online === false) reasons.push(t("SSSD offline"));
  return reasons;
}
