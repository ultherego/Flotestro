import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetSummary, Host } from "../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../components/ui";
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

  return (
    <>
      <h1>{t("Fleet dashboard")}</h1>
      <p className="subtitle">{t("Only what needs a decision.")}</p>

      <div className="tiles">
        <Tile label={t("Hosts")} value={s?.hosts} />
        <Tile label={t("Online")} value={s?.online} />
        <Tile label={t("Offline")} value={s?.offline} alarm={(s?.offline ?? 0) > 0} />
        <Tile label={t("Active sessions")} value={s?.active_sessions} />
        <Tile label={t("Reboot required")} value={s?.reboot_required} warn={(s?.reboot_required ?? 0) > 0} />
        <Tile label={t("With failed units")} value={s?.with_failed_units} warn={(s?.with_failed_units ?? 0) > 0} />
        <Tile label={t("Security updates")} value={s?.hosts_with_security_updates} warn={(s?.hosts_with_security_updates ?? 0) > 0} />
        <Tile label={t("Quarantined")} value={s?.quarantined_hosts} alarm={(s?.quarantined_hosts ?? 0) > 0} />
      </div>

      <h2>{t("Hosts needing attention")}</h2>
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
                <td><span className="badge">{t(host.connection_state)}</span></td>
                <td>{attentionReasons(host, t).join(", ")}</td>
                <td><Time value={host.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Campaigns in progress")}</h2>
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
                <td>{campaign.action_type}</td>
                <td>{campaign.pause_reason || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Recent access denials")}</h2>
      {denials.length === 0 ? (
        <Empty>{t("No denials in recent events.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Reason")}</th></tr></thead>
          <tbody>
            {denials.slice(0, 10).map((event) => (
              <tr key={event.id}>
                <td><Time value={event.occurred_at} /></td>
                <td>{event.actor_id}</td>
                <td>{event.action}</td>
                <td>{String(event.detail?.reason ?? "")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
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

function Tile({
  label, value, warn, alarm,
}: { label: string; value?: number; warn?: boolean; alarm?: boolean }) {
  const kind = alarm ? "tile error" : warn ? "tile warn" : "tile";
  return (
    <div className={kind}>
      <div className="label">{label}</div>
      <div className="value">{value ?? "—"}</div>
    </div>
  );
}
