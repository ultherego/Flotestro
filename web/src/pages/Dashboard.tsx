import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetSummary } from "../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../components/ui";
import { Card, Columns, PageHeader, Stat, StatGrid } from "../components/layout";
import { useT } from "../i18n";

/**
 * The dashboard shows only data that needs a decision. It is not a wall of
 * decorative charts: every tile leads to a specific action.
 *
 * The counters come from the fleet summary, computed in the database over
 * the hosts the operator may see. The dashboard does not fetch the fleet
 * to count it: a fleet of five thousand hosts is five thousand rows the
 * browser would download every few seconds to learn one number.
 */
export function Dashboard() {
  const t = useT();
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<FleetSummary>("/api/v1/fleet/summary"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const campaigns = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=20"),
  });
  // The denials are asked for by name: the trail filters on the server, so
  // the dashboard does not read fifty events to find the three that matter.
  const denials = useQuery({
    queryKey: ["audit", "denied"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?outcome=denied&limit=10"),
  });

  if (summary.error) return <ErrorBox error={summary.error} />;
  const s = summary.data;

  const activeCampaigns = (campaigns.data?.items ?? []).filter((campaign) =>
    ["canary", "running", "paused", "awaiting_approval"].includes(campaign.state),
  );
  const denied = denials.data?.items ?? [];

  // A count above zero on a tile that should read zero is the alarm; the
  // rest of the tiles are the fleet's size, not a state.
  const warnAbove = (value?: number) => ((value ?? 0) > 0 ? "warn" : undefined);
  const errorAbove = (value?: number) => ((value ?? 0) > 0 ? "error" : undefined);
  // The window the failed-task counter covers, for the link to the list.
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const attention = [
    s?.reboot_required, s?.with_failed_units, s?.package_database_broken, s?.sssd_offline,
    s?.failed_jobs_24h, s?.pending_enrollment_requests, s?.agents_behind_latest,
    s?.agent_certificates_expiring, s?.degraded_relays,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  return (
    <>
      <PageHeader title={t("Fleet dashboard")} description={t("Only what needs a decision.")} />

      <StatGrid>
        <Stat label={t("Hosts")} value={s?.hosts} to="/hosts" />
        <Stat label={t("Online")} value={s?.online} to="/hosts?connection_state=online" />
        <Stat label={t("Offline")} value={s?.offline} tone={errorAbove(s?.offline)} to="/hosts?connection_state=offline" />
        <Stat label={t("Active sessions")} value={s?.active_sessions} />
        <Stat label={t("Security updates")} value={s?.hosts_with_security_updates} tone={warnAbove(s?.hosts_with_security_updates)} />
        <Stat label={t("Quarantined")} value={s?.quarantined_hosts} tone={errorAbove(s?.quarantined_hosts)} to="/hosts?lifecycle_state=quarantined" />
        <Stat label={t("In maintenance")} value={s?.in_maintenance} hint={t("campaigns skip them")} to="/hosts?maintenance=true" />
      </StatGrid>

      {/* A tile the server left out is a counter it could not answer
          honestly for this view; it is missing, not zero. */}
      <Card
        title={t("Needs attention")}
        description={t("Counted in the database over the hosts you can see.")}
        actions={attention > 0 && <span className="badge warn">{attention}</span>}
      >
        <StatGrid compact>
          <Stat label={t("Reboot required")} value={s?.reboot_required} tone={warnAbove(s?.reboot_required)} />
          <Stat label={t("With failed units")} value={s?.with_failed_units} tone={warnAbove(s?.with_failed_units)} />
          <Stat label={t("Package database broken")} value={s?.package_database_broken} tone={errorAbove(s?.package_database_broken)} />
          <Stat label={t("SSSD offline")} value={s?.sssd_offline} tone={warnAbove(s?.sssd_offline)} />
          {s?.failed_jobs_24h !== undefined && (
            <Stat label={t("Failed jobs, 24 h")} value={s.failed_jobs_24h} tone={errorAbove(s.failed_jobs_24h)} to={`/jobs?state=failed&since=${encodeURIComponent(dayAgo)}`} />
          )}
          {s?.pending_enrollment_requests !== undefined && (
            <Stat label={t("Pending enrollments")} value={s.pending_enrollment_requests} tone={warnAbove(s.pending_enrollment_requests)} to="/hosts/new" />
          )}
          {s?.agents_behind_latest !== undefined && (
            <Stat
              label={t("Agents behind {version}", { version: s.latest_agent_version ?? "" })}
              value={s.agents_behind_latest}
              tone={warnAbove(s.agents_behind_latest)}
              hint={t("newest version seen in the fleet")}
            />
          )}
          {s?.agent_certificates_expiring !== undefined && (
            <Stat label={t("Agent certificates expiring")} value={s.agent_certificates_expiring} hint={t("within 30 days")} tone={warnAbove(s.agent_certificates_expiring)} />
          )}
          {s?.degraded_relays !== undefined && (
            <Stat label={t("Degraded relays")} value={s.degraded_relays} hint={t("missed renewal")} tone={errorAbove(s.degraded_relays)} />
          )}
        </StatGrid>
      </Card>

      <Columns>
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
        actions={denied.length > 0 && <span className="badge error">{denied.length}</span>}
        flush
      >
        {denied.length === 0 ? (
          <Empty>{t("No denials in recent events.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Reason")}</th></tr></thead>
            <tbody>
              {denied.map((event) => (
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
      </Columns>
    </>
  );
}
