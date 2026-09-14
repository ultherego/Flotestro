import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetActivity, FleetSummary, Job } from "../lib/types";
import { ErrorBox, ErrorCode, Time, Empty, JobState } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid } from "../components/layout";
import { BarChart, Breakdown, StatusBar } from "../components/widgets";
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
  // The activity feeds the chart and the composition widgets: computed in
  // the database over the visible hosts, like the summary.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const security = useQuery({
    queryKey: ["security"],
    queryFn: () => api.get<{ checks: { failed: number; unknown: number }[] }>("/api/v1/security"),
    retry: false,
  });
  const failures = useQuery({
    queryKey: ["jobs", "recent-failures"],
    queryFn: () => api.get<Collection<Job>>("/api/v1/jobs?state=failed&limit=8"),
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
  const a = activity.data;
  const byConnection = (state: string) => a?.by_connection_state.find((f) => f.key === state)?.count;
  // Security counts are absent, not zero, while the module is refused or
  // has not answered: the segment then shows a dash.
  const securityFailed = security.data ? security.data.checks.reduce((sum, c) => sum + c.failed, 0) : undefined;
  const securityUnknown = security.data ? security.data.checks.reduce((sum, c) => sum + c.unknown, 0) : undefined;
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });

  // A count above zero on a tile that should read zero is the alarm; the
  // rest of the tiles are the fleet's size, not a state.
  const warnAbove = (value?: number) => ((value ?? 0) > 0 ? "warn" : undefined);
  const errorAbove = (value?: number) => ((value ?? 0) > 0 ? "error" : undefined);
  // The window the failed-task counter covers, for the link to the list.
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const attention = [
    s?.reboot_required, s?.with_failed_units, s?.package_database_broken, s?.sssd_offline,
    s?.failed_jobs_24h, s?.pending_enrollment_requests, s?.agents_behind_latest,
    s?.agent_certificates_expiring, s?.agent_certificates_expired, s?.degraded_relays,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  return (
    <>
      <PageHeader title={t("Fleet dashboard")} description={t("Only what needs a decision.")} />

      {/* The two bars are the state of the fleet read from across the
          room: where the hosts are, and what is wrong. */}
      <div className="widgets">
        <Card className="span-7" title={t("Host availability")} description={t("{n} hosts you can see", { n: s?.hosts ?? 0 })}>
          <StatusBar segments={[
            { label: t("Online"), value: s?.online, tone: "ok", to: "/hosts?connection_state=online" },
            { label: t("Stale"), value: a ? byConnection("stale") ?? 0 : undefined, tone: "warn", to: "/hosts?connection_state=stale" },
            { label: t("Offline"), value: a ? byConnection("offline") ?? 0 : undefined, tone: "error", to: "/hosts?connection_state=offline" },
            { label: t("Unknown"), value: a ? byConnection("unknown") ?? 0 : undefined, tone: "unknown", to: "/hosts?connection_state=unknown" },
            { label: t("Quarantined"), value: s?.quarantined_hosts, tone: "neutral", to: "/hosts?lifecycle_state=quarantined" },
            { label: t("In maintenance"), value: s?.in_maintenance, tone: "neutral", to: "/hosts?maintenance=true" },
          ]} />
        </Card>
        <Card className="span-5" title={t("Problems")} description={t("Findings that need a decision, by kind.")}>
          <StatusBar segments={[
            { label: t("Security findings"), value: securityFailed, tone: "error", to: "/security" },
            { label: t("Failed jobs, 24 h"), value: s?.failed_jobs_24h, tone: "error", to: `/jobs?state=failed&since=${encodeURIComponent(dayAgo)}` },
            { label: t("Reboot required"), value: s?.reboot_required, tone: "warn", to: "/hosts" },
            { label: t("Security updates"), value: s?.hosts_with_security_updates, tone: "warn", to: "/vulnerabilities" },
            { label: t("Unknown checks"), value: securityUnknown, tone: "unknown", to: "/security" },
          ]} />
        </Card>

        <Card className="span-5" title={t("Operations, last 24 h")} description={t("Finished per hour, by outcome.")}>
          {a ? (
            <BarChart
              labels={a.hours.map(hourLabel)}
              everyLabel={3}
              series={[
                { name: t("Succeeded"), tone: "ok", values: a.succeeded },
                { name: t("Failed"), tone: "error", values: a.failed },
                { name: t("Other"), tone: "unknown", values: a.other },
              ]}
            />
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>

        {/* A tile the server left out is a counter it could not answer
            honestly for this view; it is missing, not zero. */}
        <Card
          className="span-4"
          title={t("Needs attention")}
          description={t("Counted in the database over the hosts you can see.")}
          actions={attention > 0 && <span className="badge warn">{attention}</span>}
        >
          <StatGrid compact>
            <Stat label={t("Reboot required")} value={s?.reboot_required} tone={warnAbove(s?.reboot_required)} />
            <Stat label={t("With failed units")} value={s?.with_failed_units} tone={warnAbove(s?.with_failed_units)} />
            <Stat label={t("Package database broken")} value={s?.package_database_broken} tone={errorAbove(s?.package_database_broken)} />
            <Stat label={t("SSSD offline")} value={s?.sssd_offline} tone={warnAbove(s?.sssd_offline)} />
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
            {/* Two tiles for one lifetime: an agent renews with ten days
                left, so a certificate inside its last week is one the agent
                should already have renewed, and one that has run out is a
                host that comes back only through an identity recovery. */}
            {s?.agent_certificates_expiring !== undefined && (
              <Stat label={t("Agent certificates expiring")} value={s.agent_certificates_expiring} hint={t("within 7 days; the agent renews at 10 days left")} tone={warnAbove(s.agent_certificates_expiring)} />
            )}
            {s?.agent_certificates_expired !== undefined && (
              <Stat label={t("Agent certificates expired")} value={s.agent_certificates_expired} hint={t("needs identity recovery")} tone={errorAbove(s.agent_certificates_expired)} to="/hosts?connection_refusal=certificate_expired" />
            )}
            {s?.degraded_relays !== undefined && (
              <Stat label={t("Degraded relays")} value={s.degraded_relays} hint={t("missed renewal")} tone={errorAbove(s.degraded_relays)} />
            )}
            <Stat label={t("Active sessions")} value={s?.active_sessions} />
          </StatGrid>
        </Card>

        <Card className="span-3" title={t("Fleet composition")} description={t("By system and by agent build.")}>
          {a ? (
            <>
              <Breakdown items={a.by_os_family.map((f) => ({ label: f.key, value: f.count }))} />
              <h4 className="widget-subhead">{t("Agent builds")}</h4>
              <Breakdown tone="neutral" items={a.by_agent_version.map((f) => ({ label: f.key, value: f.count }))} />
              <h4 className="widget-subhead">{t("Sites and environments")}</h4>
              <Breakdown tone="ok" items={[...a.by_site.map((f) => ({ label: f.key, value: f.count })), ...a.by_environment.map((f) => ({ label: f.key, value: f.count }))]} />
            </>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>

        <Card
          className="span-6"
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
          className="span-6"
          title={t("Recent failures")}
          description={t("The last operations that failed, newest first.")}
          actions={<Link to="/jobs?state=failed">{t("All jobs")}</Link>}
          flush
        >
          {(failures.data?.items ?? []).length === 0 ? (
            <Empty>{t("No failed operations.")}</Empty>
          ) : (
            <table>
              <thead><tr><th>{t("Time")}</th><th>{t("Host")}</th><th>{t("Operation")}</th><th>{t("Error")}</th></tr></thead>
              <tbody>
                {(failures.data?.items ?? []).map((job) => (
                  <tr key={job.id}>
                    <td><Time value={job.finished_at ?? job.created_at} /></td>
                    <td><Link to={`/hosts/${job.host_id}/jobs`}>{job.hostname || job.host_id.slice(0, 8)}</Link></td>
                    <td className="mono">{job.action_type}</td>
                    <td><ErrorCode code={job.result_error_code || "failed"} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-12"
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
      </div>
    </>
  );
}
