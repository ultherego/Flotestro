import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetActivity, FleetSummary, Job } from "../lib/types";
import { relativeTime } from "../lib/format";
import { ErrorBox, ErrorCode, Time, Empty, JobState } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid } from "../components/layout";
import { BarChart, Breakdown, StatusBar } from "../components/widgets";
import { useT } from "../i18n";

/**
 * The summary with the counters of what waits for a person: the jobs and the
 * campaigns awaiting approval, the campaigns at a manual gate, the directory
 * changes with a plan and no signature, the hosts a policy found drifted,
 */
type DecisionSummary = FleetSummary & {
  jobs_awaiting_approval?: number;
  campaigns_awaiting_approval?: number;
  campaigns_manual_gate?: number;
  directory_changes_pending?: number;
  hosts_drifted?: number;
  alerts_firing?: number;
  alerts_critical?: number;
};

/**
 * The dashboard shows only data that needs a decision. It is not a wall of
 * decorative charts: every tile leads to a specific action.
 */
export function Dashboard() {
  const t = useT();
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<DecisionSummary>("/api/v1/fleet/summary"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const campaigns = useQuery({
    queryKey: ["campaigns"],
    // The list takes one state at a time, so the ones that need a person are
    // picked out here: a hundred newest rows reach back far enough for a
    // campaign parked at a gate weeks ago, where twenty did not.
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=100"),
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

  // A campaign in progress is one a person may still have to act on: the
  // ones at work, the ones waiting for a consent or a go-ahead, and the ones
  // still computing their plans.
  const activeCampaigns = (campaigns.data?.items ?? []).filter((campaign) =>
    ["planning", "planned", "awaiting_approval", "canary", "manual_gate", "running", "pausing", "paused"].includes(campaign.state),
  );
  const denied = denials.data?.items ?? [];
  const a = activity.data;
  const byConnection = (state: string) => a?.by_connection_state.find((f) => f.key === state)?.count;
  // Security counts are absent, not zero, while the module is refused or
  // has not answered: the segment then shows a dash.
  const securityFailed = security.data ? security.data.checks.reduce((sum, c) => sum + c.failed, 0) : undefined;
  const securityUnknown = security.data ? security.data.checks.reduce((sum, c) => sum + c.unknown, 0) : undefined;
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });
  // A facet the hosts have not reported is a badge, not a value named
  // "unknown" that reads like a system called that.
  const facetLabel = (key: string) => (key === "" || key === "unknown"
    ? <span className="badge unknown">{t("unknown")}</span>
    : key);

  // A count above zero on a tile that should read zero is the alarm; the
  // rest of the tiles are the fleet's size, not a state.
  const warnAbove = (value?: number) => ((value ?? 0) > 0 ? "warn" : undefined);
  const errorAbove = (value?: number) => ((value ?? 0) > 0 ? "error" : undefined);
  // The window the failed-task counter covers, for the link to the list.
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const waiting = [
    s?.jobs_awaiting_approval, s?.campaigns_awaiting_approval, s?.campaigns_manual_gate,
    s?.directory_changes_pending, s?.hosts_drifted,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  // The tile has something to show when at least one kind of decision
  // is the reader's to take.
  const decidable = s !== undefined && [
    s.jobs_awaiting_approval, s.campaigns_awaiting_approval, s.directory_changes_pending, s.hosts_drifted,
  ].some((value) => value !== undefined);

  const attention = [
    s?.reboot_required, s?.with_failed_units, s?.package_database_broken, s?.sssd_offline,
    s?.failed_jobs_24h, s?.pending_enrollment_requests, s?.agents_behind_latest,
    s?.agent_certificates_expiring, s?.agent_certificates_expired, s?.degraded_relays,
    s?.relays_buffer_high, s?.duplicate_identities_24h, s?.enrollment_refusals_1h, s?.agents_unsupported,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  return (
    <>
      <PageHeader
        title={t("Fleet dashboard")}
        description={<>{t("Only what needs a decision.")} <Refreshed at={summary.dataUpdatedAt} fetching={summary.isFetching} onRefresh={() => summary.refetch()} /></>}
      />

      {/* An empty fleet is a panel on its first run, not a fleet with
          nothing wrong: the card says what comes first and leads to the
          checklist, so the empty tiles below are not the whole answer. */}
      {s?.hosts === 0 && (
        <div style={{ marginBottom: 16 }}>
          <Card
            tone="warn"
            title={t("No host is enrolled yet")}
            description={t("A fresh panel is set up in this order; the checklist tracks every step.")}
            actions={<Link className="button primary" to="/setup">{t("Open the first-run checklist")}</Link>}
          >
            <ol className="steps">
              <li>{t("Test the identity provider and map the first group to a role, so the team can sign in.")}</li>
              <li>{t("Revoke the bootstrap token once a mapped administrator has signed in.")}</li>
              <li>{t("Enrol the first host with the one-line installation from the add-host screen.")}</li>
            </ol>
          </Card>
        </div>
      )}

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
            // A segment at zero is the narrowest of the bar, and a label
            // longer than a dozen characters is cut off in it; these two are
            // the short names of the tiles below.
            { label: t("Reboot due"), value: s?.reboot_required, tone: "warn", to: "/hosts?reboot_required=true" },
            { label: t("Unpatched"), value: s?.hosts_with_security_updates, tone: "warn", to: "/hosts?security_updates=true" },
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
            {/* Every tile leads to the host list narrowed to the hosts it
                counted: the count is the question, the list the answer. */}
            <Stat label={t("Reboot required")} value={s?.reboot_required} tone={warnAbove(s?.reboot_required)} to="/hosts?reboot_required=true" />
            <Stat label={t("With failed units")} value={s?.with_failed_units} tone={warnAbove(s?.with_failed_units)} to="/hosts?failed_units=true" />
            <Stat label={t("Package database broken")} value={s?.package_database_broken} tone={errorAbove(s?.package_database_broken)} to="/hosts?package_db_broken=true" />
            <Stat label={t("SSSD offline")} value={s?.sssd_offline} tone={warnAbove(s?.sssd_offline)} to="/hosts?sssd_offline=true" />
            {s?.pending_enrollment_requests !== undefined && (
              <Stat label={t("Pending enrollments")} value={s.pending_enrollment_requests} tone={warnAbove(s.pending_enrollment_requests)} to="/hosts/new" />
            )}
            {s?.agents_behind_latest !== undefined && (
              <Stat
                label={t("Agents behind {version}", { version: s.latest_agent_version ?? "" })}
                value={s.agents_behind_latest}
                tone={warnAbove(s.agents_behind_latest)}
                hint={t("newest version seen in the fleet")}
                to="/hosts?agent_behind=true"
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
              <Stat label={t("Degraded relays")} value={s.degraded_relays} hint={t("missed renewal")} tone={errorAbove(s.degraded_relays)} to="/relays" />
            )}
            {/* The lifecycle document's alarms that no host sample can
                carry: a relay filling up, a cloned identity, a burst of
                refused enrollments, an agent the panel cannot talk to.
                Each is a counter over the trail or the heartbeats, and
                each leads where the detail is. */}
            {s?.relays_buffer_high !== undefined && (
              <Stat label={t("Relay buffers high")} value={s.relays_buffer_high} hint={t("at least 70 % full")} tone={warnAbove(s.relays_buffer_high)} to="/relays" />
            )}
            {s?.duplicate_identities_24h !== undefined && (
              <Stat label={t("Duplicate identities, 24 h")} value={s.duplicate_identities_24h} hint={t("a cloned machine or image")} tone={errorAbove(s.duplicate_identities_24h)} to="/audit?action=security.duplicate_identity" />
            )}
            {s?.enrollment_refusals_1h !== undefined && (
              <Stat label={t("Enrollment refusals, 1 h")} value={s.enrollment_refusals_1h} hint={t("a burst is a leaked token")} tone={warnAbove(s.enrollment_refusals_1h)} to="/audit?action=host.enroll&outcome=denied" />
            )}
            {s?.agents_unsupported !== undefined && (
              <Stat label={t("Agents unsupported")} value={s.agents_unsupported} hint={t("a protocol this panel does not speak")} tone={errorAbove(s.agents_unsupported)} to="/hosts?agent_behind=true" />
            )}
            <Stat label={t("Active sessions")} value={s?.active_sessions} />
          </StatGrid>
        </Card>

        {/* What waits for a person, by kind, each count leading to the
            list it was taken from. A kind the reader may not see is left
            out rather than shown as nothing waiting. */}
        <Card
          className="span-3"
          title={t("Waiting for approval")}
          description={t("Decisions nobody has taken yet.")}
          actions={waiting > 0 && <span className="badge warn">{waiting}</span>}
        >
          {!s ? <Empty>{t("Loading…")}</Empty> : !decidable ? <Empty>{t("Nothing you may decide on.")}</Empty> : (
            <StatGrid compact>
              {s.jobs_awaiting_approval !== undefined && (
                <Stat label={t("Jobs")} value={s.jobs_awaiting_approval} tone={warnAbove(s.jobs_awaiting_approval)} to="/jobs?state=awaiting_approval" />
              )}
              {s.campaigns_awaiting_approval !== undefined && (
                <Stat label={t("Campaigns")} value={s.campaigns_awaiting_approval} tone={warnAbove(s.campaigns_awaiting_approval)} to="/campaigns?state=awaiting_approval" />
              )}
              {s.campaigns_manual_gate !== undefined && (
                <Stat label={t("Campaigns at a gate")} value={s.campaigns_manual_gate} hint={t("a wave waits for a go-ahead")} tone={warnAbove(s.campaigns_manual_gate)} to="/campaigns?state=manual_gate" />
              )}
              {s.directory_changes_pending !== undefined && (
                <Stat label={t("Directory changes")} value={s.directory_changes_pending} tone={warnAbove(s.directory_changes_pending)} to="/directory" />
              )}
              {s.hosts_drifted !== undefined && (
                <Stat label={t("Hosts drifted")} value={s.hosts_drifted} hint={t("a policy disagrees with the host")} tone={warnAbove(s.hosts_drifted)} to="/policies" />
              )}
            </StatGrid>
          )}
        </Card>

        <Card className="span-3" title={t("Fleet composition")} description={t("By system, agent build, site and environment.")}>
          {a ? (
            <>
              <Breakdown items={a.by_os_family.map((f) => ({ label: facetLabel(f.key), value: f.count }))} />
              <h4 className="widget-subhead">{t("Agent builds")}</h4>
              <Breakdown tone="neutral" items={a.by_agent_version.map((f) => ({ label: facetLabel(f.key), value: f.count }))} />
              {/* Sites and environments are two dimensions, not one list:
                  "lab 6, test 6" under one heading reads as two sites. */}
              <h4 className="widget-subhead">{t("Sites")}</h4>
              <Breakdown tone="ok" items={a.by_site.map((f) => ({ label: facetLabel(f.key), value: f.count }))} />
              <h4 className="widget-subhead">{t("Environments")}</h4>
              <Breakdown tone="ok" items={a.by_environment.map((f) => ({ label: facetLabel(f.key), value: f.count }))} />
            </>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>

        <Card
          className="span-5"
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
          className="span-4"
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
                {/* The time leads to the job itself, the host to its
                    history: the two questions a failure raises. */}
                {(failures.data?.items ?? []).map((job) => (
                  <tr key={job.id}>
                    <td><Link to={`/jobs/${job.id}`}><Time value={job.finished_at ?? job.created_at} /></Link></td>
                    <td><Link to={`/hosts/${job.host_id}/jobs`}>{job.hostname || job.host_id.slice(0, 8)}</Link></td>
                    <td className="mono"><Link to={`/jobs/${job.id}`}>{job.action_type}</Link></td>
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
          actions={(
            <>
              {denied.length > 0 && <span className="badge error">{denied.length}</span>}
              <Link to="/audit?outcome=denied">{t("All denials")}</Link>
            </>
          )}
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
                    {/* The actor leads to their trail: one denial is a
                        typo, a run of them is somebody probing. */}
                    <td className="mono"><Link to={`/audit?actor=${encodeURIComponent(event.actor_id)}`}>{event.actor_id}</Link></td>
                    <td className="mono">{event.action}</td>
                    {/* The reason is a code with a guide on hover, the
                        way a job's error is: what it means and what to
                        do about it. */}
                    <td><DenialReason reason={event.detail?.reason} /></td>
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

/**
 * What the server's reasons for a refusal mean, for the hover: the code
 * stays on screen as the trail spells it, and the sentence says whether the
 * person lacked a right or the request came at the wrong moment.
 */
const DENIAL_MEANINGS: Record<string, string> = {
  permission_denied: "The person has no role that grants this operation.",
  invalid_state: "The object was not in a state that allows this: for example a cancel of a job that had already finished.",
  reason_required: "The request carried no reason, and this operation is not recorded without one.",
  target_confirmation_mismatch: "The name typed to confirm the target did not match it; nothing was done.",
  reauthentication_required: "The session was too old for this operation; a fresh sign-in is asked for first.",
  approval_stale: "The plan changed between the review and the approval; the approval was refused so nobody consents to a plan they have not read.",
  fingerprint_mismatch: "What was approved is not what stands now; the campaign has to be reviewed again.",
  forbidden: "The server refused the request for this person.",
};

function DenialReason({ reason }: { reason: unknown }) {
  const t = useT();
  if (reason === undefined || reason === null || reason === "") return <>—</>;
  const code = String(reason);
  const meaning = DENIAL_MEANINGS[code];
  return <code title={meaning ? t(meaning) : undefined}>{code}</code>;
}

/**
 * When the counters were last read from the server, with a way to read
 * them again now rather than at the next tick.
 */
function Refreshed({ at, fetching, onRefresh }: { at: number; fetching: boolean; onRefresh: () => void }) {
  const t = useT();
  return (
    <span className="source" data-testid="refreshed">
      {at > 0 ? t("refreshed {when}", { when: relativeTime(new Date(at).toISOString()) }) : t("not yet loaded")}
      {" · "}
      <button
        type="button"
        style={{ background: "none", border: 0, padding: 0, font: "inherit", color: "inherit", textDecoration: "underline dotted", cursor: "pointer" }}
        onClick={onRefresh}
        disabled={fetching}
      >
        {fetching ? t("refreshing…") : t("refresh now")}
      </button>
    </span>
  );
}
