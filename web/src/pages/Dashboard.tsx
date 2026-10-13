import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetActivity, FleetSummary, Job } from "../lib/types";
import { relativeTime } from "../lib/format";
import { ErrorBox, ErrorCode, Time, Empty, JobState } from "../components/ui";
import { Card, NeedsAttention, PageHeader, Section, Verdict } from "../components/layout";
import { BarChart, Breakdown, CountRow, StatusBar, type Segment } from "../components/widgets";
import { FleetCoverage, type Coverage } from "../components/FleetCoverage";
import { FirstRunCard } from "../components/FirstRunCard";
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
  operations_unconfirmed?: number;
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
  // The head of the answer comes with the checks: the sweep behind it has a
  // time budget, and a count taken over a part of the fleet says so.
  const security = useQuery({
    queryKey: ["security"],
    queryFn: () => api.get<{ checks: { failed: number; unknown: number }[] } & Coverage>("/api/v1/security"),
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
  // The two security segments are sums over the hosts the sweep judged. The
  // coverage line goes under the bar whenever that is not the whole fleet.
  const securityCoverage = security.data && (security.data.partial || security.data.unknown_hosts > 0)
    ? security.data
    : undefined;
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });
  // A facet the hosts have not reported is a badge, not a value named
  // "unknown" that reads like a system called that.
  const facetLabel = (key: string) => (key === "" || key === "unknown"
    ? <span className="badge unknown">{t("unknown")}</span>
    : key);

  // The window the failed-task counter covers, for the link to the list.
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const waiting = [
    s?.jobs_awaiting_approval, s?.campaigns_awaiting_approval, s?.campaigns_manual_gate,
    s?.directory_changes_pending, s?.hosts_drifted, s?.operations_unconfirmed,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  const attention = [
    s?.reboot_required, s?.with_failed_units, s?.package_database_broken, s?.sssd_offline,
    s?.helper_capability_legacy,
    s?.failed_jobs_24h, s?.pending_enrollment_requests, s?.agents_behind_latest,
    s?.agent_certificates_expiring, s?.agent_certificates_expired, s?.degraded_relays,
    s?.relays_buffer_high, s?.duplicate_identities_24h, s?.enrollment_refusals_1h, s?.agents_unsupported,
  ].reduce<number>((sum, value) => sum + (value ?? 0), 0);

  // What the fleet needs from a person, and what it has found wrong. The two
  // are counted apart: an approval is somebody's decision, a finding is a
  // state of a host.
  const decisions: Segment[] = s === undefined ? [] : ([
    { label: t("Jobs"), value: s.jobs_awaiting_approval, tone: "warn", to: "/jobs?state=awaiting_approval" },
    { label: t("Campaigns"), value: s.campaigns_awaiting_approval, tone: "warn", to: "/campaigns?state=awaiting_approval" },
    { label: t("Campaigns at a gate"), value: s.campaigns_manual_gate, tone: "warn", to: "/campaigns?state=manual_gate" },
    { label: t("Directory changes"), value: s.directory_changes_pending, tone: "warn", to: "/directory" },
    { label: t("Hosts drifted"), value: s.hosts_drifted, tone: "warn", to: "/policies" },
    { label: t("Unconfirmed outcomes"), value: s.operations_unconfirmed, tone: "warn", to: "/unresolved" },
    { label: t("Pending enrollments"), value: s.pending_enrollment_requests, tone: "warn", to: "/hosts/new" },
  ] as Segment[]).filter((count) => count.value !== undefined);

  const problems: Segment[] = ([
    { label: t("Failed jobs, 24 h"), value: s?.failed_jobs_24h, tone: "error", to: `/jobs?state=failed&since=${encodeURIComponent(dayAgo)}` },
    { label: t("Package database broken"), value: s?.package_database_broken, tone: "error", to: "/hosts?package_db_broken=true" },
    { label: t("Agent certificates expired"), value: s?.agent_certificates_expired, tone: "error", to: "/hosts?connection_refusal=certificate_expired" },
    { label: t("Degraded relays"), value: s?.degraded_relays, tone: "error", to: "/relays" },
    { label: t("Duplicate identities, 24 h"), value: s?.duplicate_identities_24h, tone: "error", to: "/audit?action=security.duplicate_identity" },
    { label: t("Agents unsupported"), value: s?.agents_unsupported, tone: "error", to: "/hosts?agent_behind=true" },
    { label: t("Reboot required"), value: s?.reboot_required, tone: "warn", to: "/hosts?reboot_required=true" },
    { label: t("With failed units"), value: s?.with_failed_units, tone: "warn", to: "/hosts?failed_units=true" },
    { label: t("Security updates pending"), value: s?.hosts_with_security_updates, tone: "warn", to: "/hosts?security_updates=true" },
    { label: t("Helper not on enforce"), value: s?.helper_capability_legacy, tone: "warn", to: "/hosts?helper_mode=prefer" },
    { label: t("SSSD offline"), value: s?.sssd_offline, tone: "warn", to: "/hosts?sssd_offline=true" },
    { label: t("Agent certificates expiring"), value: s?.agent_certificates_expiring, tone: "warn" },
    { label: t("Relay buffers high"), value: s?.relays_buffer_high, tone: "warn", to: "/relays" },
    { label: t("Enrollment refusals, 1 h"), value: s?.enrollment_refusals_1h, tone: "warn", to: "/audit?action=host.enroll&outcome=denied" },
    { label: t("Agents behind the newest"), value: s?.agents_behind_latest, tone: "warn", to: "/hosts?agent_behind=true" },
  ] as Segment[]).filter((count) => count.value !== undefined);

  // The security module answers for itself, and until it does its two counts
  // are absent rather than zero: they keep their place with a dash. A counter
  // the fleet summary left out is a different thing - it is one this reader
  // may not have, and it is left out here too.
  const findings: Segment[] = [
    { label: t("Security findings"), value: securityFailed, tone: "error", to: "/security" },
    ...problems,
    { label: t("Checks with no answer"), value: securityUnknown, tone: "unknown", to: "/security" },
  ];

  // The zone is drawn for something above zero, or for something nobody
  // could count. A fleet of zeros is answered by the verdict alone.
  const needsYou = [...decisions, ...findings]
    .some((count) => count.value === undefined || (count.value ?? 0) > 0);

  // The headline. A fleet with nothing waiting and nothing wrong says so in
  // one line, and that line is the whole answer somebody opened this for.
  const quiet = waiting === 0 && attention === 0;
  const headline = s === undefined
    ? t("Reading the fleet…")
    : quiet
      ? t("Nothing needs a decision")
      : waiting === 0
        ? t("{attention} things need a look")
        : attention === 0
          ? t("{waiting} decisions waiting")
          : t("{waiting} decisions waiting, {attention} things need a look");

  return (
    <>
      <PageHeader
        title={t("Fleet dashboard")}
        description={t("Only what needs a decision.")}
        help={
          <p>{t("Every counter here is taken in the database over the hosts you are allowed to see, not over a page of them. A counter the server could not answer honestly for your view is left out rather than drawn as zero, and a count at zero is a word under the row rather than a tile.")}</p>
        }
        actions={<Refreshed at={summary.dataUpdatedAt} fetching={summary.isFetching} onRefresh={() => summary.refetch()} />}
      />

      {/* An empty fleet is a panel on its first run, not a fleet with
          nothing wrong: the card reads the server's checklist, so the empty
          tiles below are not the whole answer and this screen keeps no
          account of the flow of its own. */}
      {s?.hosts === 0 && <FirstRunCard />}

      <Verdict
        tone={s === undefined ? "unknown" : quiet ? "ok" : attention > 0 ? "warn" : undefined}
        headline={t(headline, { waiting, attention })}
      >
        <span>{t("{n} hosts you can see", { n: s?.hosts ?? 0 })}</span>
        <span>{t("{n} online", { n: s?.online ?? 0 })}</span>
        {s?.quarantined_hosts ? <span>{t("{n} quarantined", { n: s.quarantined_hosts })}</span> : null}
        {s?.in_maintenance ? <span>{t("{n} in maintenance", { n: s.in_maintenance })}</span> : null}
      </Verdict>

      <NeedsAttention title={t("What needs you")}>
        {needsYou ? (
          <Card>
            {decisions.length > 0 && (
              <>
                <h4 className="widget-subhead first">{t("Decisions nobody has taken")}</h4>
                <CountRow counts={decisions} />
              </>
            )}
            {findings.length > 0 && (
              <>
                <h4 className="widget-subhead">{t("Found on the hosts")}</h4>
                <CountRow counts={findings} />
                <FleetCoverage coverage={securityCoverage} />
              </>
            )}
          </Card>
        ) : null}
      </NeedsAttention>

      {/* Where the fleet is, read across the room. */}
      <div className="widgets">
        {/* The size of the fleet is in the verdict above; the bar says where it is. */}
        <Card className="span-12" title={t("Host availability")}>
          <StatusBar segments={[
            { label: t("Online"), value: s?.online, tone: "ok", to: "/hosts?connection_state=online" },
            { label: t("Stale"), value: a ? byConnection("stale") ?? 0 : undefined, tone: "warn", to: "/hosts?connection_state=stale" },
            { label: t("Offline"), value: a ? byConnection("offline") ?? 0 : undefined, tone: "error", to: "/hosts?connection_state=offline" },
            { label: t("Unknown"), value: a ? byConnection("unknown") ?? 0 : undefined, tone: "unknown", to: "/hosts?connection_state=unknown" },
            { label: t("Quarantined"), value: s?.quarantined_hosts, tone: "neutral", to: "/hosts?lifecycle_state=quarantined" },
            { label: t("In maintenance"), value: s?.in_maintenance, tone: "neutral", to: "/hosts?maintenance=true" },
          ]} />
        </Card>

        <Card className="span-6" title={t("Operations, last 24 h")} description={t("Finished per hour, by outcome.")}>
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


        <Card className="span-6" title={t("Fleet composition")} description={t("By system, agent build, site and environment.")}>
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

        {/* The three lists the dashboard keeps. One line each until
            somebody opens them: a table nobody opened is a table nobody
            read, and three of them stacked is what made this screen a
            wall. The campaigns in progress open themselves, because work
            under way is the one list somebody is here to watch. */}
        <Card className="span-12" flush>
          <Section
            title={t("Campaigns in progress")}
            count={activeCampaigns.length}
            open={activeCampaigns.length > 0}
            className="list-section"
          >
          {activeCampaigns.length === 0 ? (
            <Empty>{t("No campaigns need attention.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th scope="col">{t("Name")}</th><th scope="col">{t("State")}</th><th scope="col">{t("Operation")}</th><th scope="col">{t("Pause reason")}</th></tr>
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
          </Section>
          <Section
            title={t("Recent failures")}
            count={(failures.data?.items ?? []).length}
            actions={<Link to="/jobs?state=failed">{t("All jobs")}</Link>}
            className="list-section"
          >
          {(failures.data?.items ?? []).length === 0 ? (
            <Empty>{t("No failed operations.")}</Empty>
          ) : (
            <table>
              <thead><tr><th scope="col">{t("Time")}</th><th scope="col">{t("Host")}</th><th scope="col">{t("Operation")}</th><th scope="col">{t("Error")}</th></tr></thead>
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
          </Section>
          <Section
            title={t("Recent access denials")}
            count={denied.length}
            actions={<Link to="/audit?outcome=denied">{t("All denials")}</Link>}
            className="list-section"
          >
          {denied.length === 0 ? (
            <Empty>{t("No denials in recent events.")}</Empty>
          ) : (
            <table>
              <thead><tr><th scope="col">{t("Time")}</th><th scope="col">{t("Actor")}</th><th scope="col">{t("Operation")}</th><th scope="col">{t("Reason")}</th></tr></thead>
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
          </Section>
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
      {/* The panel already has a button that reads as a link; this one
          carried its own copy of those declarations inline. */}
      <button type="button" className="link" onClick={onRefresh} disabled={fetching}>
        {fetching ? t("refreshing…") : t("refresh now")}
      </button>
    </span>
  );
}
