import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../../lib/api";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { relativeTime, absoluteTime } from "../../lib/format";
import type { AuditEvent, Campaign, FleetActivity, FleetSummary, Job } from "../../lib/types";
import { stateName } from "../../components/ui";
import { useT } from "../../i18n";
import {
  Band, Bars, Card, Chart, Empty, Head, Kpi, Pill, Problem, Ring, Table,
  type Segment, type Tone,
} from "../kit";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";

/**
 * What the fleet needs from a person, and what it found wrong.
 *
 * The screen answers one question - is there anything for me to do - and
 * everything on it is a way into the thing that needs doing. A counter
 * nobody could take is a dash and says so; a counter at zero is a word
 * under the row rather than a tile, because thirty tiles of nought is the
 * wall of text the owner threw this screen out for.
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

type Coverage = { partial?: boolean; unknown_hosts: number; hosts_judged?: number };

export function Dashboard() {
  const t = useT();
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<DecisionSummary>("/api/v1/fleet/summary"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const campaigns = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=100"),
  });
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const security = useQuery({
    queryKey: ["security"],
    queryFn: () => api.get<{ checks: { failed: number; unknown: number }[] } & Coverage>("/api/v1/security"),
    retry: false,
  });
  const failures = useQuery({
    queryKey: ["jobs", "recent-failures"],
    queryFn: () => api.get<Collection<Job>>("/api/v1/jobs?state=failed&limit=8"),
  });
  const denials = useQuery({
    queryKey: ["audit", "denied"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?outcome=denied&limit=10"),
  });

  if (summary.error) return <Problem>{String(summary.error)}</Problem>;

  const s = summary.data;
  const a = activity.data;
  const byConnection = (state: string) => a?.by_connection_state.find((one) => one.key === state)?.count;
  const securityFailed = security.data ? security.data.checks.reduce((sum, one) => sum + one.failed, 0) : undefined;
  const securityUnknown = security.data ? security.data.checks.reduce((sum, one) => sum + one.unknown, 0) : undefined;
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const waiting = [
    s?.jobs_awaiting_approval, s?.campaigns_awaiting_approval, s?.campaigns_manual_gate,
    s?.directory_changes_pending, s?.hosts_drifted, s?.operations_unconfirmed,
  ].reduce<number>((sum, one) => sum + (one ?? 0), 0);

  const found = [
    s?.reboot_required, s?.with_failed_units, s?.package_database_broken, s?.sssd_offline,
    s?.helper_capability_legacy, s?.failed_jobs_24h, s?.pending_enrollment_requests,
    s?.agents_behind_latest, s?.agent_certificates_expiring, s?.agent_certificates_expired,
    s?.degraded_relays, s?.relays_buffer_high, s?.duplicate_identities_24h,
    s?.enrollment_refusals_1h, s?.agents_unsupported,
  ].reduce<number>((sum, one) => sum + (one ?? 0), 0);

  /* An approval is somebody's decision; a finding is a state of a host.
     They are counted apart because they are answered apart. */
  const decisions: Need[] = [
    { label: t("Jobs awaiting approval"), value: s?.jobs_awaiting_approval, tone: "warn", to: "/jobs?state=awaiting_approval" },
    { label: t("Campaigns awaiting approval"), value: s?.campaigns_awaiting_approval, tone: "warn", to: "/campaigns?state=awaiting_approval" },
    { label: t("Campaigns at a gate"), value: s?.campaigns_manual_gate, tone: "warn", to: "/campaigns?state=manual_gate" },
    { label: t("Directory changes"), value: s?.directory_changes_pending, tone: "warn", to: "/directory" },
    { label: t("Hosts drifted"), value: s?.hosts_drifted, tone: "warn", to: "/policies" },
    { label: t("Unconfirmed outcomes"), value: s?.operations_unconfirmed, tone: "warn", to: "/unresolved" },
    { label: t("Pending enrollments"), value: s?.pending_enrollment_requests, tone: "warn", to: "/hosts/new" },
  ];

  const findings: Need[] = [
    { label: t("Security findings"), value: securityFailed, tone: "error", to: "/security" },
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
    { label: t("Checks with no answer"), value: securityUnknown, tone: "unknown", to: "/security" },
  ];

  const all = [...decisions, ...findings].filter((one) => one.value !== undefined || one.tone === "unknown");
  const open = all.filter((one) => one.value === undefined || (one.value ?? 0) > 0);
  const clear = all.filter((one) => one.value === 0).length;
  const coverage = security.data && (security.data.partial || security.data.unknown_hosts > 0) ? security.data : undefined;

  const active = (campaigns.data?.items ?? []).filter((one) =>
    ["planning", "planned", "awaiting_approval", "canary", "manual_gate", "running", "pausing", "paused"].includes(one.state));
  const denied = denials.data?.items ?? [];
  const hour = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });
  const facet = (key: string) => (key === "" || key === "unknown" ? t("unknown") : key);

  const availability: Segment[] = [
    { label: t("Online"), value: s?.online, tone: "ok", to: "/next/hosts?connection_state=online" },
    { label: t("Stale"), value: a ? byConnection("stale") ?? 0 : undefined, tone: "warn", to: "/next/hosts?connection_state=stale" },
    { label: t("Offline"), value: a ? byConnection("offline") ?? 0 : undefined, tone: "error", to: "/next/hosts?connection_state=offline" },
    { label: t("Unknown"), value: a ? byConnection("unknown") ?? 0 : undefined, tone: "unknown", to: "/next/hosts?connection_state=unknown" },
    { label: t("Quarantined"), value: s?.quarantined_hosts, tone: "neutral" },
    { label: t("In maintenance"), value: s?.in_maintenance, tone: "neutral" },
  ];

  return (
    <>
      <Head
        title={t("Fleet dashboard")}
        lead={t("Only what needs a decision.")}
        actions={
          <>
            <span className="fl-note" data-testid="refreshed">
              {summary.dataUpdatedAt > 0
                ? t("refreshed {when}", { when: relativeTime(new Date(summary.dataUpdatedAt).toISOString()) })
                : t("not yet loaded")}
            </span>
            <button type="button" className="fl-quiet" onClick={() => summary.refetch()} disabled={summary.isFetching}>
              {summary.isFetching ? t("refreshing…") : t("Refresh")}
            </button>
          </>
        }
      />

      <Board screen="next-dashboard" catalogue={DASHBOARD} drawn={{
        hosts: <Kpi icon="hosts" label={t("Hosts")} value={s?.hosts ?? null} hero />,
        online: (
          <Kpi
            icon="server"
            label={t("Online")}
            value={s?.online ?? null}
            tone={s && s.offline > 0 ? "warn" : "ok"}
            delta={s === undefined ? undefined : {
              text: t("{n} offline", { n: s.offline }),
              direction: s.offline > 0 ? "down" : "up",
              good: s.offline === 0,
            }}
          />
        ),
        waiting: (
          <Kpi
            icon="jobs"
            label={t("Waiting on a person")}
            value={s === undefined ? null : waiting}
            tone={waiting > 0 ? "warn" : "ok"}
            note={waiting > 0 ? t("approvals, gates and confirmations") : t("nothing waits")}
          />
        ),
        found: (
          <Kpi
            icon="security"
            label={t("Found on the hosts")}
            value={s === undefined ? null : found}
            tone={found > 0 ? "error" : "ok"}
            note={found > 0 ? t("across every check the fleet answers") : t("every check is clear")}
          />
        ),
        needs: (
          <Card
            title={t("What needs you")}
            note={coverage ? t("Judged over {n} hosts; the rest have not answered.", { n: coverage.hosts_judged ?? 0 }) : undefined}
            tools={open.length > 0 ? <Pill tone="warn">{open.length}</Pill> : undefined}
            foot={clear > 0 ? t("{n} other checks are clear.", { n: clear }) : undefined}
          >
            {open.length === 0
              ? <Empty>{t("Nothing waits and nothing is wrong.")}</Empty>
              : <Needs items={open} />}
          </Card>
        ),
        answering: (
          <Card title={t("Fleet answering")} note={t("The share of the fleet the panel has heard from.")}>
            <Ring
              share={s && s.hosts > 0 ? s.online / s.hosts : undefined}
              label={t("online")}
              tone={s && s.offline > 0 ? "warn" : "ok"}
              legend={[
                { label: t("Online"), value: s?.online ?? "—", tone: "ok" },
                { label: t("Stale"), value: a ? byConnection("stale") ?? 0 : "—", tone: "warn" },
                { label: t("Offline"), value: a ? byConnection("offline") ?? 0 : "—", tone: "error" },
                { label: t("Unknown"), value: a ? byConnection("unknown") ?? 0 : "—", tone: "unknown" },
              ]}
            />
          </Card>
        ),
        availability: (
          <Card title={t("Host availability")}>
            <Band segments={availability} testId="availability" />
          </Card>
        ),
        operations: (
          <Card title={t("Operations, last 24 h")} note={t("Finished per hour, by outcome.")}>
            {a ? (
              <Chart
                labels={a.hours.map(hour)}
                series={[
                  { name: t("Succeeded"), tone: "ok", values: a.succeeded },
                  { name: t("Failed"), tone: "error", values: a.failed },
                  { name: t("Other"), tone: "unknown", values: a.other },
                ]}
              />
            ) : <Empty>{t("Loading…")}</Empty>}
          </Card>
        ),
        composition: (
          <Card title={t("Fleet composition")} note={t("By system, agent build, site and environment.")}>
            {a ? (
              <div className="fl-stack">
                <Composition label={t("Systems")} items={a.by_os_family.map((f) => ({ label: facet(f.key), value: f.count, tone: "accent" as Tone }))} />
                <Composition label={t("Agent builds")} items={a.by_agent_version.map((f) => ({ label: facet(f.key), value: f.count, tone: "neutral" as Tone }))} />
                <Composition label={t("Sites")} items={a.by_site.map((f) => ({ label: facet(f.key), value: f.count, tone: "info" as Tone }))} />
                <Composition label={t("Environments")} items={a.by_environment.map((f) => ({ label: facet(f.key), value: f.count, tone: "info" as Tone }))} />
              </div>
            ) : <Empty>{t("Loading…")}</Empty>}
          </Card>
        ),
        campaigns: (
          <Card
            title={t("Campaigns in progress")}
            tools={active.length > 0 ? <Pill tone="info">{active.length}</Pill> : undefined}
            flush
          >
            <Table
              rows={active}
              keyOf={(one) => one.id}
              empty={t("No campaigns need attention.")}
              columns={[
                { key: "name", head: t("Name"), cell: (one) => <Link to={`/campaigns/${one.id}`}>{one.name}</Link> },
                { key: "state", head: t("State"), cell: (one) => <Pill tone={campaignTone(one.state)}>{t(stateName(one.state))}</Pill> },
                { key: "action", head: t("Operation"), minor: true, cell: (one) => <code>{one.action_type}</code> },
              ]}
            />
          </Card>
        ),
        failures: (
          <Card
            title={t("Recent failures")}
            tools={<Link to="/next/jobs?state=failed">{t("All jobs")}</Link>}
            flush
          >
            <Table
              rows={failures.data?.items ?? []}
              keyOf={(one) => one.id}
              empty={t("No failed operations.")}
              columns={[
                { key: "when", head: t("Time"), cell: (one) => (
                  <Link to={`/jobs/${one.id}`} title={absoluteTime(one.finished_at ?? one.created_at)}>
                    {relativeTime(one.finished_at ?? one.created_at)}
                  </Link>
                ) },
                { key: "host", head: t("Host"), cell: (one) => (
                  <Link to={`/next/hosts/${one.host_id}`}>{one.hostname || one.host_id.slice(0, 8)}</Link>
                ) },
                { key: "what", head: t("Operation"), minor: true, cell: (one) => <code>{one.action_type}</code> },
                { key: "error", head: t("Error"), cell: (one) => <code>{one.result_error_code || "failed"}</code> },
              ]}
            />
          </Card>
        ),
        denials: (
          <Card
            title={t("Recent access denials")}
            tools={
              <>
                {denied.length > 0 && <Pill tone="error">{denied.length}</Pill>}
                <Link to="/next/audit?outcome=denied">{t("All denials")}</Link>
              </>
            }
            flush
          >
            <Table
              rows={denied}
              keyOf={(one) => String(one.id)}
              empty={t("No denials in recent events.")}
              columns={[
                { key: "when", head: t("Time"), cell: (one) => (
                  <span title={absoluteTime(one.occurred_at)}>{relativeTime(one.occurred_at)}</span>
                ) },
                { key: "actor", head: t("Actor"), cell: (one) => (
                  <Link to={`/next/audit?actor=${encodeURIComponent(one.actor_id)}`} className="fl-mono">{one.actor_id}</Link>
                ) },
                { key: "action", head: t("Operation"), cell: (one) => <code>{one.action}</code> },
                { key: "reason", head: t("Reason"), minor: true, cell: (one) => (
                  one.detail?.reason ? <code>{String(one.detail.reason)}</code> : <>—</>
                ) },
              ]}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * The containers this screen can draw: the name each is picked by when the
 * screen is arranged, and the width and height it takes until somebody
 * says otherwise.
 */
export const DASHBOARD: BoardEntry[] = [
  { key: "hosts", title: "Hosts", width: 3, height: 2 },
  { key: "online", title: "Online", width: 3, height: 2 },
  { key: "waiting", title: "Waiting on a person", width: 3, height: 2 },
  { key: "found", title: "Found on the hosts", width: 3, height: 2 },
  { key: "needs", title: "What needs you", width: 8, height: 5 },
  { key: "answering", title: "Fleet answering", width: 4, height: 5 },
  { key: "availability", title: "Host availability", width: 4, height: 3 },
  { key: "operations", title: "Operations, last 24 h", width: 8, height: 4 },
  { key: "composition", title: "Fleet composition", width: 4, height: 7 },
  { key: "campaigns", title: "Campaigns in progress", width: 4, height: 4 },
  { key: "failures", title: "Recent failures", width: 4, height: 4 },
  { key: "denials", title: "Recent access denials", width: 12, height: 4 },
];

type Need = { label: string; value?: number; tone: Tone; to?: string };

/**
 * The things that need somebody, as a list rather than a field of tiles:
 * the count, what it is, and the way to it. Read down in one pass.
 */
function Needs({ items }: { items: Need[] }) {
  const t = useT();
  return (
    <ul className="fl-needs">
      {items.map((one) => {
        const body = (
          <>
            <span className={`fl-needs-count fl-${one.tone}`}>{one.value === undefined ? "—" : one.value}</span>
            <span className="fl-needs-label">{one.label}</span>
            {one.value === undefined && <span className="fl-faint">{t("not counted")}</span>}
          </>
        );
        return (
          <li key={one.label}>
            {one.to ? <Link to={`/next${one.to}`} className="fl-needs-row">{body}</Link> : <span className="fl-needs-row">{body}</span>}
          </li>
        );
      })}
    </ul>
  );
}

/** One dimension of the fleet: a heading, then the bars under it. */
function Composition({ label, items }: { label: string; items: { label: string; value: number; tone: Tone }[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="fl-subhead">{label}</h3>
      <Bars items={items} />
    </div>
  );
}

/** The state of a campaign as a tone: running is work, paused is a person. */
function campaignTone(state: string): Tone {
  if (["completed", "succeeded", "active"].includes(state)) return "ok";
  if (["failed", "plan_failed", "canceled"].includes(state)) return "error";
  if (["awaiting_approval", "manual_gate", "paused", "pausing"].includes(state)) return "warn";
  return "info";
}
