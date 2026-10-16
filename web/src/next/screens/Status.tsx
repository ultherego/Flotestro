import { useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { copyToClipboard } from "../../lib/clipboard";
import { absoluteTime, bytes, duration, goDuration, relativeTime } from "../../lib/format";
import { useT } from "../../i18n";
import type { Translate } from "../../i18n";
import {
  Band, Banner, Bars, Bones, Card, Chart, Empty, Fact, Facts, Feed, FeedRow, Grid, Kpi, Kpis,
  Note, Pie, Pill, Problem, Ring, Screen, type Segment, type Series, Squares, Stack, Table,
  type Tone,
} from "../kit";

/**
 * The condition of the installation itself: is it the database, the
 * publisher, the scheduler or a feed that is not well.
 *
 * Every part is judged by the control plane and nothing here is judged by
 * the browser. A part the server could not judge is drawn as unknown and
 * counted apart - a panel nobody could ask is not a panel that passed, and
 * the verdict at the top says so rather than rounding it down to fine.
 *
 * The series under the cards are the readings this screen itself took
 * while it was open. The server keeps no history of its own condition, so
 * the chart says how long it has been watching rather than pretending to
 * reach back before the page was opened.
 */

/** How often the screen asks again; an incident moves faster than a page reload. */
export const STATUS_REFRESH_INTERVAL = 15_000;

/** How many readings the session history keeps: a quarter of an hour at this interval. */
export const HISTORY_POINTS = 60;

/* The shape of the answer, local to the screen: no other page reads it. */
export type StatusBlock = {
  ok: boolean | null;
  reason?: string;
  attention?: string;
  facts: Record<string, unknown>;
};

export type StatusView = {
  generated_at: string;
  ok: boolean;
  unknown: number;
  blocks: Record<string, StatusBlock>;
  links: { openapi: string; metrics: string };
};

type OutboxConsumer = { name: string; behind: number; failures: number; last_error?: string; updated_at: string };
type VulnerabilityFeed = { provider: string; age_seconds: number; stale: boolean; advisories: number; error?: string };

/** One reading this screen took, kept so a figure can say where it is going. */
export type Reading = { at: number; latency?: number; pending?: number };

/** The tone of a block: red when not fine, amber when fine with a note, grey when unknown. */
export function blockTone(block: Pick<StatusBlock, "ok" | "attention">): Tone {
  if (block.ok === null || block.ok === undefined) return "unknown";
  if (!block.ok) return "error";
  return block.attention ? "warn" : "ok";
}

/** The order the blocks stand in: what breaks the panel first comes first. */
const BLOCK_ORDER = [
  "database", "replicas", "migrations", "crypto", "outbox", "scheduler", "sessions", "relays",
  "directory", "vulnerability_feeds", "certificates", "monitoring", "housekeeping",
];

const BLOCK_TITLES: Record<string, string> = {
  database: "Database",
  replicas: "Replicas",
  crypto: "Cryptographic state",
  migrations: "Schema",
  outbox: "Durable trail",
  scheduler: "Scheduler",
  sessions: "Sessions",
  relays: "Relays",
  directory: "Directory connector",
  vulnerability_feeds: "Vulnerability feeds",
  certificates: "Certificates",
  monitoring: "Monitoring",
  housekeeping: "Housekeeping",
  build: "About",
};

/** How a value is drawn once its key is known. */
type FactKind = "text" | "number" | "bytes" | "seconds" | "ms" | "time" | "flag" | "duration" | "id";

/* The label of each fact and how its value is drawn. A key without a
   label is shown as it is, so a new fact of the server is visible before
   the screen learns its name. */
const FACT_LABELS: Record<string, [string, FactKind]> = {
  settings_stored: ["Settings stored in the panel", "flag"],
  settings_updated_at: ["Settings stored at", "time"],
  settings_updated_by: ["Settings stored by", "text"],
  lock_waiters: ["Backends waiting on a lock", "number"],
  locks_ungranted: ["Locks not granted", "number"],
  lock_wait_seconds_max: ["Longest lock wait", "seconds"],
  wal_lsn: ["WAL position", "text"],
  wal_bytes_total: ["WAL written", "bytes"],
  wal_bytes_per_second: ["WAL rate", "bytes"],
  inserts_total: ["Rows inserted", "number"],
  inserts_per_second: ["Insert rate", "number"],
  raw_partitioned: ["Raw samples partitioned", "flag"],
  raw_partitions: ["Raw partitions", "number"],
  oldest_raw_day: ["Oldest raw day", "time"],
  newest_raw_day: ["Newest raw day", "time"],
  dirty_buckets: ["Buckets to recompute", "number"],
  oldest_dirty_bucket_at: ["Oldest waiting bucket", "time"],
  hosts_with_rollup_mark: ["Hosts with a rollup mark", "number"],
  sample_identities: ["Sample identities", "number"],
  raw_retention: ["Raw retention", "duration"],
  rollup_retention: ["Rollup retention", "duration"],
  max_lateness: ["Maximum lateness", "duration"],
  raw_query_window: ["Raw query window", "duration"],
  clock_skew_limit: ["Clock skew limit", "duration"],
  partitions_ahead_days: ["Partitions ahead", "number"],
  evaluator_holder: ["Evaluator holder", "text"],
  evaluator_lease_until: ["Evaluator lease until", "time"],
  reachable: ["Reachable", "flag"],
  latency_ms: ["Round trip", "ms"],
  size_bytes: ["Size", "bytes"],
  connections_used: ["Server connections", "number"],
  connections_max: ["Server connection limit", "number"],
  pool_used: ["Pool connections", "number"],
  pool_max: ["Pool limit", "number"],
  replicas_seen: ["Replicas alive", "number"],
  connections_per_replica: ["Connections per replica", "number"],
  connections_claimed: ["Connections claimed", "number"],
  server_max_connections: ["Server max_connections", "number"],
  server_reserved_connections: ["Reserved for superusers", "number"],
  connections_available: ["Connections available", "number"],
  connections_in_use: ["Connections in use", "number"],
  connections_headroom: ["Headroom", "number"],
  next_replica_fits: ["Another replica fits", "flag"],
  next_replica_shortfall: ["Shortfall for the next replica", "number"],
  instance_stale_after: ["Instance dead after", "duration"],
  replicas_without_a_pool: ["Replicas without a declared pool", "number"],
  pool_min: ["Pool minimum", "number"],
  pool_idle: ["Idle connections", "number"],
  pool_max_conn_lifetime: ["Connection lifetime", "duration"],
  pool_max_conn_idle_time: ["Idle limit", "duration"],
  pool_health_check_period: ["Health check period", "duration"],
  pool_connect_timeout: ["Connect timeout", "duration"],
  pool_empty_acquires: ["Waits for a free connection", "number"],
  oldest_transaction_seconds: ["Oldest transaction", "seconds"],
  server_version: ["Server version", "text"],
  error: ["Error", "text"],
  level: ["Level", "number"],
  latest: ["Latest migration", "text"],
  applied: ["Applied migrations", "number"],
  pending: ["Events waiting", "number"],
  set_aside: ["Events set aside", "number"],
  oldest_set_aside_seconds: ["Oldest set aside", "seconds"],
  oldest_pending_seconds: ["Oldest waiting", "seconds"],
  last_published_at: ["Last published", "time"],
  dispatch_rate: ["Dispatch rate (per second)", "number"],
  oldest_queued_seconds: ["Oldest queued", "seconds"],
  configured: ["Configured", "flag"],
  principal: ["Service principal", "text"],
  keytab_readable: ["Keytab read", "flag"],
  last_success_at: ["Last success", "time"],
  last_error: ["Last error", "text"],
  last_error_at: ["Last error at", "time"],
  last_refusal: ["Last refusal", "text"],
  last_refusal_at: ["Last refusal at", "time"],
  cache_entries: ["Cache entries", "number"],
  enabled: ["Enabled", "flag"],
  max_snapshot_age_seconds: ["Maximum snapshot age", "seconds"],
  ca_subject: ["Fleet CA", "text"],
  ca_not_after: ["CA expires", "time"],
  authorities: ["Authorities in the trust set", "number"],
  agents_expiring_7d: ["Hosts expiring within 7 days", "number"],
  agents_expiring_30d: ["Hosts expiring within 30 days", "number"],
  last_sweep_at: ["Last sweep", "time"],
  total: ["Relays", "number"],
  degraded: ["Degraded", "number"],
  /* The cryptographic state. Every one of these used to be drawn under its
     own key, and the three identifiers ran out of the card. */
  installation_id: ["Installation", "id"],
  provider: ["Key provider", "text"],
  recorded_provider: ["Provider in the record", "text"],
  active_key_id: ["Active key", "id"],
  issuer_id: ["Issuer", "id"],
  issuer_fingerprint: ["Issuer fingerprint", "id"],
  kek_id: ["Key encryption key", "id"],
  revision: ["Revision", "number"],
  initialized_at: ["Initialised", "time"],
  keys: ["Keys", "text"],
  versions_by_key: ["Versions per key", "text"],
  pending_rewrap: ["Rows waiting to be re-sealed", "number"],
  unreadable_versions: ["Versions this installation cannot open", "number"],
  initialised: ["Initialised", "flag"],
  adopted: ["Adopted", "flag"],
  /* The replicas of the control plane. */
  gateway_id: ["This gateway", "id"],
  replicas: ["Replicas", "text"],
};

/* What the housekeeping sweeps, named as the settings screen names the
   retention of the same thing; a kind the screen does not know is shown
   as it came. */
const HOUSEKEEPING_KINDS: Record<string, string> = {
  agent_sessions: "Ended agent sessions",
  audit_events: "Audit trail",
  campaigns: "Finished campaigns",
  jobs: "Finished jobs",
  outbox_events: "Delivered trail events",
  metrics_raw: "Raw resource samples",
  metrics_rollup: "Quarter-hour rollups",
};

/* The keys a drawing takes instead of a row, so the row is not repeated.
   The days until the CA expires are in the expiry time itself, and the
   total of the relays is the sum of the segments above it. */
const DRAWN_ELSEWHERE = new Set([
  "consumers", "feeds", "removed", "retention", "ca_expires_in_days", "total",
  "awaiting_approval", "queued", "leased", "dispatched", "running",
  "agents_on_this_gateway", "hosts_online", "hosts_stale", "web_sessions",
  "active", "silent", "never_seen", "revoked",
]);

/** A fact read as a number, or nothing at all where the server did not say. */
export function numberFact(facts: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = facts?.[key];
  return typeof value === "number" ? value : undefined;
}

export function Status() {
  const t = useT();
  const { data, error, dataUpdatedAt } = useQuery({
    queryKey: ["status"],
    queryFn: () => api.get<StatusView>("/api/v1/status"),
    refetchInterval: STATUS_REFRESH_INTERVAL,
    retry: false,
  });
  const [copied, setCopied] = useState(false);
  // What this screen has watched since it was opened. The server keeps no
  // history of its own condition, so a line over time can only be the
  // readings taken here - and it is labelled as such.
  const [history, setHistory] = useState<Reading[]>([]);

  useEffect(() => {
    if (!data || !dataUpdatedAt) return;
    const point: Reading = {
      at: dataUpdatedAt,
      latency: numberFact(data.blocks.database?.facts, "latency_ms"),
      pending: numberFact(data.blocks.outbox?.facts, "pending"),
    };
    setHistory((past) => (past[past.length - 1]?.at === point.at ? past : [...past, point].slice(-HISTORY_POINTS)));
  }, [data, dataUpdatedAt]);

  const copyDiagnostics = () => {
    if (!data) return;
    // A bundle reported as copied and not copied is pasted as whatever was on
    // the clipboard before - into a ticket, as the state of somebody's fleet.
    void copyToClipboard(JSON.stringify(data, null, 2)).then((done) => {
      setCopied(done);
      if (done) window.setTimeout(() => setCopied(false), 3000);
    });
  };

  const blocks = data ? BLOCK_ORDER.filter((key) => data.blocks[key]) : [];
  const toneOf = (key: string) => blockTone(data!.blocks[key]);
  // What the reader has to do something about, named at the top. The same
  // parts stand open below; this card is how they are found without
  // reading all thirteen headings.
  const wanting = data ? blocks.filter((key) => toneOf(key) !== "ok") : [];
  const count = (tone: Tone) => (data ? blocks.filter((key) => toneOf(key) === tone).length : null);

  const latency = numberFact(data?.blocks.database?.facts, "latency_ms");
  const poolUsed = numberFact(data?.blocks.database?.facts, "pool_used");
  const poolMax = numberFact(data?.blocks.database?.facts, "pool_max");
  const poolShare = poolUsed !== undefined && poolMax !== undefined && poolMax > 0 ? poolUsed / poolMax : undefined;

  const latencySeries = history.filter((one) => one.latency !== undefined);
  const pendingSeries = history.filter((one) => one.pending !== undefined);
  const clock = (at: number) => new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  return (
    <Screen
      icon="settings"
      title={t("Status")}
      lead={t("The condition of this panel, judged by the server.")}
      help={
        <p>
          {t("Every part of the panel is judged by the control plane itself and read again every {n} seconds. A part that cannot be judged is counted as unknown, which is not the same as fine: a reading nobody could take says so rather than passing. The parts that need a look are named first, and every part is open underneath with everything the server said about it; the lines over time are the readings this screen has taken since it was opened, because the server keeps no history of its own condition.", { n: STATUS_REFRESH_INTERVAL / 1000 })}
        </p>
      }
      actions={
        <>
          <a className="fl-quiet fl-small" href={data?.links?.openapi ?? "/api/v1/openapi.json"} target="_blank" rel="noreferrer">
            {t("OpenAPI")}
          </a>
          <a className="fl-quiet fl-small" href={data?.links?.metrics ?? "/metrics"} target="_blank" rel="noreferrer">
            {t("Metrics")}
          </a>
          <button type="button" className="fl-quiet fl-small" onClick={copyDiagnostics} disabled={!data} data-testid="copy-diagnostics">
            {copied ? t("Copied") : t("Copy diagnostics")}
          </button>
        </>
      }
      banner={data && (
        <Banner tone={data.ok ? (data.unknown > 0 ? "warn" : "ok") : "error"}>
          {data.ok
            ? data.unknown > 0
              ? t("Every judged part of this panel is fine, and {n} of {total} could not be judged at all.", { n: data.unknown, total: blocks.length })
              : t("Every one of the {total} parts of this panel was judged, and every one is fine.", { total: blocks.length })
            : t("A part of this panel is not fine. Judged {when}, read at {read}.", {
                when: relativeTime(data.generated_at),
                read: dataUpdatedAt ? absoluteTime(new Date(dataUpdatedAt).toISOString()) : "—",
              })}
        </Banner>
      )}
    >
      {error && <Problem>{String(error)}</Problem>}
      {!error && !data && <Bones rows={6} />}

      {data && (
        <>
          <Kpis>
            <Kpi
              hero
              icon="settings"
              label={t("Parts judged")}
              value={blocks.length - data.unknown}
              note={t("of {total} the server reports", { total: blocks.length })}
              testId="kpi-judged"
            />
            <Kpi
              icon="check"
              label={t("Fine")}
              value={count("ok")}
              tone="ok"
              note={t("nothing to do about these")}
              testId="kpi-fine"
            />
            <Kpi
              icon="help"
              label={t("Need a look")}
              value={wanting.length - (count("unknown") ?? 0)}
              tone={wanting.length - (count("unknown") ?? 0) > 0 ? "error" : "ok"}
              note={t("not fine, or fine with a note")}
              testId="kpi-wanting"
            />
            <Kpi
              icon="overview"
              label={t("Not judged")}
              value={data.unknown}
              tone={data.unknown > 0 ? "unknown" : "ok"}
              note={t("unknown is not the same as fine")}
              testId="kpi-unknown"
            />
            <Kpi
              icon="monitoring"
              label={t("Database round trip")}
              value={latency === undefined ? null : latency.toFixed(1)}
              unit="ms"
              note={t("as the server last measured it")}
              spark={latencySeries.length > 1 ? latencySeries.map((one) => one.latency ?? 0) : undefined}
              testId="kpi-latency"
            />
          </Kpis>

          <Grid>
            <Card
              span={4}
              title={t("How the parts divide")}
              note={t("What nobody could judge is a slice like any other, not an absence.")}
            >
              <Pie
                testId="status-division"
                total={blocks.length}
                label={t("parts")}
                slices={[
                  { label: t("Fine"), value: count("ok") ?? 0, tone: "ok" },
                  { label: t("Attention"), value: count("warn") ?? 0, tone: "warn" },
                  { label: t("Not fine"), value: count("error") ?? 0, tone: "error" },
                  { label: t("Not judged"), value: count("unknown") ?? 0, tone: "unknown" },
                ]}
              />
            </Card>

            <Card
              span={4}
              title={t("Every part at a glance")}
              note={t("One square per part, in the order a failure reaches the operator.")}
            >
              <Squares
                testId="status-squares"
                items={blocks.map((key) => ({
                  key,
                  tone: toneOf(key),
                  title: `${t(BLOCK_TITLES[key] ?? key)} · ${verdictWord(toneOf(key), t)}`,
                }))}
                tally={[
                  { label: t("fine"), value: count("ok") ?? "—", tone: "ok" },
                  { label: t("attention"), value: count("warn") ?? "—", tone: "warn" },
                  { label: t("not fine"), value: count("error") ?? "—", tone: "error" },
                  { label: t("not judged"), value: count("unknown") ?? "—", tone: "unknown" },
                ]}
              />
            </Card>

            <Card
              span={4}
              title={t("The database pool")}
              note={t("How much of this gateway's own pool of connections is taken. A pool the server did not report draws no arc.")}
            >
              <Ring
                share={poolShare}
                label={t("of the pool")}
                tone={poolShare === undefined ? "unknown" : poolShare > 0.85 ? "error" : poolShare > 0.7 ? "warn" : "ok"}
                legend={[
                  { label: t("In use"), value: poolUsed ?? "—" },
                  { label: t("Limit"), value: poolMax ?? "—" },
                  { label: t("Idle"), value: numberFact(data.blocks.database?.facts, "pool_idle") ?? "—" },
                  { label: t("Waits for a free connection"), value: numberFact(data.blocks.database?.facts, "pool_empty_acquires") ?? "—" },
                ]}
              />
            </Card>

            <Card
              span={12}
              title={t("Parts that need a look")}
              note={t("Everything that is not plainly fine, with the reason the server gave.")}
              flush
            >
              {wanting.length === 0
                ? <Empty>{t("Every part of this panel was judged and every one is fine.")}</Empty>
                : (
                  <Feed>
                    {wanting.map((key) => (
                      <FeedRow
                        key={key}
                        icon="settings"
                        tone={toneOf(key)}
                        what={t(BLOCK_TITLES[key] ?? key)}
                        who={data.blocks[key].reason || data.blocks[key].attention || t("judged as unknown")}
                        when={verdictWord(toneOf(key), t)}
                      />
                    ))}
                  </Feed>
                )}
            </Card>

            <Card
              span={12}
              title={t("Since this screen was opened")}
              note={t("The readings this screen took, one every {n} seconds. The server keeps no history of its own condition, so nothing here reaches back before the page was opened.", { n: STATUS_REFRESH_INTERVAL / 1000 })}
            >
              {latencySeries.length < 2 && pendingSeries.length < 2
                ? <Note>{t("One reading so far. A line appears with the second.")}</Note>
                : (
                  <Stack>
                    {latencySeries.length > 1 && (
                      <Chart
                        testId="latency-chart"
                        shape="area"
                        height={120}
                        everyLabel={Math.max(1, Math.ceil(latencySeries.length / 8))}
                        labels={latencySeries.map((one) => clock(one.at))}
                        series={[{ name: t("Round trip, ms"), tone: "accent", values: latencySeries.map((one) => one.latency ?? 0) } as Series]}
                      />
                    )}
                    {pendingSeries.length > 1 && (
                      <Chart
                        testId="pending-chart"
                        shape="line"
                        height={120}
                        everyLabel={Math.max(1, Math.ceil(pendingSeries.length / 8))}
                        labels={pendingSeries.map((one) => clock(one.at))}
                        series={[{ name: t("Events waiting in the trail"), tone: "info", values: pendingSeries.map((one) => one.pending ?? 0) } as Series]}
                      />
                    )}
                  </Stack>
                )}
            </Card>

            {blocks.map((key) => (
              <Block key={key} name={key} block={data.blocks[key]} />
            ))}

            {data.blocks.build && <About block={data.blocks.build} />}
          </Grid>
        </>
      )}
    </Screen>
  );
}

/** The verdict of a part in the word an operator reads it as. */
export function verdictWord(tone: Tone, t: Translate): string {
  return tone === "ok" ? t("fine") : tone === "warn" ? t("attention") : tone === "error" ? t("not fine") : t("unknown");
}

/**
 * One part of the panel: its name, its verdict, the one fact worth reading
 * first, the drawing that part has, and then everything the server said.
 */
function Block({ name, block }: { name: string; block: StatusBlock }) {
  const t = useT();
  const tone = blockTone(block);
  const rows = Object.entries(block.facts).filter(([key]) => !DRAWN_ELSEWHERE.has(key));
  const summary = blockSummary(name, block.facts, t);
  return (
    <Card
      span={4}
      title={t(BLOCK_TITLES[name] ?? name)}
      note={summary || undefined}
      tools={<Pill tone={tone}>{verdictWord(tone, t)}</Pill>}
    >
      <Stack>
        {(block.reason || block.attention) && <Note>{block.reason || block.attention}</Note>}
        <BlockDrawing name={name} facts={block.facts} />
        {rows.length > 0 && (
          <Facts>
            {rows.map(([key, value]) => {
              const [label, kind] = FACT_LABELS[key] ?? [key, "text"];
              return <Fact key={key} label={t(label)}><Value value={value} kind={kind} /></Fact>;
            })}
          </Facts>
        )}
      </Stack>
    </Card>
  );
}

/**
 * The one fact of a part that is worth reading beside its name. Without it
 * a card says only its own name until the reader goes through its facts.
 */
export function blockSummary(name: string, facts: Record<string, unknown>, t: Translate): string {
  const number = (key: string): number | undefined => numberFact(facts, key);
  const count = (key: string) => number(key) ?? 0;
  switch (name) {
    case "database": {
      const latency = number("latency_ms");
      return latency === undefined ? "" : t("{ms} ms round trip", { ms: latency.toFixed(1) });
    }
    case "replicas":
      return t("{n} alive", { n: count("replicas_seen") });
    case "migrations":
      return t("level {n}", { n: count("level") });
    case "crypto": {
      const keys = Array.isArray(facts.keys) ? facts.keys.length : 0;
      const provider = typeof facts.provider === "string" ? facts.provider : "";
      return provider === "" ? t("{n} keys", { n: keys }) : t("{provider}, {n} keys", { provider, n: keys });
    }
    case "outbox":
      return t("{n} events waiting", { n: count("pending") });
    case "scheduler":
      return t("{running} running, {queued} queued", { running: count("running"), queued: count("queued") });
    case "sessions":
      return t("{n} hosts online", { n: count("hosts_online") });
    case "relays":
      return t("{n} active", { n: count("active") });
    case "directory":
      return facts.configured ? t("configured") : t("not configured");
    case "vulnerability_feeds": {
      const feeds = Array.isArray(facts.feeds) ? facts.feeds.length : 0;
      return t("{n} feeds", { n: feeds });
    }
    case "certificates": {
      const days = number("ca_expires_in_days");
      return days === undefined ? "" : t("fleet CA expires in {n} days", { n: days });
    }
    case "monitoring":
      return facts.enabled ? t("sampling") : t("off");
    case "housekeeping":
      return typeof facts.last_sweep_at === "string"
        ? t("swept {when}", { when: relativeTime(facts.last_sweep_at) })
        : t("never swept");
    default:
      return "";
  }
}

/**
 * The drawing a part has instead of a column of numbers.
 *
 * A count the server did not send stays undefined all the way down, so the
 * band puts it under the line as "not counted" rather than drawing a
 * segment of nought.
 */
function BlockDrawing({ name, facts }: { name: string; facts: Record<string, unknown> }) {
  const t = useT();
  const count = (key: string) => numberFact(facts, key);

  switch (name) {
    case "scheduler": {
      const segments: Segment[] = [
        { label: t("for approval"), value: count("awaiting_approval"), tone: "info", to: "/next/jobs?state=awaiting_approval" },
        { label: t("queued"), value: count("queued"), tone: "neutral", to: "/next/jobs?state=queued" },
        { label: t("leased"), value: count("leased"), tone: "info" },
        { label: t("dispatched"), value: count("dispatched"), tone: "info" },
        { label: t("running"), value: count("running"), tone: "ok", to: "/next/jobs?state=running" },
      ];
      return <Band segments={segments} testId="scheduler-band" />;
    }
    case "sessions": {
      const segments: Segment[] = [
        { label: t("agents on this gateway"), value: count("agents_on_this_gateway"), tone: "ok" },
        { label: t("hosts online"), value: count("hosts_online"), tone: "ok", to: "/next/hosts?connection_state=online" },
        { label: t("hosts stale"), value: count("hosts_stale"), tone: "warn", to: "/next/hosts?connection_state=stale" },
        { label: t("browser sessions"), value: count("web_sessions"), tone: "info" },
      ];
      return <Band segments={segments} testId="sessions-band" />;
    }
    case "relays": {
      const segments: Segment[] = [
        { label: t("active"), value: count("active"), tone: "ok", to: "/next/relays" },
        { label: t("silent"), value: count("silent"), tone: "error", to: "/next/relays" },
        { label: t("never seen"), value: count("never_seen"), tone: "unknown", to: "/next/relays" },
        { label: t("revoked"), value: count("revoked"), tone: "neutral", to: "/next/relays" },
      ];
      return <Band segments={segments} testId="relays-band" />;
    }
    case "outbox": {
      const consumers = (facts.consumers as OutboxConsumer[] | undefined) ?? [];
      if (consumers.length === 0) {
        return <Note>{t("No external consumer; the panel alone reads the trail.")}</Note>;
      }
      return (
        <Stack>
          <Bars items={consumers.map((one) => ({ label: one.name, value: one.behind, tone: one.behind > 0 ? "warn" : "ok" }))} />
          <Table
            rows={consumers}
            keyOf={(one) => one.name}
            testId="consumers"
            rowTestId={(one) => `consumer-${one.name}`}
            columns={[
              { key: "name", head: t("Consumer"), tight: true, cell: (one) => <code>{one.name}</code> },
              { key: "behind", head: t("Behind"), num: true, cell: (one) => one.behind },
              {
                key: "failures",
                head: t("Failures"),
                cell: (one) => one.failures > 0
                  ? <Pill tone="error" title={one.last_error}>{one.failures}</Pill>
                  : <Pill tone="ok">0</Pill>,
              },
              {
                key: "delivered",
                head: t("Last delivery"),
                minor: true,
                cell: (one) => <span title={absoluteTime(one.updated_at)}>{relativeTime(one.updated_at)}</span>,
              },
            ]}
          />
        </Stack>
      );
    }
    case "vulnerability_feeds": {
      const feeds = (facts.feeds as VulnerabilityFeed[] | undefined) ?? [];
      if (feeds.length === 0) return null;
      return (
        <Stack>
          <Bars items={feeds.map((one) => ({
            label: one.provider,
            value: one.advisories,
            tone: one.stale ? "error" : one.error ? "warn" : "ok",
          }))} />
          <Table
            rows={feeds}
            keyOf={(one) => one.provider}
            testId="feeds"
            rowTestId={(one) => `feed-${one.provider}`}
            columns={[
              { key: "provider", head: t("Feed"), tight: true, cell: (one) => <code>{one.provider}</code> },
              { key: "age", head: t("Age"), cell: (one) => duration(one.age_seconds) },
              { key: "advisories", head: t("Advisories"), num: true, cell: (one) => one.advisories },
              {
                key: "state",
                head: t("State"),
                cell: (one) => one.stale
                  ? <Pill tone="error">{t("stale")}</Pill>
                  : one.error
                    ? <Pill tone="warn" title={one.error}>{t("last fetch failed")}</Pill>
                    : <Pill tone="ok">{t("current")}</Pill>,
              },
            ]}
          />
        </Stack>
      );
    }
    case "housekeeping": {
      const removed = (facts.removed as Record<string, number> | undefined) ?? {};
      const retention = (facts.retention as Record<string, string> | undefined) ?? {};
      const kinds = Array.from(new Set([...Object.keys(retention), ...Object.keys(removed)])).sort();
      if (kinds.length === 0) return null;
      const swept = kinds.filter((kind) => typeof removed[kind] === "number");
      return (
        <Stack>
          {swept.length > 0 && (
            <Bars items={swept.map((kind) => ({
              label: t(HOUSEKEEPING_KINDS[kind] ?? kind),
              value: removed[kind],
              tone: "accent",
            }))} />
          )}
          <Table
            rows={kinds}
            keyOf={(kind) => kind}
            testId="housekeeping"
            rowTestId={(kind) => `kind-${kind}`}
            columns={[
              { key: "kind", head: t("Kind"), cell: (kind) => t(HOUSEKEEPING_KINDS[kind] ?? kind) },
              {
                key: "retention",
                head: t("Retention"),
                cell: (kind) => retention[kind] ? goDuration(retention[kind]) : t("forever"),
              },
              {
                key: "removed",
                head: t("Removed by the last sweep"),
                num: true,
                // A kind the sweep did not report is not a kind it removed
                // nothing from.
                cell: (kind) => typeof removed[kind] === "number" ? removed[kind] : "—",
              },
            ]}
          />
        </Stack>
      );
    }
    default:
      return null;
  }
}

/* The build and the process: the card a bug report starts with, with the
   places the documentation lives. */
function About({ block }: { block: StatusBlock }) {
  const t = useT();
  const facts = block.facts;
  const text = (key: string) => {
    const value = facts[key];
    return value === null || value === undefined || value === "" ? "—" : String(value);
  };
  const up = typeof facts.uptime_seconds === "number" ? duration(facts.uptime_seconds) : "—";
  return (
    <Card
      span={4}
      title={t("About")}
      note={t("version {version}, up {uptime}", { version: text("version"), uptime: up })}
    >
      <Facts>
        <Fact label={t("Product")}>Flotestro</Fact>
        <Fact label={t("Version")}><code>{text("version")}</code></Fact>
        <Fact label={t("Commit")}><Value value={facts.commit} kind="id" /></Fact>
        <Fact label={t("Build date")}><code>{text("build_date")}</code></Fact>
        <Fact label={t("Go version")}><code>{`${text("go_version")} (${text("platform")})`}</code></Fact>
        <Fact label={t("Agent protocol")}><code>{text("agent_protocol")}</code></Fact>
        <Fact label={t("Gateway identifier")}><Value value={facts.gateway_id} kind="id" /></Fact>
        <Fact label={t("Hostname")}><code>{text("hostname")}</code></Fact>
        <Fact label={t("Uptime")}><code>{up}</code></Fact>
        <Fact label={t("Started")}><Value value={facts.started_at} kind="time" /></Fact>
        <Fact label={t("Documentation")}>
          <>
            <a href="https://ultherego.github.io/Flotestro/docs/configuration.html" target="_blank" rel="noreferrer">
              {t("Configuration reference")}
            </a>
            {" · "}
            <a href="https://github.com/ultherego/flotestro/blob/main/docs/runbooks/index.md" target="_blank" rel="noreferrer">
              {t("Runbooks")}
            </a>
          </>
        </Fact>
      </Facts>
    </Card>
  );
}

/** An opaque identifier by its ends; the middle of a hash carries nothing. */
export function shortIdentifier(value: string, keep = 8): string {
  return value.length > keep * 2 + 3 ? `${value.slice(0, keep)}…${value.slice(-keep)}` : value;
}

/**
 * One value of the server's answer, drawn by what its key says it is.
 *
 * Nothing at all is an em dash: a fact the server did not send is not a
 * fact at nought, and this is the screen where that rule is most easily
 * lost, because almost everything here is a number.
 */
function Value({ value, kind = "text" }: { value: unknown; kind?: FactKind }): ReactNode {
  const t = useT();
  if (value === null || value === undefined || value === "") return <>—</>;
  switch (kind) {
    case "flag":
      return <Pill tone={value ? "ok" : "error"}>{value ? t("yes") : t("no")}</Pill>;
    case "bytes":
      return <code>{bytes(Number(value))}</code>;
    case "seconds":
      return <code>{duration(Number(value))}</code>;
    case "ms":
      return <code>{`${Number(value).toFixed(1)} ms`}</code>;
    case "time":
      return <span title={absoluteTime(String(value))}>{relativeTime(String(value))}</span>;
    case "number":
      return <code>{String(value)}</code>;
    case "duration":
      return <code title={String(value)}>{goDuration(String(value))}</code>;
    case "id":
      return <code title={String(value)}>{shortIdentifier(String(value))}</code>;
    default:
      return <Structured value={value} />;
  }
}

/**
 * A fact that is a list or a record of its own.
 *
 * It used to be squeezed into the value track and drawn as one unbreakable
 * line of JSON. A list of scalars reads as a line of words; a list of
 * records reads as a table; a record reads as the facts it holds.
 */
function Structured({ value }: { value: unknown }): ReactNode {
  const t = useT();
  if (value === null || value === undefined) return <>—</>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <>—</>;
    const records = value.filter((one) => one !== null && typeof one === "object" && !Array.isArray(one));
    if (records.length !== value.length) {
      return <code>{value.map((one) => String(one)).join(", ")}</code>;
    }
    const columns = Array.from(new Set(records.flatMap((one) => Object.keys(one as object))));
    return (
      <Table
        rows={records as Record<string, unknown>[]}
        keyOf={(_, index) => String(index)}
        columns={columns.map((column) => ({
          key: column,
          head: t(labelOfKey(column)),
          cell: (row: Record<string, unknown>) => <Value value={row[column]} kind={kindOfKey(column)} />,
        }))}
      />
    );
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <>—</>;
    return (
      <Facts>
        {entries.map(([key, one]) => (
          <Fact key={key} label={t(labelOfKey(key))}><Value value={one} kind={kindOfKey(key)} /></Fact>
        ))}
      </Facts>
    );
  }
  return <code>{String(value)}</code>;
}

/** The label of a key the screen has no name for: the key, made readable. */
function labelOfKey(key: string): string {
  const named = FACT_LABELS[key];
  if (named) return named[0];
  const words = key.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** What a key of a nested record is, read off its name. */
function kindOfKey(key: string): FactKind {
  const named = FACT_LABELS[key];
  if (named) return named[1];
  if (/(^|_)(id|uuid|fingerprint|digest|hash)$/.test(key)) return "id";
  if (/_at$/.test(key)) return "time";
  if (/_seconds(_ago)?$/.test(key)) return "seconds";
  if (/_bytes$/.test(key)) return "bytes";
  if (/_ms$/.test(key)) return "ms";
  return "text";
}
