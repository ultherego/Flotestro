import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { copyToClipboard } from "../lib/clipboard";
import { absoluteTime, duration, goDuration, relativeTime } from "../lib/format";
import {
  Empty, ErrorBox, FactValue, Pair, Pairs, Structured, TableScroll, Time,
  type FactKind,
} from "../components/ui";
import { Card, NeedsAttention, PageHeader, Verdict, type Tone } from "../components/layout";
import { StatusBar, type Segment } from "../components/widgets";
import { Board } from "../components/board";
import { useT } from "../i18n";

/**
 * The condition of the panel itself: is it the database, the publisher, the
 * scheduler or a feed that is not well.
 */

/** How often the screen asks again; an incident moves faster than a page reload. */
export const STATUS_REFRESH_INTERVAL = 15_000;

/* The shape of the answer, local to the screen: no other page reads it. */
type StatusBlock = {
  ok: boolean | null;
  reason?: string;
  attention?: string;
  facts: Record<string, unknown>;
};

type StatusView = {
  generated_at: string;
  ok: boolean;
  unknown: number;
  blocks: Record<string, StatusBlock>;
  links: { openapi: string; metrics: string };
};

type OutboxConsumer = { name: string; behind: number; failures: number; last_error?: string; updated_at: string };
type Feed = { provider: string; age_seconds: number; stale: boolean; advisories: number; error?: string };

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

/* The keys a widget draws instead of a row, so the row is not repeated.
   The days until the CA expires are in the expiry time itself, and the
   total of the relays is the sum of the segments above it. */
const DRAWN_ELSEWHERE = new Set([
  "consumers", "feeds", "removed", "retention", "ca_expires_in_days", "total",
  "awaiting_approval", "queued", "leased", "dispatched", "running",
  "agents_on_this_gateway", "hosts_online", "hosts_stale", "web_sessions",
  "active", "silent", "never_seen", "revoked",
]);

export function Status() {
  const t = useT();
  const { data, error, dataUpdatedAt } = useQuery({
    queryKey: ["status"],
    queryFn: () => api.get<StatusView>("/api/v1/status"),
    refetchInterval: STATUS_REFRESH_INTERVAL,
    retry: false,
  });
  const [copied, setCopied] = useState(false);

  const copyDiagnostics = () => {
    if (!data) return;
    // A bundle reported as copied and not copied is pasted as whatever was on
    // the clipboard before - into a ticket, as the state of somebody's fleet.
    void copyToClipboard(JSON.stringify(data, null, 2)).then((done) => {
      setCopied(done);
      if (done) {
        window.setTimeout(() => setCopied(false), 3000);
      }
    });
  };

  const blocks = data ? BLOCK_ORDER.filter((key) => data.blocks[key]) : [];
  // What the reader has to do something about, named at the top. The same
  // blocks stand open below; this zone is how they are found without
  // reading all thirteen headings.
  const wanting = blocks.filter((key) => blockTone(data!.blocks[key]) !== "ok");

  return (
    <>
      <PageHeader
        icon="settings"
        title={t("Status")}
        description={t("The condition of this panel, judged by the server.")}
        help={
          <p>
            {t("Every part of the panel is judged by the control plane itself and read again every {n} seconds. A part that cannot be judged is counted as unknown, which is not the same as fine. The details of a part that is fine stay closed; one that is not opens itself.", { n: STATUS_REFRESH_INTERVAL / 1000 })}
          </p>
        }
        actions={
          <>
            <a className="button" href="/api/v1/openapi.json" target="_blank" rel="noreferrer">{t("OpenAPI")}</a>
            <a className="button" href="/metrics" target="_blank" rel="noreferrer">{t("Metrics")}</a>
            <button className="secondary" onClick={copyDiagnostics} disabled={!data}>
              {copied ? t("Copied") : t("Copy diagnostics")}
            </button>
          </>
        }
      />
      {error && <ErrorBox error={error} />}
      {!error && !data && <Card><Empty>{t("Loading…")}</Empty></Card>}
      {data && (
        <>
          <div className="verdict-band">
          <Verdict
            tone={data.ok ? (data.unknown > 0 ? "warn" : "ok") : "error"}
            headline={data.ok ? t("Every judged part of this panel is fine") : t("A part of this panel is not fine")}
          >
            <span>
              {data.unknown > 0
                ? t("{n} of {total} parts could not be judged", { n: data.unknown, total: blocks.length })
                : t("all {total} parts judged", { total: blocks.length })}
            </span>
            <span title={absoluteTime(data.generated_at)}>{t("judged {when}", { when: relativeTime(data.generated_at) })}</span>
            <span>{dataUpdatedAt ? t("read at {when}", { when: absoluteTime(new Date(dataUpdatedAt).toISOString()) }) : "—"}</span>
          </Verdict>

          <NeedsAttention title={t("Parts that need a look")}>
            {wanting.map((key) => (
              <p key={key} className="attention-line">
                <ToneBadge tone={blockTone(data.blocks[key])} />
                <strong>{t(BLOCK_TITLES[key] ?? key)}</strong>
                <span>{data.blocks[key].reason || data.blocks[key].attention || t("judged as unknown")}</span>
              </p>
            ))}
          </NeedsAttention>
          </div>

          {/* Every part on the screen at once, as tiles that fit three or
              four to a row. Folding them away was worse than the wall it
              was meant to answer: thirteen closed lines say thirteen names
              and nothing else, and finding anything took a click. */}
          {/* Until somebody arranges this screen the tiles are packed into
              columns, so a board nobody has touched has no holes in it. A
              tile is about as tall as the facts it holds. */}
          <Board
            screen="status"
            catalogue={[...blocks, ...(data.blocks.build ? ["build"] : [])].map((key) => ({
              key, title: BLOCK_TITLES[key] ?? key, width: 4,
            }))}
            weights={Object.fromEntries([
              ...blocks.map((key) => [key, tileWeight(data.blocks[key])]),
              ["build", 12],
            ])}
            drawn={{
              ...Object.fromEntries(blocks.map((key) => [
                key, <BlockTile key={key} name={key} block={data.blocks[key]} />,
              ])),
              ...(data.blocks.build ? { build: <AboutTile block={data.blocks.build} /> } : {}),
            }}
          />
        </>
      )}
    </>
  );
}

/**
 * One part of the panel: its name, its state, the one fact worth reading
 * first and then everything the server said about it.
 *
 * The tile carries no border of its own - thirteen bordered boxes is the
 * wall this screen started as. It is a surface with a title, and only a
 * part that is not fine takes a coloured edge, so the eye lands on those.
 */
function BlockTile({ name, block }: { name: string; block: StatusBlock }) {
  const t = useT();
  const tone = blockTone(block);
  const rows = Object.entries(block.facts).filter(([key]) => !DRAWN_ELSEWHERE.has(key));
  const summary = blockSummary(name, block.facts, t);
  return (
    <section className={`part ${tone}`}>
      <h3 className="part-title">
        <span>{t(BLOCK_TITLES[name] ?? name)}</span>
        <ToneBadge tone={tone} />
        {summary && <span className="part-summary">{summary}</span>}
      </h3>
      {(block.reason || block.attention) && (
        <p className="part-reason">{block.reason || block.attention}</p>
      )}
      <BlockWidget name={name} facts={block.facts} />
      <Pairs>
        {rows.map(([key, value]) => {
          const [label, kind] = FACT_LABELS[key] ?? [key, "text"];
          // A structure is given the width of the tile; squeezed into a
          // value track it used to be drawn as one line of JSON.
          const structured = value !== null && typeof value === "object";
          return (
            <Pair key={key} label={t(label)} wide={structured}>
              {structured ? <Structured value={value} /> : <FactValue value={value} kind={kind} />}
            </Pair>
          );
        })}
      </Pairs>
    </section>
  );
}

/**
 * The one fact of a part that is worth reading while it is closed. Without
 * it a closed section says only its own name, and the reader has to open
 * every one to find out anything.
 */
export function blockSummary(
  name: string,
  facts: Record<string, unknown>,
  t: (text: string, values?: Record<string, string | number>) => string,
): string {
  const number = (key: string): number | undefined =>
    typeof facts[key] === "number" ? (facts[key] as number) : undefined;
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

/** Roughly how tall a part's tile will be, counted in rows of facts. */
export function tileWeight(block: StatusBlock): number {
  const rows = Object.keys(block.facts).filter((key) => !DRAWN_ELSEWHERE.has(key)).length;
  // A structure draws a row per field of every record, and a widget takes
  // about four rows of its own.
  const structured = Object.values(block.facts).filter(
    (value) => value !== null && typeof value === "object").length;
  return rows + structured * 4 + 3;
}

function ToneBadge({ tone }: { tone: Tone }) {
  const t = useT();
  const text = tone === "ok" ? t("fine") : tone === "warn" ? t("attention") : tone === "error" ? t("not fine") : t("unknown");
  return <span className={`badge ${tone}`}>{text}</span>;
}

function BlockWidget({ name, facts }: { name: string; facts: Record<string, unknown> }) {
  const t = useT();
  const count = (key: string): number | undefined => {
    const value = facts[key];
    return typeof value === "number" ? value : undefined;
  };
  switch (name) {
    case "scheduler": {
      const segments: Segment[] = [
        // Five segments share a third of the page; the shortest label that
        // still says what the number counts is the one that is not cut.
        { label: t("for approval"), value: count("awaiting_approval"), tone: "info", to: "/jobs?state=awaiting_approval" },
        { label: t("queued"), value: count("queued"), tone: "neutral", to: "/jobs?state=queued" },
        { label: t("leased"), value: count("leased"), tone: "info" },
        { label: t("dispatched"), value: count("dispatched"), tone: "info" },
        { label: t("running"), value: count("running"), tone: "ok", to: "/jobs?state=running" },
      ];
      return <StatusBar segments={segments} compact />;
    }
    case "sessions": {
      const segments: Segment[] = [
        { label: t("agents on this gateway"), value: count("agents_on_this_gateway"), tone: "ok" },
        { label: t("hosts online"), value: count("hosts_online"), tone: "ok", to: "/hosts?connection_state=online" },
        { label: t("hosts stale"), value: count("hosts_stale"), tone: "warn", to: "/hosts?connection_state=stale" },
        { label: t("browser sessions"), value: count("web_sessions"), tone: "info" },
      ];
      return <StatusBar segments={segments} compact />;
    }
    case "relays": {
      const segments: Segment[] = [
        { label: t("active"), value: count("active"), tone: "ok", to: "/relays" },
        { label: t("silent"), value: count("silent"), tone: "error", to: "/relays" },
        { label: t("never seen"), value: count("never_seen"), tone: "unknown", to: "/relays" },
        { label: t("revoked"), value: count("revoked"), tone: "neutral", to: "/relays" },
      ];
      return <StatusBar segments={segments} compact />;
    }
    case "outbox": {
      const consumers = (facts.consumers as OutboxConsumer[] | undefined) ?? [];
      if (consumers.length === 0) return <p className="source">{t("No external consumer; the panel alone reads the trail.")}</p>;
      return (
        <TableScroll>
          <table>
          <thead>
            <tr><th scope="col">{t("Consumer")}</th><th scope="col">{t("Behind")}</th><th scope="col">{t("Failures")}</th><th scope="col">{t("Last delivery")}</th></tr>
          </thead>
          <tbody>
            {consumers.map((consumer) => (
              <tr key={consumer.name}>
                <td className="mono">{consumer.name}</td>
                <td className="mono">{consumer.behind}</td>
                <td>
                  {consumer.failures > 0
                    ? <span className="badge error" title={consumer.last_error}>{consumer.failures}</span>
                    : <span className="badge ok">0</span>}
                </td>
                <td><Time value={consumer.updated_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        </TableScroll>
      );
    }
    case "vulnerability_feeds": {
      const feeds = (facts.feeds as Feed[] | undefined) ?? [];
      if (feeds.length === 0) return null;
      return (
        <TableScroll>
          <table>
          <thead>
            <tr><th scope="col">{t("Feed")}</th><th scope="col">{t("Age")}</th><th scope="col">{t("Advisories")}</th><th scope="col">{t("State")}</th></tr>
          </thead>
          <tbody>
            {feeds.map((feed) => (
              <tr key={feed.provider}>
                <td className="mono">{feed.provider}</td>
                <td className="mono">{duration(feed.age_seconds)}</td>
                <td className="mono">{feed.advisories}</td>
                <td>
                  {feed.stale
                    ? <span className="badge error">{t("stale")}</span>
                    : feed.error
                      ? <span className="badge warn" title={feed.error}>{t("last fetch failed")}</span>
                      : <span className="badge ok">{t("current")}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </TableScroll>
      );
    }
    case "housekeeping": {
      const removed = (facts.removed as Record<string, number> | undefined) ?? {};
      const retention = (facts.retention as Record<string, string> | undefined) ?? {};
      const kinds = Array.from(new Set([...Object.keys(retention), ...Object.keys(removed)])).sort();
      if (kinds.length === 0) return null;
      return (
        <TableScroll>
          <table>
          <thead>
            <tr><th scope="col">{t("Kind")}</th><th scope="col">{t("Retention")}</th><th scope="col">{t("Removed by the last sweep")}</th></tr>
          </thead>
          <tbody>
            {kinds.map((kind) => (
              <tr key={kind}>
                <td>{t(HOUSEKEEPING_KINDS[kind] ?? kind)}</td>
                <td className="mono">{retention[kind] ? goDuration(retention[kind]) : t("forever")}</td>
                <td className="mono">{removed[kind] ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </TableScroll>
      );
    }
    default:
      return null;
  }
}

/* The build and the process: the block a bug report starts with, with the
   places the documentation lives. */

/* The build and the process: the block a bug report starts with, with the
   places the documentation lives. */
function AboutTile({ block }: { block: StatusBlock }) {
  const t = useT();
  const facts = block.facts;
  const text = (key: string) => {
    const value = facts[key];
    return value === null || value === undefined || value === "" ? "—" : String(value);
  };
  const up = typeof facts.uptime_seconds === "number" ? duration(facts.uptime_seconds) : "—";
  return (
    <section className="part">
      <h3 className="part-title">
        <span>{t("About")}</span>
        <span className="part-summary">{t("version {version}, up {uptime}", { version: text("version"), uptime: up })}</span>
      </h3>
      <Pairs>
        <Pair label={t("Product")}><span>Flotestro</span></Pair>
        <Pair label={t("Version")}><span className="mono">{text("version")}</span></Pair>
        <Pair label={t("Commit")}><FactValue value={facts.commit} kind="id" /></Pair>
        <Pair label={t("Build date")}><span className="mono">{text("build_date")}</span></Pair>
        <Pair label={t("Go version")}><span className="mono">{text("go_version")} ({text("platform")})</span></Pair>
        <Pair label={t("Agent protocol")}><span className="mono">{text("agent_protocol")}</span></Pair>
        <Pair label={t("Gateway identifier")}><FactValue value={facts.gateway_id} kind="id" /></Pair>
        <Pair label={t("Hostname")}><span className="mono">{text("hostname")}</span></Pair>
        <Pair label={t("Uptime")}><span className="mono">{up}</span></Pair>
        <Pair label={t("Started")}><Time value={typeof facts.started_at === "string" ? facts.started_at : null} /></Pair>
        <Pair label={t("Documentation")} wide>
          <span>
            <a href="https://ultherego.github.io/Flotestro/docs/configuration.html" target="_blank" rel="noreferrer">{t("Configuration reference")}</a>
            {" · "}
            <a href="https://github.com/ultherego/flotestro/blob/main/docs/runbooks/index.md" target="_blank" rel="noreferrer">{t("Runbooks")}</a>
          </span>
        </Pair>
      </Pairs>
    </section>
  );
}
