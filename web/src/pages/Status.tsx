import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { absoluteTime, bytes, relativeTime } from "../lib/format";
import { Empty, ErrorBox, Pair, Pairs, Time } from "../components/ui";
import { Card, PageHeader } from "../components/layout";
import { StatusBar, type Segment, type WidgetTone } from "../components/widgets";
import { useT } from "../i18n";

/**
 * The condition of the panel itself: is it the database, the publisher,
 * the scheduler or a feed that is not well. The metrics endpoint carries
 * the same facts for a scraper; this screen is for the person without
 * one, and it refreshes itself so an incident can be watched from it.
 *
 * Every block is judged by the server: fine, not fine with a reason, or
 * unknown when the panel cannot tell. Unknown is drawn grey, never green -
 * a light that means "nobody looked" is the one that costs an outage.
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
export function blockTone(block: Pick<StatusBlock, "ok" | "attention">): WidgetTone {
  if (block.ok === null || block.ok === undefined) return "unknown";
  if (!block.ok) return "error";
  return block.attention ? "warn" : "ok";
}

/**
 * A number of seconds as a short duration. Fractions matter below a
 * minute - a latency of 0.4 s and one of 4 s are different conditions -
 * and stop mattering above it.
 */
export function formatSeconds(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 60) return `${value < 10 ? value.toFixed(1) : Math.round(value)}s`;
  if (value < 3600) return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
  if (value < 86400) return `${Math.floor(value / 3600)}h ${Math.floor((value % 3600) / 60)}m`;
  return `${Math.floor(value / 86400)}d ${Math.floor((value % 86400) / 3600)}h`;
}

/** The order the blocks stand in: what breaks the panel first comes first. */
const BLOCK_ORDER = [
  "database", "migrations", "outbox", "scheduler", "sessions", "relays",
  "directory", "vulnerability_feeds", "certificates", "housekeeping",
];

const BLOCK_TITLES: Record<string, string> = {
  database: "Database",
  migrations: "Schema",
  outbox: "Durable trail",
  scheduler: "Scheduler",
  sessions: "Sessions",
  relays: "Relays",
  directory: "Directory connector",
  vulnerability_feeds: "Vulnerability feeds",
  certificates: "Certificates",
  housekeeping: "Housekeeping",
  build: "About",
};

/* The label of each fact and how its value is drawn. A key without a
   label is shown as it is, so a new fact of the server is visible before
   the screen learns its name. */
type FactKind = "text" | "number" | "bytes" | "seconds" | "time" | "flag" | "ms";
const FACT_LABELS: Record<string, [string, FactKind]> = {
  reachable: ["Reachable", "flag"],
  latency_ms: ["Round trip", "ms"],
  size_bytes: ["Size", "bytes"],
  connections_used: ["Server connections", "number"],
  connections_max: ["Server connection limit", "number"],
  pool_used: ["Pool connections", "number"],
  pool_max: ["Pool limit", "number"],
  oldest_transaction_seconds: ["Oldest transaction", "seconds"],
  server_version: ["Server version", "text"],
  error: ["Error", "text"],
  level: ["Level", "number"],
  latest: ["Latest migration", "text"],
  applied: ["Applied migrations", "number"],
  pending: ["Events waiting", "number"],
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
  ca_expires_in_days: ["CA expires in (days)", "number"],
  authorities: ["Authorities in the trust set", "number"],
  agents_expiring_7d: ["Hosts expiring within 7 days", "number"],
  agents_expiring_30d: ["Hosts expiring within 30 days", "number"],
  last_sweep_at: ["Last sweep", "time"],
  total: ["Relays", "number"],
  degraded: ["Degraded", "number"],
};

/* The keys a widget draws instead of a row, so the row is not repeated. */
const DRAWN_ELSEWHERE = new Set([
  "consumers", "feeds", "removed", "retention",
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
    navigator.clipboard?.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 3000);
  };

  return (
    <>
      <PageHeader
        icon="settings"
        title={t("Status")}
        description={t("The condition of this panel: every part judged by the server, refreshed every {n} seconds.", { n: STATUS_REFRESH_INTERVAL / 1000 })}
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
        <div className="widgets">
          <Verdict view={data} updatedAt={dataUpdatedAt} />
          {BLOCK_ORDER.filter((key) => data.blocks[key]).map((key) => (
            <BlockCard key={key} name={key} block={data.blocks[key]} />
          ))}
          {data.blocks.build && <About block={data.blocks.build} />}
        </div>
      )}
    </>
  );
}

/* The verdict of the whole, with how many blocks could not be judged. */
function Verdict({ view, updatedAt }: { view: StatusView; updatedAt: number }) {
  const t = useT();
  const tone: WidgetTone = view.ok ? (view.unknown > 0 ? "warn" : "ok") : "error";
  return (
    <Card className="span-12" tone={tone === "error" ? "error" : tone === "warn" ? "warn" : undefined}>
      <Pairs>
        <Pair label={t("Verdict")}>
          <span className={`badge ${tone}`}>
            {view.ok ? t("every judged part is fine") : t("a part of the panel is not fine")}
          </span>
        </Pair>
        <Pair label={t("Not judged")}>
          {view.unknown > 0
            ? <span className="badge unknown">{t("{n} parts unknown", { n: view.unknown })}</span>
            : <span className="badge ok">{t("none")}</span>}
        </Pair>
        <Pair label={t("Generated")}>
          <span title={absoluteTime(view.generated_at)}>{relativeTime(view.generated_at)}</span>
        </Pair>
        <Pair label={t("Last refresh")}>
          <span>{updatedAt ? absoluteTime(new Date(updatedAt).toISOString()) : "—"}</span>
        </Pair>
      </Pairs>
    </Card>
  );
}

/* One block: the verdict badge in the title, the reason under it, a
   widget where the facts make a picture and the remaining facts as rows. */
function BlockCard({ name, block }: { name: string; block: StatusBlock }) {
  const t = useT();
  const tone = blockTone(block);
  return (
    <Card
      className="span-4"
      tone={tone === "error" ? "error" : tone === "warn" ? "warn" : undefined}
      title={<>{t(BLOCK_TITLES[name] ?? name)} <ToneBadge tone={tone} /></>}
      description={block.reason || block.attention}
    >
      <BlockWidget name={name} facts={block.facts} />
      <Pairs>
        {Object.entries(block.facts)
          .filter(([key]) => !DRAWN_ELSEWHERE.has(key))
          .map(([key, value]) => {
            const [label, kind] = FACT_LABELS[key] ?? [key, "text"];
            return (
              <Pair key={key} label={t(label)}>
                <FactValue value={value} kind={kind} />
              </Pair>
            );
          })}
      </Pairs>
    </Card>
  );
}

function ToneBadge({ tone }: { tone: WidgetTone }) {
  const t = useT();
  const text = tone === "ok" ? t("fine") : tone === "warn" ? t("attention") : tone === "error" ? t("not fine") : t("unknown");
  return <span className={`badge ${tone}`}>{text}</span>;
}

function FactValue({ value, kind }: { value: unknown; kind: FactKind }) {
  const t = useT();
  if (value === null || value === undefined || value === "") return <span className="source">—</span>;
  switch (kind) {
    case "flag":
      return <span className={value ? "badge ok" : "badge error"}>{value ? t("yes") : t("no")}</span>;
    case "bytes":
      return <span className="mono">{bytes(Number(value))}</span>;
    case "seconds":
      return <span className="mono">{formatSeconds(Number(value))}</span>;
    case "ms":
      return <span className="mono">{Number(value).toFixed(1)} ms</span>;
    case "time":
      return <Time value={String(value)} />;
    case "number":
      return <span className="mono">{String(value)}</span>;
    default:
      return typeof value === "object"
        ? <span className="mono">{JSON.stringify(value)}</span>
        : <span className="mono">{String(value)}</span>;
  }
}

/* The picture of a block, where its facts make one. */
function BlockWidget({ name, facts }: { name: string; facts: Record<string, unknown> }) {
  const t = useT();
  const count = (key: string): number | undefined => {
    const value = facts[key];
    return typeof value === "number" ? value : undefined;
  };
  switch (name) {
    case "scheduler": {
      const segments: Segment[] = [
        { label: t("awaiting approval"), value: count("awaiting_approval"), tone: "info", to: "/jobs?state=awaiting_approval" },
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
        <table>
          <thead>
            <tr><th>{t("Consumer")}</th><th>{t("Behind")}</th><th>{t("Failures")}</th><th>{t("Last delivery")}</th></tr>
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
      );
    }
    case "vulnerability_feeds": {
      const feeds = (facts.feeds as Feed[] | undefined) ?? [];
      if (feeds.length === 0) return null;
      return (
        <table>
          <thead>
            <tr><th>{t("Feed")}</th><th>{t("Age")}</th><th>{t("Advisories")}</th><th>{t("State")}</th></tr>
          </thead>
          <tbody>
            {feeds.map((feed) => (
              <tr key={feed.provider}>
                <td className="mono">{feed.provider}</td>
                <td className="mono">{formatSeconds(feed.age_seconds)}</td>
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
      );
    }
    case "housekeeping": {
      const removed = (facts.removed as Record<string, number> | undefined) ?? {};
      const retention = (facts.retention as Record<string, string> | undefined) ?? {};
      const kinds = Array.from(new Set([...Object.keys(retention), ...Object.keys(removed)])).sort();
      if (kinds.length === 0) return null;
      return (
        <table>
          <thead>
            <tr><th>{t("Kind")}</th><th>{t("Retention")}</th><th>{t("Removed by the last sweep")}</th></tr>
          </thead>
          <tbody>
            {kinds.map((kind) => (
              <tr key={kind}>
                <td className="mono">{kind}</td>
                <td className="mono">{retention[kind] ? humanDuration(retention[kind]) : t("forever")}</td>
                <td className="mono">{removed[kind] ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
    }
    default:
      return null;
  }
}

/* The build and the process: the block a bug report starts with, with the
   places the documentation lives. */
function About({ block }: { block: StatusBlock }) {
  const t = useT();
  const facts = block.facts;
  const text = (key: string) => {
    const value = facts[key];
    return value === null || value === undefined || value === "" ? "—" : String(value);
  };
  const uptime = typeof facts.uptime_seconds === "number" ? formatSeconds(facts.uptime_seconds) : "—";
  return (
    <Card className="span-4" title={t("About")}>
      <Pairs>
        <Pair label={t("Product")}><span>Flotestro</span></Pair>
        <Pair label={t("Version")}><span className="mono">{text("version")}</span></Pair>
        <Pair label={t("Commit")}><span className="mono">{text("commit")}</span></Pair>
        <Pair label={t("Build date")}><span className="mono">{text("build_date")}</span></Pair>
        <Pair label={t("Go version")}><span className="mono">{text("go_version")} ({text("platform")})</span></Pair>
        <Pair label={t("Agent protocol")}><span className="mono">{text("agent_protocol")}</span></Pair>
        <Pair label={t("Gateway identifier")}><span className="mono">{text("gateway_id")}</span></Pair>
        <Pair label={t("Hostname")}><span className="mono">{text("hostname")}</span></Pair>
        <Pair label={t("Uptime")}><span className="mono">{uptime}</span></Pair>
        <Pair label={t("Started")}><Time value={typeof facts.started_at === "string" ? facts.started_at : null} /></Pair>
        <Pair label={t("Documentation")}>
          <span>
            <a href="https://github.com/ultherego/flotestro/blob/main/docs/configuration.md" target="_blank" rel="noreferrer">{t("Configuration reference")}</a>
            {" · "}
            <a href="https://github.com/ultherego/flotestro/blob/main/docs/runbooks/index.md" target="_blank" rel="noreferrer">{t("Runbooks")}</a>
          </span>
        </Pair>
      </Pairs>
    </Card>
  );
}

/** A Go duration such as 720h0m0s as days and hours: what a retention is read in. */
export function humanDuration(value: string): string {
  const match = /^(\d+)h(\d+)m(\d+)s$/.exec(value);
  if (!match) return value;
  const hours = Number(match[1]);
  if (hours % 24 === 0) return `${hours / 24} d`;
  return `${Math.floor(hours / 24)} d ${hours % 24} h`;
}
