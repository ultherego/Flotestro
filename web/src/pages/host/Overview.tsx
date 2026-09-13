import { Link } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Time, OptionalFlag, OptionalNumber, Empty, ErrorBox, JobState } from "../../components/ui";
import { Icon, type IconName } from "../../components/icons";
import { Meter } from "../../components/widgets";
import { api, loadedItems } from "../../lib/api";
import { bytes } from "../../lib/format";
import type { Host, HostTimelineItem, HostTimelineKind, HostTimelinePage } from "../../lib/types";
import {
  Fact, Facts, Foot, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, usageTone,
  useHost, useModule,
} from "./shared";
import { useT } from "../../i18n";

type SystemState = {
  os?: Record<string, string>;
  hardware?: {
    cpu_cores?: number;
    memory_bytes?: number;
    root_fs_bytes?: number;
    root_fs_free_bytes?: number;
    virtualization?: string;
  };
};

export function Overview() {
  const t = useT();
  const host = useHost();
  const module = useModule<SystemState>(host.id, "system");
  const hardware = module.data?.payload?.hardware;

  // A host that has not reported its adapters has an unknown registry,
  // not an empty one: the bar shows dashes until the first report.
  const adapters = host.capabilities?.length ? host.capabilities : undefined;
  const rootUsed = hardware?.root_fs_bytes !== undefined && hardware.root_fs_free_bytes !== undefined
    ? hardware.root_fs_bytes - hardware.root_fs_free_bytes
    : undefined;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Overview")}
        description={t("Identity, hardware and the adapters of this host, as the agent last reported them.")}
      />
      <ModuleFreshness fragment={module.data} />

      <Widgets>
        {/* The two bars are the host read from across the room: what the
            panel can do here, and what wants a decision. */}
        <Summary
          title={t("Adapters")}
          description={t("What the panel can read and change on this host.")}
          span={7}
          segments={[
            { label: t("available"), value: countWhere(adapters, (a) => a.available && !a.read_only), tone: "ok" },
            { label: t("read only"), value: countWhere(adapters, (a) => a.available && a.read_only), tone: "warn" },
            { label: t("unavailable"), value: countWhere(adapters, (a) => !a.available), tone: "neutral" },
          ]}
        />
        <Summary
          title={t("Needs attention")}
          description={t("Counted by the agent on its last report.")}
          span={5}
          segments={[
            { label: t("Failed units"), value: host.failed_units ?? undefined, tone: "error" },
            { label: t("Updates waiting"), value: host.pending_updates ?? undefined, tone: "warn" },
            { label: t("Security updates"), value: host.pending_security_updates ?? undefined, tone: "error" },
          ]}
        />

        <Section title={t("System")} span={7} flush>
          <Facts>
            <Fact label={t("System")}>{host.os_distribution} {host.os_version} ({host.os_family})</Fact>
            <Fact label={t("Architecture")}>{host.architecture || "—"}</Fact>
            <Fact label={t("Management address")}>
              {host.management_address
                ? <span className="hm-mono">{host.management_address} ({host.management_address_source})</span>
                : <span className="badge unknown">{t("unknown")}</span>}
            </Fact>
            <Fact label={t("Lifecycle state")}>{host.lifecycle_state}</Fact>
            <Fact label={t("Reboot required")}><OptionalFlag value={host.reboot_required} /></Fact>
            <Fact label={t("Failed units")}><OptionalNumber value={host.failed_units} /></Fact>
            <Fact label={t("Package database")}>
              {host.package_database_broken ? <span className="badge error">{t("needs repair")}</span> : t("healthy")}
            </Fact>
            <Fact label={t("Enrolled")}><Time value={host.enrolled_at} /></Fact>
            <Fact label={t("Machine ID")}><span className="hm-mono">{host.machine_id}</span></Fact>
            <Fact label={t("Boot ID")}><span className="hm-mono">{host.boot_id || "—"}</span></Fact>
          </Facts>
        </Section>

        <Section title={t("Hardware")} span={5} flush>
          {hardware ? (
            <Facts>
              <Fact label={t("CPU cores")}>{hardware.cpu_cores ?? "—"}</Fact>
              <Fact label={t("Memory")}>{hardware.memory_bytes ? bytes(hardware.memory_bytes) : "—"}</Fact>
              <Fact label={t("Virtualization")}>{hardware.virtualization || "—"}</Fact>
              {/* The filesystem is the one number here that changes on its
                  own; it gets a bar, and the bar's colour says when it is
                  time to look at the storage page. */}
              <Fact label={t("Root filesystem")} wide>
                {rootUsed !== undefined && hardware.root_fs_bytes ? (
                  <Meter
                    value={rootUsed}
                    max={hardware.root_fs_bytes}
                    tone={usageTone(rootUsed, hardware.root_fs_bytes)}
                    text={t("{free} free of {total}", { free: bytes(hardware.root_fs_free_bytes), total: bytes(hardware.root_fs_bytes) })}
                  />
                ) : "—"}
              </Fact>
            </Facts>
          ) : (
            <Empty>{t("This host has not reported its hardware yet.")}</Empty>
          )}
        </Section>

        <Section title={t("Adapters")} count={(host.capabilities ?? []).length} span={12} flush>
          <Adapters host={host} />
        </Section>

        {/* The history of the host from every record the panel keeps,
            lined up by time: what ran, what failed, who did what and when
            the host was last seen. */}
        <Section
          title={t("Recent activity")}
          description={t("Tasks, audit entries, sessions, campaigns and alerts of this host, newest first.")}
          span={12}
          flush
        >
          <RecentActivity host={host} />
        </Section>
      </Widgets>
    </ModulePage>
  );
}

/** How many rows one page of the timeline holds; the operator asks for more. */
const TIMELINE_PAGE = 30;

/** The mark of every kind of record, taken from the page it links to. */
const KIND_ICONS: Record<HostTimelineKind, IconName> = {
  job: "jobs", audit: "audit", session: "server", lifecycle: "hosts", alert: "monitoring", campaign: "campaigns",
};

/**
 * The host timeline. Every row is one record of one table - nothing is
 * derived here - and the row links to the page of that record. The server
 * folds in only the sources the operator may read; the ones left out are
 * named under the list rather than passed over.
 */
function RecentActivity({ host }: { host: Host }) {
  const t = useT();
  const timeline = useInfiniteQuery({
    queryKey: ["host-timeline", host.id],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams({ limit: String(TIMELINE_PAGE) });
      if (pageParam) page.set("cursor", pageParam);
      return api.get<HostTimelinePage>(`/api/v1/hosts/${host.id}/timeline?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });
  const items = loadedItems(timeline.data);
  const sources = timeline.data?.pages[0]?.sources ?? [];
  const hidden = (Object.keys(KIND_ICONS) as HostTimelineKind[]).filter((kind) => !sources.includes(kind));

  if (timeline.error) return <ErrorBox error={timeline.error} />;
  if (timeline.isPending) return <Empty>{t("Loading…")}</Empty>;
  return (
    <>
      {items.length === 0 ? (
        <Empty>{t("Nothing has been recorded for this host yet.")}</Empty>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>{t("When")}</th><th>{t("Kind")}</th><th>{t("What")}</th><th>{t("State")}</th><th>{t("Who")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.kind}:${item.id}`}>
                <td><Time value={item.at} /></td>
                <td>
                  <span className="badge" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                    <Icon name={KIND_ICONS[item.kind]} />{t(kindName(item.kind))}
                  </span>
                </td>
                <td>
                  <ActivityTitle host={host} item={item} />
                  {item.detail && <div className="source">{item.detail}</div>}
                </td>
                <td><ActivityState item={item} /></td>
                <td className="source">{item.actor || "—"}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <Foot>
        {timeline.hasNextPage && (
          <button className="secondary" onClick={() => timeline.fetchNextPage()} disabled={timeline.isFetchingNextPage}>
            {t("Load more")}
          </button>
        )}
        <span>{t("{n} shown", { n: items.length })}</span>
        {hidden.length > 0 && (
          <span>{t("Not shown, no permission: {kinds}", { kinds: hidden.map((kind) => t(kindName(kind))).join(", ") })}</span>
        )}
      </Foot>
    </>
  );
}

/** The name of a kind of record, as the row's badge says it. */
function kindName(kind: HostTimelineKind): string {
  const names: Record<HostTimelineKind, string> = {
    job: "task", audit: "audit", session: "session", lifecycle: "lifecycle", alert: "alert", campaign: "campaign",
  };
  return names[kind];
}

/**
 * The title of a row with the link to its record. A task links to the
 * host's task list and an audit entry to the host's trail, because those
 * are the pages that show the record; a campaign has a page of its own;
 * a session has none and stays text.
 */
function ActivityTitle({ host, item }: { host: Host; item: HostTimelineItem }) {
  const t = useT();
  const target = linkOf(host, item);
  const title = <span className="hm-mono">{item.title || "—"}</span>;
  return (
    <div>
      {target ? <Link to={target}>{title}</Link> : title}
      {/* The event words come from the server in a fixed set (created,
          finished, opened, ended, fired, resolved, selected, started). */}
      {item.event && <span className="source"> · {t(item.event)}</span>}
    </div>
  );
}

function linkOf(host: Host, item: HostTimelineItem): string | undefined {
  switch (item.kind) {
    case "job": return `/hosts/${host.id}/jobs`;
    case "audit":
    case "lifecycle": return `/hosts/${host.id}/audit`;
    case "alert": return `/hosts/${host.id}/monitoring`;
    case "campaign": return `/campaigns/${item.ref.id}`;
    default: return undefined;
  }
}

/**
 * The state of the record, coloured by what it means: a task or a
 * campaign target uses the shared state badge, an audit entry its outcome,
 * a lifecycle change the state the host went into, an alert whether it
 * still fires. An empty state is a dash, not a made-up "ok".
 */
function ActivityState({ item }: { item: HostTimelineItem }) {
  const t = useT();
  if (!item.state) return <>—</>;
  const errorCode = item.error_code ? <span className="source"> {item.error_code}</span> : null;
  switch (item.kind) {
    case "job":
    case "campaign":
      return <><JobState state={item.state} />{errorCode}</>;
    case "audit":
      return <span className={`badge ${item.state === "success" ? "ok" : "error"}`}>{t(item.state)}</span>;
    case "lifecycle":
      return <span className={`badge ${lifecycleTone(item.state)}`}>{t(item.state)}</span>;
    case "alert":
      return <span className={`badge ${item.state === "firing" ? "error" : "ok"}`}>{t(item.state)}</span>;
    case "session":
      return <span className={`badge ${item.state === "open" ? "ok" : ""}`}>{t(item.state)}</span>;
    default:
      return <span className="badge">{item.state}</span>;
  }
}

function lifecycleTone(state: string): string {
  switch (state) {
    case "active": return "ok";
    case "quarantined": return "warn";
    case "retired": return "unknown";
    // A refused or failed attempt carries its outcome in place of a state.
    case "denied":
    case "failure": return "error";
    default: return "";
  }
}

/**
 * The host's adapter registry. The operator sees not only what is missing
 * but also why - the reason comes from the host, not from browser code.
 */
function Adapters({ host }: { host: ReturnType<typeof useHost> }) {
  const t = useT();
  const adapters = host.capabilities ?? [];
  if (adapters.length === 0) {
    return <Empty>{t("This host has not reported its adapters yet.")}</Empty>;
  }
  return (
    <Table>
      <thead><tr><th>{t("Adapter")}</th><th>{t("State")}</th><th>{t("Features")}</th><th>{t("Reason")}</th></tr></thead>
      <tbody>
        {adapters.map((adapter) => (
          <tr key={adapter.name}>
            <td className="hm-mono">{adapter.name}</td>
            <td>
              {!adapter.available ? (
                <span className="badge">{t("unavailable")}</span>
              ) : adapter.read_only ? (
                <span className="badge warn">{t("read only")}</span>
              ) : (
                <span className="badge ok">{t("available")}</span>
              )}
            </td>
            <td className="source">
              {Object.entries(adapter.features ?? {}).length === 0
                ? "—"
                : Object.entries(adapter.features ?? {})
                    .map(([name, present]) => `${name}: ${present ? t("yes") : t("no")}`)
                    .join(", ")}
            </td>
            <td className="source">{adapter.reason || "—"}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
