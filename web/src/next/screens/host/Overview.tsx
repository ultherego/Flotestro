import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../../../lib/api";
import { bytes, relativeTime, absoluteTime } from "../../../lib/format";
import { REFRESH_INTERVAL } from "../../../lib/stream";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { stateName } from "../../../components/ui";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Card, Empty, Fact, Facts, Kpi, Meter, Needs, Pill, Table, type Segment, type Tone,
} from "../../kit";

/**
 * What this machine is: what it is made of, what it is carrying, and what
 * has lately been done to it.
 *
 * Everything on it is read. A figure the host never reported is an em dash
 * and says so - the one place that matters most, because a nought on a
 * disk reads as "plenty of room" about a machine nobody has asked.
 */

type SystemState = {
  os?: Record<string, string>;
  hostname?: string;
  hardware?: {
    cpu_cores?: number;
    memory_bytes?: number;
    root_fs_bytes?: number;
    root_fs_free_bytes?: number;
    virtualization?: string;
  };
};

/**
 * How full the root filesystem is, and whether that is a condition.
 *
 * Three answers rather than two: a host that has not reported its disk is
 * unknown, not empty. The thresholds are the ones an operator acts on -
 * past ninety per cent a full disk is a matter of hours, past eighty it is
 * a matter of planning.
 */
export function diskPressure(total?: number, free?: number): { used?: number; share?: number; tone?: Tone } {
  if (total === undefined || free === undefined || total <= 0) return {};
  const used = total - free;
  const share = used / total;
  return { used, share, tone: share > 0.9 ? "error" : share > 0.8 ? "warn" : "ok" };
}

export function Overview({ host }: { host: Host }) {
  const t = useT();

  const system = useQuery({
    queryKey: ["inventory", host.id, "system"],
    queryFn: () => api.get<InventoryFragment<SystemState>>(`/api/v1/hosts/${host.id}/inventory/system`),
    retry: false,
  });
  const jobs = useQuery({
    queryKey: ["jobs", host.id, "recent"],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=8`),
    refetchInterval: REFRESH_INTERVAL,
  });

  const hardware = system.data?.payload?.hardware;
  const root = diskPressure(hardware?.root_fs_bytes, hardware?.root_fs_free_bytes);
  // A host that has not reported its adapters has an unknown registry, not
  // an empty one.
  const adapters = host.capabilities?.length ? host.capabilities : undefined;
  const available = adapters?.filter((one) => one.available).length;
  const unavailable = adapters === undefined ? undefined : adapters.length - (available ?? 0);
  const readOnly = adapters?.filter((one) => one.available && one.read_only).length;

  const registry: Segment[] = [
    { label: t("available"), value: available, tone: "ok" },
    { label: t("unavailable"), value: unavailable, tone: "neutral" },
  ];

  /* What is wrong with this machine right now, counted apart from what it
     is made of: a reader asks "is it well" before "what is it". */
  const attention: { label: string; value?: number | boolean | null; tone: Tone; to?: string }[] = [
    { label: t("Failed units"), value: host.failed_units, tone: "error", to: `/next/hosts/${host.id}/services` },
    { label: t("Reboot required"), value: host.reboot_required, tone: "warn" },
    { label: t("Package database broken"), value: host.package_database_broken, tone: "error" },
    { label: t("Security updates"), value: host.pending_security_updates, tone: "warn", to: `/next/hosts/${host.id}/packages` },
    { label: t("Updates waiting"), value: host.pending_updates, tone: "neutral", to: `/next/hosts/${host.id}/packages` },
  ];

  return (
    <Board screen="next_host_overview" catalogue={HOST_OVERVIEW} drawn={{
      disk: (
        <Kpi
          icon="storage"
          label={t("Disk used")}
          value={root.share === undefined ? null : Math.round(root.share * 100)}
          unit="%"
          tone={root.tone}
          note={root.used === undefined || hardware?.root_fs_bytes === undefined
            ? undefined
            : t("{used} of {total}", { used: bytes(root.used), total: bytes(hardware.root_fs_bytes) })}
        />
      ),
      memory: (
        <Kpi
          icon="server"
          label={t("Memory")}
          value={hardware?.memory_bytes === undefined ? null : bytes(hardware.memory_bytes)}
          note={hardware?.virtualization ? t("on {what}", { what: hardware.virtualization }) : undefined}
        />
      ),
      cores: (
        <Kpi icon="overview" label={t("CPU cores")} value={hardware?.cpu_cores ?? null} />
      ),
      adapters: (
        <Card
          title={t("What the panel can do here")}
          note={t("The adapters this host reported, and what each of them allows.")}
          foot={readOnly !== undefined && readOnly > 0 ? t("{n} of them read only.", { n: readOnly }) : undefined}
        >
          {adapters === undefined
            ? <Empty>{t("This host has not reported its adapters yet.")}</Empty>
            : <Band segments={registry} testId="adapters" />}
        </Card>
      ),
      attention: (
        <Card title={t("Needs attention")} note={t("Counted by the agent on its last report.")}>
          <Needs items={attention.map((one) => ({
            label: one.label,
            value: one.value ?? undefined,
            tone: one.tone,
            quiet: one.value === false || one.value === 0,
            to: one.to && one.value !== false && one.value !== 0 && one.value !== null && one.value !== undefined
              ? one.to
              : undefined,
          }))} />
        </Card>
      ),
      system: (
        <Card
          title={t("System")}
          foot={system.data
            ? t("Source: {source}, revision {revision}, observed {when}", {
                source: system.data.source,
                revision: system.data.revision.slice(0, 12),
                when: relativeTime(system.data.observed_at),
              })
            : undefined}
        >
          <Facts>
            <Fact label={t("Hostname")}>{host.hostname}</Fact>
            <Fact label={t("System")}>
              {host.os_distribution || host.os_family || <span className="fl-faint">{t("unknown")}</span>}
              {host.os_version ? ` ${host.os_version}` : ""}
            </Fact>
            <Fact label={t("Architecture")}>{host.architecture || <span className="fl-faint">{t("unknown")}</span>}</Fact>
            <Fact label={t("Agent")}>{host.agent_version || <span className="fl-faint">{t("unknown")}</span>}</Fact>
            <Fact label={t("Site / environment")}>{host.site} / {host.environment}</Fact>
            <Fact label={t("Owner")}>{host.owner || <span className="fl-faint">{t("nobody")}</span>}</Fact>
            <Fact label={t("Management address")}>
              <span className="fl-mono">{host.management_address || <span className="fl-faint">{t("unknown")}</span>}</span>
            </Fact>
            <Fact label={t("Failure domain")}>{host.failure_domain || <span className="fl-faint">{t("not placed")}</span>}</Fact>
          </Facts>
        </Card>
      ),
      hardware: (
        <Card title={t("Hardware")}>
          <Facts>
            <Fact label={t("CPU cores")}>{hardware?.cpu_cores ?? <span className="fl-faint">—</span>}</Fact>
            <Fact label={t("Memory")}>
              {hardware?.memory_bytes === undefined ? <span className="fl-faint">—</span> : bytes(hardware.memory_bytes)}
            </Fact>
            <Fact label={t("Virtualization")}>
              {hardware?.virtualization || <span className="fl-faint">{t("unknown")}</span>}
            </Fact>
            <Fact label={t("Root filesystem")}>
              {root.share === undefined
                ? <span className="fl-faint">—</span>
                : (
                  <Meter
                    share={root.share}
                    tone={root.tone}
                    text={t("{free} free of {total}", {
                      free: bytes((hardware?.root_fs_free_bytes ?? 0)),
                      total: bytes((hardware?.root_fs_bytes ?? 0)),
                    })}
                  />
                )}
            </Fact>
          </Facts>
        </Card>
      ),
      lifecycle: (
        <Card title={t("Lifecycle")}>
          <Facts>
            <Fact label={t("State")}>
              <Pill tone={host.lifecycle_state === "active" ? "ok" : "warn"}>{t(host.lifecycle_state)}</Pill>
            </Fact>
            <Fact label={t("Enrolled")}>
              <span title={absoluteTime(host.enrolled_at)}>{relativeTime(host.enrolled_at)}</span>
            </Fact>
            <Fact label={t("Last seen")}>
              {host.last_seen_at
                ? <span title={absoluteTime(host.last_seen_at)}>{relativeTime(host.last_seen_at)}</span>
                : <span className="fl-faint">{t("never")}</span>}
            </Fact>
            <Fact label={t("Release channel")}>{host.release_channel}</Fact>
            {host.maintenance && (
              <Fact label={t("Maintenance until")}>
                <span title={absoluteTime(host.maintenance.until)}>{relativeTime(host.maintenance.until)}</span>
              </Fact>
            )}
            {host.lifecycle_reason && <Fact label={t("Reason")}>{host.lifecycle_reason}</Fact>}
          </Facts>
        </Card>
      ),
      recent: (
        <Card
          title={t("Recent activity")}
          tools={<Link to={`/next/hosts/${host.id}/jobs`}>{t("All jobs")}</Link>}
          flush
        >
          <Table
            rows={jobs.data?.items ?? []}
            keyOf={(one) => one.id}
            empty={jobs.isLoading ? t("Loading…") : t("Nothing has been done to this host yet.")}
            columns={[
              { key: "when", head: t("Time"), cell: (one) => (
                <Link to={`/jobs/${one.id}`} title={absoluteTime(one.created_at)}>
                  {relativeTime(one.finished_at ?? one.created_at)}
                </Link>
              ) },
              { key: "what", head: t("Operation"), tight: true, cell: (one) => <code title={one.action_type}>{one.action_type}</code> },
              { key: "state", head: t("Outcome"), cell: (one) => (
                <Pill tone={jobTone(one.state)}>{t(stateName(one.state))}</Pill>
              ) },
              { key: "error", head: t("Error"), minor: true, tight: true, cell: (one) => (
                one.result_error_code
                  ? <code title={one.result_error_code}>{one.result_error_code}</code>
                  : <span className="fl-faint">—</span>
              ) },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

/** The outcome of a job as a state: waiting is a person, failed is a fault. */
function jobTone(state: string): Tone {
  if (["succeeded", "completed", "no_change", "active"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired", "partially_applied", "plan_failed"].includes(state)) return "error";
  if (["ineligible", "skipped", "superseded_by_result", "unknown"].includes(state)) return "unknown";
  return "warn";
}

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_OVERVIEW: BoardEntry[] = [
  { key: "disk", title: "Disk used", width: 4, height: 2 },
  { key: "memory", title: "Memory", width: 4, height: 2 },
  { key: "cores", title: "CPU cores", width: 4, height: 2 },
  { key: "adapters", title: "What the panel can do here", width: 7, height: 3 },
  { key: "attention", title: "Needs attention", width: 5, height: 3 },
  { key: "system", title: "System", width: 7, height: 4 },
  { key: "hardware", title: "Hardware", width: 5, height: 4 },
  { key: "lifecycle", title: "Lifecycle", width: 5, height: 3 },
  { key: "recent", title: "Recent activity", width: 7, height: 5 },
];

/** The name this screen's arrangement is stored under. */
export const HOST_OVERVIEW_SCREEN = "next_host_overview";
