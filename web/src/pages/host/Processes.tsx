import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown, Meter } from "../../components/widgets";
import {
  Foot, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere,
  useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Process = {
  pid: number;
  ppid: number;
  user?: string;
  command?: string;
  name: string;
  state: string;
  rss_bytes: number;
  threads: number;
  start_time_ticks: number;
  cpu_ticks: number;
  unit?: string;
  container?: string;
};

type Snapshot = { processes?: Process[]; total?: number; truncated?: boolean };

/** One row of the table: the process, and where it stands in the tree. */
type Row = { process: Process; depth: number; children: number };

/**
 * The host's processes.
 *
 * The module is a diagnostic, not an observability system: the snapshot is
 * taken on request and has an upper bound. The trend of the host over
 * time is the Monitoring module's.
 */
export function Processes() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "processes");
  const [sort, setSort] = useState("rss");
  const [filter, setFilter] = useState("");
  const [tree, setTree] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(() => new Set());
  const [toSignal, setToSignal] = useState<{ process: Process; signal: string } | null>(null);
  const [message, setMessage] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setToSignal(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const listed = snapshot?.processes;
  // The meters are read against the largest process in the slice, and the
  // CPU column against the CPU time of the whole slice: the snapshot has no
  // rate, so the share of the time consumed so far is what it can say.
  const maxRss = Math.max(1, ...(listed ?? []).map((process) => process.rss_bytes));
  const cpuTotal = (listed ?? []).reduce((sum, process) => sum + process.cpu_ticks, 0);
  const users = Object.entries((listed ?? []).reduce<Record<string, number>>((acc, process) => {
    const user = process.user || "?";
    acc[user] = (acc[user] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const matches = (process: Process) => {
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return (
      (process.command ?? process.name).toLowerCase().includes(needle) ||
      (process.user ?? "").toLowerCase().includes(needle) ||
      (process.unit ?? "").toLowerCase().includes(needle) ||
      String(process.pid) === filter
    );
  };
  const processes = (snapshot?.processes ?? []).filter(matches);
  // The tree is computed here from the ppid of every row: the host sends a
  // flat slice, and nesting it is the panel's work. A parent outside the
  // slice makes its child a root - the slice is a slice, not the host.
  const rows: Row[] = tree
    ? treeRows(snapshot?.processes ?? [], matches, collapsed)
    : processes.map((process) => ({ process, depth: 0, children: 0 }));

  function toggleNode(pid: number) {
    setCollapsed((previous) => {
      const next = new Set(previous);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  }

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Processes")}
        description={t("A snapshot is read from the host on request; the trend over time is on the Monitoring tab.")}
        actions={
          <>
            <select value={sort} onChange={(e) => setSort(e.target.value)}>
              <option value="rss">{t("by memory")}</option>
              <option value="cpu">{t("by CPU time")}</option>
              <option value="started">{t("by start time")}</option>
              <option value="pid">{t("by PID")}</option>
            </select>
            <button
              onClick={() =>
                request.mutate({
                  action: "process.list",
                  payload: { process_list: { sort_by: sort, limit: 200 } },
                })
              }
              disabled={request.isPending || host.connection_state !== "online"}
            >
              {request.isPending ? t("Requesting…") : t("Read from host")}
            </button>
          </>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      <Widgets>
      {/* The slice by state, then by who runs it; both are dashes until the
          host has been read. */}
      <Summary
        title={t("Process states")}
        description={t("The processes in the snapshot, by their scheduler state.")}
        span={8}
        segments={[
          { label: t("running"), value: countWhere(listed, (p) => p.state.startsWith("R")), tone: "ok" },
          { label: t("sleeping"), value: countWhere(listed, (p) => p.state.startsWith("S")), tone: "neutral" },
          { label: t("waiting on disk"), value: countWhere(listed, (p) => p.state.startsWith("D")), tone: "warn" },
          { label: t("zombie"), value: countWhere(listed, (p) => p.state.startsWith("Z")), tone: "error" },
          { label: t("stopped"), value: countWhere(listed, (p) => p.state.startsWith("T") || p.state.startsWith("t")), tone: "unknown" },
        ]}
      />
      <Section title={t("By user")} span={4} description={t("Who runs the most of the slice.")}>
        {listed ? (
          <Breakdown items={users.map(([user, count]) => ({ label: user, value: count }))} />
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("Known after a read from the host.")}</p>
        )}
        {listed && (
          <>
            <p className="widget-subhead">{t("Managed by")}</p>
            <Breakdown
              items={[
                { label: t("units"), value: countWhere(listed, (p) => !!p.unit && !p.container) ?? 0, tone: "info" },
                { label: t("containers"), value: countWhere(listed, (p) => !!p.container) ?? 0, tone: "info" },
                { label: t("neither"), value: countWhere(listed, (p) => !p.unit && !p.container) ?? 0, tone: "info" },
              ]}
            />
          </>
        )}
      </Section>

      <Section
        title={t("Processes")}
        count={snapshot ? rows.length : undefined}
        span={12}
        tools={snapshot && (
          <>
            <input
              placeholder={t("Filter by command, user, unit or PID")}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            {/* The tree nests children under parents; the flat slice
                sorted by the chosen measure stays the default. */}
            <label className="toggle">
              <input type="checkbox" checked={tree} onChange={(e) => setTree(e.target.checked)} />
              {t("Tree")}
            </label>
          </>
        )}
        flush
      >
        {!snapshot ? (
          <Empty>{t("This host has not been read yet. Use “Read from host”.")}</Empty>
        ) : (
          <>
            {/* A cut-off list is marked together with the count of all the
                processes: without it, it would look like a full picture of
                the host. */}
            {snapshot.truncated && (
              <p className="warning">
                <span>
                  {t("Showing {shown} of {total} processes. Change the sort order to see a different slice.", {
                    shown: snapshot.processes?.length ?? 0, total: snapshot.total ?? 0,
                  })}
                </span>
              </p>
            )}
            <Table>
              <thead>
                <tr>
                  <th className="hm-num">PID</th><th>{t("User")}</th><th>{t("Memory")}</th><th>{t("CPU share")}</th><th className="hm-num">{t("Threads")}</th>
                  <th>{t("State")}</th><th>{t("Managed by")}</th><th>{t("Command")}</th><th>{t("Actions")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ process, depth, children }) => (
                  <tr key={process.pid}>
                    <td className="hm-num">{process.pid}</td>
                    <td>{process.user || <span className="badge unknown">{t("unknown")}</span>}</td>
                    <td><Meter value={process.rss_bytes} max={maxRss} tone="info" text={bytes(process.rss_bytes)} /></td>
                    <td>
                      <Meter
                        value={process.cpu_ticks}
                        max={cpuTotal}
                        tone="info"
                        text={cpuTotal > 0 ? `${(process.cpu_ticks / cpuTotal * 100).toFixed(1)}%` : "—"}
                      />
                    </td>
                    <td className="hm-num">{process.threads}</td>
                    <td>{process.state}</td>
                    {/* The PID alone says nothing about whose process it is. */}
                    <td className="hm-mono">
                      {process.container
                        ? `${t("container")} ${process.container.slice(0, 12)}`
                        : process.unit || "—"}
                    </td>
                    {/* In the tree the command is indented by its depth and a
                        parent carries the fold; the flat table has neither. */}
                    <td className="hm-mono" title={process.command || process.name}>
                      {tree && depth > 0 && <span style={{ display: "inline-block", width: depth * 16 }} />}
                      {tree && children > 0 && (
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => toggleNode(process.pid)}
                          aria-expanded={!collapsed.has(process.pid)}
                          title={collapsed.has(process.pid) ? t("Show {n} children", { n: children }) : t("Hide children")}
                        >
                          {collapsed.has(process.pid) ? "▸" : "▾"}
                        </button>
                      )}
                      {tree && children > 0 && " "}
                      {(process.command || process.name).slice(0, 60)}
                    </td>
                    <td>
                      <div className="operations">
                        <button onClick={() => setToSignal({ process, signal: "TERM" })}>Term</button>
                        <button onClick={() => setToSignal({ process, signal: "HUP" })}>HUP</button>
                        <button className="hm-danger" onClick={() => setToSignal({ process, signal: "KILL" })}>Kill</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Foot>
              <span>
                {t("{shown} of {listed} shown · {total} on the host · read", {
                  shown: rows.length, listed: snapshot.processes?.length ?? 0, total: snapshot.total ?? 0,
                })}{" "}
                <Time value={module.data?.observed_at} />
              </span>
            </Foot>
          </>
        )}
      </Section>
      </Widgets>

      {toSignal && (
        <TargetConfirmation
          host={host}
          label={t("Send {signal}", { signal: toSignal.signal })}
          description={
            toSignal.signal === "KILL"
              ? t("PID {pid} ({command}) will be killed without a chance to clean up.", {
                  pid: toSignal.process.pid, command: toSignal.process.command || toSignal.process.name,
                })
              : t("PID {pid} ({command}) will receive {signal}.", {
                  pid: toSignal.process.pid, command: toSignal.process.command || toSignal.process.name, signal: toSignal.signal,
                })
          }
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              action: "process.signal",
              reason,
              payload: {
                process_signal: {
                  pid: toSignal.process.pid,
                  // The start time ties the job to this process: the PID
                  // alone may meanwhile belong to a completely different one.
                  expected_start_ticks: toSignal.process.start_time_ticks,
                  signal: toSignal.signal,
                  command: toSignal.process.command || toSignal.process.name,
                },
              },
            })
          }
          onCancel={() => setToSignal(null)}
        />
      )}
    </ModulePage>
  );
}

/**
 * The rows of the tree: every process under its parent, in the order of
 * the slice, with the collapsed branches folded away. A filter keeps the
 * matching processes and the path down to them, so a match deep in the
 * tree is still seen where it stands.
 */
function treeRows(processes: Process[], matches: (process: Process) => boolean, collapsed: Set<number>): Row[] {
  const byPid = new Map<number, Process>(processes.map((process) => [process.pid, process]));
  const children = new Map<number, Process[]>();
  const roots: Process[] = [];
  for (const process of processes) {
    // A parent outside the slice makes its child a root: the slice is what
    // the host sent, not the whole host.
    const parent = process.ppid !== process.pid ? byPid.get(process.ppid) : undefined;
    if (!parent) {
      roots.push(process);
      continue;
    }
    const siblings = children.get(parent.pid) ?? [];
    siblings.push(process);
    children.set(parent.pid, siblings);
  }

  // A row is kept when it matches or when something under it does.
  const kept = new Map<number, boolean>();
  const keep = (process: Process): boolean => {
    const known = kept.get(process.pid);
    if (known !== undefined) return known;
    // Written before the descent, so a cycle in the data cannot loop.
    kept.set(process.pid, false);
    let result = matches(process);
    for (const child of children.get(process.pid) ?? []) {
      if (keep(child)) result = true;
    }
    kept.set(process.pid, result);
    return result;
  };

  const rows: Row[] = [];
  const walk = (process: Process, depth: number) => {
    if (!keep(process)) return;
    const below = (children.get(process.pid) ?? []).filter(keep);
    rows.push({ process, depth, children: below.length });
    if (collapsed.has(process.pid)) return;
    for (const child of below) walk(child, depth + 1);
  };
  for (const root of roots) walk(root, 0);
  return rows;
}
