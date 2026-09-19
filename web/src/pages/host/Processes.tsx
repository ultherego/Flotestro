import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown, Meter } from "../../components/widgets";
import { ColumnChooser, Td, Th, useColumns, type ColumnDef } from "../../components/SortableTable";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import {
  Foot, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere,
  useHost, useModule, useModuleRefresh,
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
 * The scheduler state in words.
 */
export function stateWords(state: string): string {
  switch (state.charAt(0)) {
    case "R": return "running";
    case "S": return "sleeping";
    case "D": return "waiting on disk";
    case "Z": return "zombie";
    case "T":
    case "t": return "stopped";
    case "I": return "idle";
    case "X": return "dead";
    default: return state;
  }
}

/**
 * Whether a process is a kernel thread: a child of kthreadd (PID 2) or
 * kthreadd itself.
 */
export function kernelThread(process: Pick<Process, "pid" | "ppid">): boolean {
  return process.pid === 2 || process.ppid === 2;
}

/**
 * The host's processes. The module is a diagnostic, not an observability
 * system: the snapshot is taken on request and has an upper bound.
 */
/**
 * The columns of the process table.
 */
export function processColumns(t: (text: string) => string): ColumnDef[] {
  return [
    { key: "pid", label: "PID", fixed: true, className: "hm-num" },
    { key: "user", label: t("User") },
    { key: "memory", label: t("Memory") },
    { key: "cpu", label: t("CPU time share"), secondary: true },
    { key: "threads", label: t("Threads"), secondary: true, className: "hm-num" },
    { key: "state", label: t("State") },
    { key: "managed_by", label: t("Managed by") },
    { key: "command", label: t("Command"), fixed: true },
    { key: "actions", label: t("Actions") },
  ];
}

export function Processes() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "processes");
  // The snapshot lands in the inventory when the read is over.
  const refresh = useModuleRefresh(host.id, ["processes"]);
  const [sort, setSort] = useState("rss");
  const [filter, setFilter] = useState("");
  const [tree, setTree] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(() => new Set());
  // The columns of the table, remembered per table in the browser.
  const columns = useColumns("host-processes", processColumns(t));
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
      refresh(job);
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
  // flat slice, and nesting it is the panel's work.
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
      <ReadOnlyModuleNotice host={host.id} actions={["process.signal"]} />
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
            <ColumnChooser columns={columns} />
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
                  {/* The snapshot has no rate: the share is of the CPU time
                      the slice has used since its processes started. */}
                  {columns.all.map((column) => (
                    <Th
                      key={column.key}
                      columns={columns}
                      name={column.key}
                      title={column.key === "cpu" ? t("The share of the CPU time used so far by the processes in this slice, not a load of the moment.") : undefined}
                    />
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map(({ process, depth, children }) => (
                  <tr key={process.pid}>
                    <Td columns={columns} name="pid">{process.pid}</Td>
                    <Td columns={columns} name="user">{process.user || <span className="badge unknown">{t("unknown")}</span>}</Td>
                    <Td columns={columns} name="memory">
                      {kernelThread(process)
                        ? <span className="source" title={t("A kernel thread has no address space of its own.")}>—</span>
                        : <Meter value={process.rss_bytes} max={maxRss} tone="info" text={bytes(process.rss_bytes)} />}
                    </Td>
                    <Td columns={columns} name="cpu">
                      <Meter
                        value={process.cpu_ticks}
                        max={cpuTotal}
                        tone="info"
                        text={cpuTotal > 0 ? `${(process.cpu_ticks / cpuTotal * 100).toFixed(1)}%` : "—"}
                      />
                    </Td>
                    <Td columns={columns} name="threads">{process.threads}</Td>
                    <Td columns={columns} name="state" title={process.state}>{t(stateWords(process.state))}</Td>
                    {/* The PID alone says nothing about whose process it is. */}
                    <Td columns={columns} name="managed_by" className="hm-mono">
                      {process.container
                        ? `${t("container")} ${process.container.slice(0, 12)}`
                        : process.unit || (kernelThread(process) ? <span className="source">{t("kernel")}</span> : "—")}
                    </Td>
                    {/* In the tree the command is indented by its depth and a
                        parent carries the fold; the flat table has neither. */}
                    <Td columns={columns} name="command" className="hm-mono" title={process.command || process.name}>
                      {tree && depth > 0 && (
                        <span data-testid="process-indent" data-depth={depth} style={{ display: "inline-block", width: depth * 16 }} />
                      )}
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
                    </Td>
                    {/* PID 1 and a kernel thread take no signal from here:
                        init ignores what it does not handle and a kernel
                        thread cannot be ended; the buttons say so instead
                        of ordering a job the host refuses. The agent's own
                        process is a warning, not a refusal - killing it
                        cuts the host off until systemd brings it back. */}
                    <Td columns={columns} name="actions">
                      {process.pid === 1 || kernelThread(process) ? (
                        <span className="source" title={process.pid === 1
                          ? t("PID 1 ignores signals it does not handle; a reboot is ordered on the Power tab.")
                          : t("A kernel thread cannot be signalled.")}>
                          {t("no signal")}
                        </span>
                      ) : (
                        <ActionGuard action="process.signal" host={host.id}>
                          <div className="operations" title={agentProcess(process) ? t("This is the agent that carries out the order: the host goes offline until systemd restarts it.") : undefined}>
                            <button onClick={() => setToSignal({ process, signal: "TERM" })}>{t("Term")}</button>
                            <button onClick={() => setToSignal({ process, signal: "HUP" })}>HUP</button>
                            <button className="hm-danger" onClick={() => setToSignal({ process, signal: "KILL" })}>{t("Kill")}</button>
                          </div>
                        </ActionGuard>
                      )}
                    </Td>
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
            (toSignal.signal === "KILL"
              ? t("PID {pid} ({command}) will be killed without a chance to clean up.", {
                  pid: toSignal.process.pid, command: toSignal.process.command || toSignal.process.name,
                })
              : t("PID {pid} ({command}) will receive {signal}.", {
                  pid: toSignal.process.pid, command: toSignal.process.command || toSignal.process.name, signal: toSignal.signal,
                }))
            + (agentProcess(toSignal.process)
              ? " " + t("This is the agent itself: the host goes offline until systemd restarts it, and the result of this job may never be reported.")
              : "")
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

/** Whether the process is the agent the panel talks through. */
function agentProcess(process: Process): boolean {
  return process.unit === "flotestro-agent.service";
}

/**
 * The rows of the tree: every process under its parent, in the order of the
 * slice, with the collapsed branches folded away.
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
