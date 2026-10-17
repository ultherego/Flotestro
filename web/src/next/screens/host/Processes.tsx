import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { bytes, relativeTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { kernelThread, stateWords } from "../../../lib/host/processes";
import { useModuleRefresh } from "../../../lib/host/module";
import { useT } from "../../../i18n";
import {
  Band, Banner, Bars, Button, C, Card, Check, Empty, Field, Fields, Find, Grid, HeadActions, Meter,
  Modal, Note, Pill, Problem, Seg, Table, Tabs, Toolbar, useTab, type Segment, type Tone,
} from "../../kit";

/** The sub-tabs of this screen, in the order a reader wants them. */
const PROCESS_TABS = ["state", "list"] as const;

/**
 * The processes of one host, as a slice the operator asked for.
 *
 * This is a diagnostic and not an observability system: the host is read
 * on request, the answer has an upper bound, and the screen says so
 * rather than letting a bounded slice read as the whole machine. The
 * trend over time lives on Monitoring.
 */

export type Process = {
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
export type Row = { process: Process; depth: number; children: number };

/** How a process's scheduler state reads as a condition. */
export function processTone(state: string): Tone {
  const letter = state.charAt(0);
  if (letter === "R") return "ok";
  if (letter === "Z") return "error";
  if (letter === "D") return "warn";
  if (letter === "T" || letter === "t") return "unknown";
  return "neutral";
}

/** Whether the process is the agent the panel talks through. */
export function agentProcess(process: Process): boolean {
  return process.unit === "flotestro-agent.service";
}

/** A count of what satisfies a test, or nothing at all when the list is unread. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/**
 * The rows of the tree: every process under its parent, in the order of
 * the slice, with the collapsed branches folded away.
 */
export function treeRows(
  processes: Process[], matches: (process: Process) => boolean, collapsed: Set<number>,
): Row[] {
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

/** A control that exists only where the order it places would be taken. */
function Guard({ action, host, explain, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

type Sort = "rss" | "cpu" | "started" | "pid";

export function Processes({ host }: { host: Host }) {
  const t = useT();
  const [tab, go] = useTab(PROCESS_TABS);
  const queryClient = useQueryClient();

  const module = useQuery({
    queryKey: ["inventory", host.id, "processes"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/processes`),
    retry: false,
  });
  // The snapshot lands in the inventory when the read is over.
  const refresh = useModuleRefresh(host.id, ["processes"]);

  const [sort, setSort] = useState<Sort>("rss");
  const [filter, setFilter] = useState("");
  const [tree, setTree] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(() => new Set());
  const [toSignal, setToSignal] = useState<{ process: Process; signal: string } | null>(null);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setProblem("");
      setNotice(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      setToSignal(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refresh(job);
    },
    onError: (error) => setProblem(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const listed = snapshot?.processes;
  // The meters are read against the largest process in the slice, and the
  // CPU column against the CPU time of the whole slice: the snapshot has
  // no rate, so the share of the time consumed so far is what it can say.
  const maxRss = Math.max(1, ...(listed ?? []).map((process) => process.rss_bytes));
  const cpuTotal = (listed ?? []).reduce((sum, process) => sum + process.cpu_ticks, 0);
  const users = Object.entries((listed ?? []).reduce<Record<string, number>>((into, process) => {
    const user = process.user || "?";
    into[user] = (into[user] ?? 0) + 1;
    return into;
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
  // The tree is computed here from the ppid of every row: the host sends a
  // flat slice, and nesting it is the panel's work.
  const rows: Row[] = tree
    ? treeRows(listed ?? [], matches, collapsed)
    : (listed ?? []).filter(matches).map((process) => ({ process, depth: 0, children: 0 }));

  const toggleNode = (pid: number) => {
    setCollapsed((previous) => {
      const next = new Set(previous);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  };

  const states: Segment[] = [
    { label: t("running"), value: countWhere(listed, (one) => one.state.startsWith("R")), tone: "ok" },
    { label: t("sleeping"), value: countWhere(listed, (one) => one.state.startsWith("S")), tone: "neutral" },
    { label: t("waiting on disk"), value: countWhere(listed, (one) => one.state.startsWith("D")), tone: "warn" },
    { label: t("zombie"), value: countWhere(listed, (one) => one.state.startsWith("Z")), tone: "error" },
    {
      label: t("stopped"),
      value: countWhere(listed, (one) => one.state.startsWith("T") || one.state.startsWith("t")),
      tone: "unknown",
    },
  ];

  const freshness = module.data
    ? t("Source: {source}, revision {revision}, observed {when}", {
        source: module.data.source,
        revision: module.data.revision.slice(0, 12),
        when: relativeTime(module.data.observed_at),
      })
    : undefined;

  return (
    <>
      <HeadActions>
        <Seg<Sort>
          value={sort}
          onChange={setSort}
          label={t("Which slice of the host to read")}
          options={[
            { value: "rss", label: t("by memory") },
            { value: "cpu", label: t("by CPU time") },
            { value: "started", label: t("by start time") },
            { value: "pid", label: t("by PID") },
          ]}
        />
        <Guard action="process.list" host={host.id} explain>
          <Button
            onClick={() => request.mutate({
              action: "process.list",
              payload: { process_list: { sort_by: sort, limit: 200 } },
            })}
            disabled={request.isPending || host.connection_state !== "online"}
            testId="read-processes"
          >
            {request.isPending ? t("Requesting…") : t("Read from host")}
          </Button>
        </Guard>
      </HeadActions>

      <ReadOnlyNotice host={host.id} actions={["process.signal"]} />
      {module.data?.unavailable_reason && (
        <Banner tone="warn">
          {t("The processes could not be read: {reason}", { reason: module.data.unavailable_reason })}
        </Banner>
      )}
      {/* A cut-off list is marked together with the count of all the
          processes: without it, it would read as the whole host. */}
      {snapshot?.truncated && (
        <Banner tone="warn">
          {t("Showing {shown} of {total} processes. Change the sort order to see a different slice.", {
            shown: snapshot.processes?.length ?? 0, total: snapshot.total ?? 0,
          })}
        </Banner>
      )}
      {notice && <Banner tone="info">{notice}</Banner>}
      {problem && <Problem>{problem}</Problem>}

      {toSignal && (
        <SignalProcess
          host={host}
          process={toSignal.process}
          signal={toSignal.signal}
          busy={request.isPending}
          onCancel={() => setToSignal(null)}
          onConfirm={(reason) => request.mutate({
            action: "process.signal",
            reason,
            payload: {
              process_signal: {
                pid: toSignal.process.pid,
                // The start time ties the job to this process: the PID
                // alone may meanwhile belong to a different one.
                expected_start_ticks: toSignal.process.start_time_ticks,
                signal: toSignal.signal,
                command: toSignal.process.command || toSignal.process.name,
              },
            },
          })}
        />
      )}

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "state", label: t("State") },
          { value: "list", label: t("List") },
        ]}
      />

      {tab === "state" && (
        <Grid>
          <C span={12}>
            <Card
              title={t("Process states")}
              note={t("The processes in the snapshot, by their scheduler state.")}
              foot={freshness}
            >
              <Band segments={states} testId="process-states" />
            </Card>
          </C>
          <C span={12}>
            <Card title={t("By user")} note={t("Who runs the most of the slice.")}>
              {listed
                ? <Bars items={users.map(([user, count]) => ({ label: user, value: count }))} />
                : <Empty icon="help">{t("Known after a read from the host.")}</Empty>}
            </Card>
          </C>
          <C span={12}>
            <Card
              title={t("Managed by")}
              note={t("Whether something on the host answers for a process, or nothing does.")}
            >
              {listed
                ? (
                  <Bars items={[
                    { label: t("units"), value: countWhere(listed, (one) => !!one.unit && !one.container) ?? 0, tone: "info" },
                    { label: t("containers"), value: countWhere(listed, (one) => !!one.container) ?? 0, tone: "info" },
                    { label: t("neither"), value: countWhere(listed, (one) => !one.unit && !one.container) ?? 0, tone: "info" },
                  ]} />
                )
                : <Empty icon="help">{t("Known after a read from the host.")}</Empty>}
            </Card>
          </C>
        </Grid>
      )}

      {tab === "list" && (
        <Grid>
          <C span={12}>
            <Card
              title={t("Processes")}
              note={t("A snapshot is read from the host on request; the trend over time is on Monitoring.")}
              foot={snapshot
                ? t("{shown} of {listed} shown · {total} on the host", {
                    shown: rows.length,
                    listed: snapshot.processes?.length ?? 0,
                    total: snapshot.total ?? 0,
                  })
                : undefined}
              flush
            >
              <Toolbar>
                <Find
                  value={filter}
                  onChange={setFilter}
                  placeholder={t("Filter by command, user, unit or PID")}
                  testId="process-filter"
                />
                {/* The tree nests children under parents; the flat slice in
                    the chosen order stays the default. */}
                <Check checked={tree} onChange={setTree}>{t("Tree")}</Check>
              </Toolbar>
              {!snapshot
                ? <Empty icon="processes">{t("This host has not been read yet. Use “Read from host”.")}</Empty>
                : (
                  <Table
                    rows={rows}
                    keyOf={({ process }) => String(process.pid)}
                    rowTestId={({ process }) => `process-${process.pid}`}
                    testId="processes"
                    empty={t("No process answers this filter.")}
                    /* The columns an operator folds away are this browser's;
                       the PID and the command are the row's identity and
                       cannot be folded. */
                    remember="fl.columns.host-processes"
                    columns={[
                      { key: "pid", head: "PID", num: true, cell: ({ process }) => process.pid },
                      {
                        key: "user", head: t("User"), optional: true,
                        cell: ({ process }) => process.user || <Pill tone="unknown">{t("unknown")}</Pill>,
                      },
                      {
                        key: "memory", head: t("Memory"), optional: true, cell: ({ process }) => (
                          kernelThread(process)
                            ? <span title={t("A kernel thread has no address space of its own.")}>—</span>
                            : <Meter share={process.rss_bytes / maxRss} tone="info" text={bytes(process.rss_bytes)} />
                        ),
                      },
                      {
                        key: "cpu", head: t("CPU time share"), minor: true, optional: true, cell: ({ process }) => (
                          <Meter
                            share={cpuTotal > 0 ? process.cpu_ticks / cpuTotal : 0}
                            tone="info"
                            text={cpuTotal > 0 ? `${(process.cpu_ticks / cpuTotal * 100).toFixed(1)}%` : "—"}
                          />
                        ),
                      },
                      {
                        key: "threads", head: t("Threads"), num: true, minor: true, optional: true,
                        cell: ({ process }) => process.threads,
                      },
                      {
                        key: "state", head: t("State"), optional: true, cell: ({ process }) => (
                          <Pill tone={processTone(process.state)} title={process.state}>
                            {t(stateWords(process.state))}
                          </Pill>
                        ),
                      },
                      /* The PID alone says nothing about whose process it is. */
                      {
                        key: "managed", head: t("Managed by"), minor: true, tight: true, optional: true,
                        cell: ({ process }) => (
                          process.container
                            ? `${t("container")} ${process.container.slice(0, 12)}`
                            : process.unit || (kernelThread(process) ? t("kernel") : "—")
                        ),
                      },
                      /* In the tree the command is set in by its depth and a
                         parent carries the fold; the flat table has neither.
                         The setting-in is the kit's and is measured: a run of
                         non-breaking spaces is read aloud by a screen reader
                         and travels with the command when it is copied. */
                      {
                        key: "command", head: t("Command"), tight: true,
                        indent: ({ depth }) => (tree ? depth : 0),
                        cell: ({ process, children }) => (
                          <>
                            {tree && children > 0 && (
                              <Button
                                kind="word"
                                onClick={() => toggleNode(process.pid)}
                                title={collapsed.has(process.pid)
                                  ? t("Show {n} children", { n: children })
                                  : t("Hide children")}
                              >
                                {collapsed.has(process.pid) ? "▸" : "▾"}
                              </Button>
                            )}
                            {tree && children > 0 ? " " : ""}
                            <span title={process.command || process.name}>
                              {(process.command || process.name).slice(0, 60)}
                            </span>
                          </>
                        ),
                      },
                      /* PID 1 and a kernel thread take no signal from here:
                         init ignores what it does not handle and a kernel
                         thread cannot be ended, so the cell says so rather
                         than ordering a job the host will refuse. The
                         agent's own process is a warning, not a refusal. */
                      {
                        key: "actions", head: t("Actions"), actions: true, optional: true, cell: ({ process }) => (
                          process.pid === 1 || kernelThread(process) ? (
                            <span title={process.pid === 1
                              ? t("PID 1 ignores signals it does not handle; a reboot is ordered on the Power screen.")
                              : t("A kernel thread cannot be signalled.")}>
                              {t("no signal")}
                            </span>
                          ) : (
                            <Guard action="process.signal" host={host.id}>
                              <Button
                                kind="quiet"
                                onClick={() => setToSignal({ process, signal: "TERM" })}
                                title={agentProcess(process)
                                  ? t("This is the agent that carries out the order: the host goes offline until systemd restarts it.")
                                  : undefined}
                                testId={`term-${process.pid}`}
                              >
                                {t("Term")}
                              </Button>
                              <Button kind="quiet" onClick={() => setToSignal({ process, signal: "HUP" })}>HUP</Button>
                              <Button kind="danger" onClick={() => setToSignal({ process, signal: "KILL" })}>{t("Kill")}</Button>
                            </Guard>
                          )
                        ),
                      },
                    ]}
                  />
                )}
            </Card>
          </C>
        </Grid>
      )}
    </>
  );
}

/** How long a reason has to be before the trail will take it. */
export const REASON_MIN_LENGTH = 8;

/** Ending somebody else's process is asked for by name, with a reason. */
function SignalProcess({ host, process, signal, busy, onConfirm, onCancel }: {
  host: Host;
  process: Process;
  signal: string;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= REASON_MIN_LENGTH && confirmation === host.hostname;
  const command = process.command || process.name;

  return (
    <Modal
      title={t("Send {signal}", { signal })}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button kind="danger" disabled={!ready || busy} onClick={() => onConfirm(reason.trim())} testId="signal-confirm">
            {busy ? t("Requesting…") : t("Send {signal}", { signal })}
          </Button>
        </>
      }
    >
      <Note>
        {signal === "KILL"
          ? t("PID {pid} ({command}) will be killed without a chance to clean up.", { pid: process.pid, command })
          : t("PID {pid} ({command}) will receive {signal}.", { pid: process.pid, command, signal })}
      </Note>
      {agentProcess(process) && (
        <Banner tone="error">
          {t("This is the agent itself: the host goes offline until systemd restarts it, and the result of this job may never be reported.")}
        </Banner>
      )}
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="signal-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            data-testid="signal-hostname"
          />
        </Field>
      </Fields>
    </Modal>
  );
}
