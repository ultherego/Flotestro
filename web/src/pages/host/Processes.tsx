import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { ModuleFreshness, useHost, useModule } from "./shared";
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

/**
 * The host's processes.
 *
 * The module is a diagnostic, not an observability system: the snapshot is
 * taken on request and has an upper bound. Long-term metrics belong to
 * Prometheus.
 */
export function Processes() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "processes");
  const [sort, setSort] = useState("rss");
  const [filter, setFilter] = useState("");
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
  const processes = (snapshot?.processes ?? []).filter((process) => {
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return (
      (process.command ?? process.name).toLowerCase().includes(needle) ||
      (process.user ?? "").toLowerCase().includes(needle) ||
      (process.unit ?? "").toLowerCase().includes(needle) ||
      String(process.pid) === filter
    );
  });

  return (
    <>
      <p className="subtitle">
        {t("A snapshot is read from the host on request. Long-term metrics belong to Prometheus, not to this panel.")}
      </p>

      <div className="filters">
        <select value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="rss">{t("by memory")}</option>
          <option value="cpu">{t("by CPU time")}</option>
          <option value="started">{t("by start time")}</option>
          <option value="pid">{t("by PID")}</option>
        </select>
        <input
          placeholder={t("Filter by command, user, unit or PID")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ minWidth: 260 }}
        />
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
      </div>

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

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
          <table>
            <thead>
              <tr>
                <th>PID</th><th>{t("User")}</th><th>{t("Memory")}</th><th>{t("Threads")}</th>
                <th>{t("State")}</th><th>{t("Managed by")}</th><th>{t("Command")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {processes.map((process) => (
                <tr key={process.pid}>
                  <td>{process.pid}</td>
                  <td>{process.user || <span className="badge unknown">{t("unknown")}</span>}</td>
                  <td>{bytes(process.rss_bytes)}</td>
                  <td>{process.threads}</td>
                  <td>{process.state}</td>
                  {/* The PID alone says nothing about whose process it is. */}
                  <td>
                    {process.container
                      ? `${t("container")} ${process.container.slice(0, 12)}`
                      : process.unit || "—"}
                  </td>
                  <td title={process.command || process.name}>
                    {(process.command || process.name).slice(0, 60)}
                  </td>
                  <td>
                    <div className="operations">
                      <button onClick={() => setToSignal({ process, signal: "TERM" })}>Term</button>
                      <button onClick={() => setToSignal({ process, signal: "HUP" })}>HUP</button>
                      <button onClick={() => setToSignal({ process, signal: "KILL" })}>Kill</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="source" style={{ marginTop: 12 }}>
            {t("{shown} of {listed} shown · {total} on the host · read", {
              shown: processes.length, listed: snapshot.processes?.length ?? 0, total: snapshot.total ?? 0,
            })}{" "}
            <Time value={module.data?.observed_at} />
          </p>
          <ModuleFreshness fragment={module.data} />
        </>
      )}

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
    </>
  );
}
