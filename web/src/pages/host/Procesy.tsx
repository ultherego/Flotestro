import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { bytes } from "../../lib/format";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Proces = {
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

type Snapshot = { processes?: Proces[]; total?: number; truncated?: boolean };

/**
 * Procesy hosta.
 *
 * Modul jest diagnostyka, a nie systemem obserwacji: snapshot powstaje na
 * zadanie i ma gorna granice. Metryki dlugoterminowe naleza do Prometheusa.
 */
export function Procesy() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "processes");
  const [sortowanie, setSortowanie] = useState("rss");
  const [filtr, setFiltr] = useState("");
  const [doUbicia, setDoUbicia] = useState<{ proces: Proces; sygnal: string } | null>(null);
  const [komunikat, setKomunikat] = useState("");

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setDoUbicia(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  const procesy = (snapshot?.processes ?? []).filter((proces) => {
    if (!filtr) return true;
    const szukane = filtr.toLowerCase();
    return (
      (proces.command ?? proces.name).toLowerCase().includes(szukane) ||
      (proces.user ?? "").toLowerCase().includes(szukane) ||
      (proces.unit ?? "").toLowerCase().includes(szukane) ||
      String(proces.pid) === filtr
    );
  });

  return (
    <>
      <p className="podtytul">
        A snapshot is read from the host on request. Long-term metrics belong to
        Prometheus, not to this panel.
      </p>

      <div className="filtry">
        <select value={sortowanie} onChange={(e) => setSortowanie(e.target.value)}>
          <option value="rss">by memory</option>
          <option value="cpu">by CPU time</option>
          <option value="started">by start time</option>
          <option value="pid">by PID</option>
        </select>
        <input
          placeholder="Filter by command, user, unit or PID"
          value={filtr}
          onChange={(e) => setFiltr(e.target.value)}
          style={{ minWidth: 260 }}
        />
        <button
          onClick={() =>
            zlec.mutate({
              action: "process.list",
              payload: { process_list: { sort_by: sortowanie, limit: 200 } },
            })
          }
          disabled={zlec.isPending || host.connection_state !== "online"}
        >
          {zlec.isPending ? "Requesting…" : "Read from host"}
        </button>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {!snapshot ? (
        <Pusto>This host has not been read yet. Use “Read from host”.</Pusto>
      ) : (
        <>
          {/* Urwana lista jest zaznaczona razem z liczba wszystkich procesow:
              bez niej wygladalaby na pelny obraz hosta. */}
          {snapshot.truncated && (
            <p className="ostrzezenie">
              <span>
                Showing {snapshot.processes?.length ?? 0} of {snapshot.total} processes.
                Change the sort order to see a different slice.
              </span>
            </p>
          )}
          <table>
            <thead>
              <tr>
                <th>PID</th><th>User</th><th>Memory</th><th>Threads</th>
                <th>State</th><th>Managed by</th><th>Command</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {procesy.map((proces) => (
                <tr key={proces.pid}>
                  <td>{proces.pid}</td>
                  <td>{proces.user || <span className="znacznik nieznany">unknown</span>}</td>
                  <td>{bytes(proces.rss_bytes)}</td>
                  <td>{proces.threads}</td>
                  <td>{proces.state}</td>
                  {/* Sam PID nic nie mowi o tym, czyj to proces. */}
                  <td>
                    {proces.container
                      ? `container ${proces.container.slice(0, 12)}`
                      : proces.unit || "—"}
                  </td>
                  <td title={proces.command || proces.name}>
                    {(proces.command || proces.name).slice(0, 60)}
                  </td>
                  <td>
                    <div className="operacje">
                      <button onClick={() => setDoUbicia({ proces, sygnal: "TERM" })}>Term</button>
                      <button onClick={() => setDoUbicia({ proces, sygnal: "HUP" })}>HUP</button>
                      <button onClick={() => setDoUbicia({ proces, sygnal: "KILL" })}>Kill</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="zrodlo" style={{ marginTop: 12 }}>
            {procesy.length} of {snapshot.processes?.length ?? 0} shown · {snapshot.total} on the
            host · read <Czas wartosc={modul.data?.observed_at} />
          </p>
          <SwiezoscModulu fragment={modul.data} />
        </>
      )}

      {doUbicia && (
        <PotwierdzenieCelu
          host={host}
          etykieta={`Send ${doUbicia.sygnal}`}
          opis={
            doUbicia.sygnal === "KILL"
              ? `PID ${doUbicia.proces.pid} (${doUbicia.proces.command || doUbicia.proces.name}) will be killed without a chance to clean up.`
              : `PID ${doUbicia.proces.pid} (${doUbicia.proces.command || doUbicia.proces.name}) will receive ${doUbicia.sygnal}.`
          }
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({
              action: "process.signal",
              reason: powod,
              payload: {
                process_signal: {
                  pid: doUbicia.proces.pid,
                  // Czas startu wiaze zadanie z tym procesem: sam PID moze
                  // w miedzyczasie nalezec do zupelnie innego.
                  expected_start_ticks: doUbicia.proces.start_time_ticks,
                  signal: doUbicia.sygnal,
                  command: doUbicia.proces.command || doUbicia.proces.name,
                },
              },
            })
          }
          onAnuluj={() => setDoUbicia(null)}
        />
      )}
    </>
  );
}
