import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Blokada = { who: string; user?: string; pid?: number; what?: string; why?: string; mode?: string };

type Uruchomienie = { index: number; boot_id: string; first_entry: string; last_entry: string };

type Snapshot = {
  boot_id?: string;
  booted_at?: string;
  uptime_seconds?: number | null;
  running_kernel?: string;
  reboot_required?: boolean | null;
  reboot_reasons?: string[];
  inhibitors?: Blokada[];
  inhibitors_known?: boolean;
  last_boots?: Uruchomienie[];
  scheduled_shutdown?: { mode: string; at: string };
  observed_at?: string;
  unavailable_reason?: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

const nieznane = <span className="znacznik nieznany">unknown</span>;

/** Czas dzialania w postaci, ktora czyta sie bez liczenia w glowie. */
function czasDzialania(sekundy?: number | null) {
  if (sekundy === undefined || sekundy === null) return nieznane;
  const dni = Math.floor(sekundy / 86400);
  const godziny = Math.floor((sekundy % 86400) / 3600);
  const minuty = Math.floor((sekundy % 3600) / 60);
  if (dni > 0) return `${dni}d ${godziny}h`;
  if (godziny > 0) return `${godziny}h ${minuty}m`;
  return `${minuty}m`;
}

/**
 * Zasilanie, start i okno serwisowe.
 *
 * Restart nie konczy sie na wyslaniu polecenia, tylko wtedy, gdy host wraca
 * z nowym boot_id. Wylaczenie nie konczy sie w ogole: panel nie potrafi
 * wlaczyc maszyny z powrotem, i zakladka mowi to wprost.
 */
export function Zasilanie() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "power");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [powodWylaczenia, setPowodWylaczenia] = useState("");
  const [pominBlokady, setPominBlokady] = useState(false);

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setZamiar(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its boot state yet.</Pusto>;

  const blokujace = (snapshot?.inhibitors ?? []).filter((blokada) => blokada.mode === "block");

  return (
    <>
      <p className="podtytul">
        A reboot is not finished when the command is sent — it is finished when
        the host comes back with a new boot ID. A shutdown never finishes here
        at all: nothing in this panel can power the machine back on.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Boot state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}
      {/* Wylaczenie zaplanowane poza panelem jest faktem, ktory operator ma
          zobaczyc, zanim cokolwiek tu zleci. */}
      {snapshot?.scheduled_shutdown && (
        <p className="ostrzezenie">
          <span>
            A {snapshot.scheduled_shutdown.mode} is already scheduled on this host for{" "}
            <Czas wartosc={snapshot.scheduled_shutdown.at} />.
          </span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Boot ID</th><td className="zrodlo">{snapshot?.boot_id || nieznane}</td></tr>
          <tr><th>Booted</th><td>{snapshot?.booted_at ? <Czas wartosc={snapshot.booted_at} /> : nieznane}</td></tr>
          <tr><th>Uptime</th><td>{czasDzialania(snapshot?.uptime_seconds)}</td></tr>
          <tr><th>Running kernel</th><td>{snapshot?.running_kernel || nieznane}</td></tr>
          <tr>
            <th>Reboot required</th>
            <td>
              {snapshot?.reboot_required === undefined || snapshot?.reboot_required === null
                ? nieznane
                : snapshot.reboot_required
                  ? "yes"
                  : "no"}
              {/* "Dlaczego" jest tu cala odpowiedzia: host, ktory wymaga
                  restartu bez powodu, nie mowi operatorowi nic. */}
              {(snapshot?.reboot_reasons ?? []).length > 0 && (
                <span className="zrodlo"> · {snapshot!.reboot_reasons!.join(", ")}</span>
              )}
            </td>
          </tr>
        </tbody>
      </table>

      <OknoSerwisowe host={host} />

      <h2>Inhibitors</h2>
      <p className="podtytul">
        What logind would hold a shutdown for. A delay is waited out; a block
        stops the operation until an operator decides otherwise.
      </p>
      {!snapshot?.inhibitors_known ? (
        <Pusto>This host did not report inhibitors.</Pusto>
      ) : !snapshot.inhibitors?.length ? (
        <Pusto>Nothing is holding a shutdown on this host.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Who</th><th>User</th><th>What</th><th>Why</th><th>Mode</th></tr></thead>
          <tbody>
            {snapshot.inhibitors.map((blokada, i) => (
              <tr key={`${blokada.who}-${i}`}>
                <td>{blokada.who}</td>
                <td>{blokada.user || "—"}</td>
                <td>{blokada.what || "—"}</td>
                <td>{blokada.why || "—"}</td>
                <td>{blokada.mode === "block" ? <span className="znacznik uwaga">block</span> : blokada.mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Last boots</h2>
      {!snapshot?.last_boots?.length ? (
        <Pusto>The journal on this host lists no earlier boots.</Pusto>
      ) : (
        <table>
          <thead><tr><th>#</th><th>Boot ID</th><th>First entry</th><th>Last entry</th></tr></thead>
          <tbody>
            {[...snapshot.last_boots].reverse().map((start) => (
              <tr key={start.boot_id}>
                <td>{start.index}</td>
                <td className="zrodlo">{start.boot_id}</td>
                <td><Czas wartosc={start.first_entry} /></td>
                <td><Czas wartosc={start.last_entry} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Power</h2>
      <div className="filtry">
        <button
          onClick={() =>
            setZamiar({
              akcja: "system.reboot",
              etykieta: "Reboot host",
              opis:
                `${host.hostname} will reboot. The panel treats the operation as finished only when the ` +
                "host comes back with a new boot ID, so a host that does not return shows up as failed, not as done.",
              payload: { reboot: { delay_seconds: 15, reason: "operator reboot" } },
            })
          }
        >
          Reboot
        </button>
        <input
          value={powodWylaczenia}
          onChange={(e) => setPowodWylaczenia(e.target.value)}
          placeholder="Reason for shutting this host down"
          style={{ minWidth: 320 }}
        />
        <button
          className="wtorny"
          onClick={() =>
            setZamiar({
              akcja: "system.shutdown",
              etykieta: "Shut down host",
              opis:
                `${host.hostname} will power off. Nothing in this panel can turn it back on — that needs ` +
                "physical or out-of-band access to the machine. " +
                (blokujace.length
                  ? pominBlokady
                    ? `${blokujace.length} blocking inhibitor(s) will be overridden.`
                    : `${blokujace.length} inhibitor(s) are blocking shutdown; the host will refuse.`
                  : ""),
              payload: {
                power: {
                  mode: "poweroff",
                  delay_seconds: 15,
                  reason: powodWylaczenia,
                  ignore_inhibitors: pominBlokady,
                },
              },
            })
          }
          disabled={powodWylaczenia.trim().length < 10}
          title="a shutdown needs a reason: nobody will read the panel to find out why this host is dark"
        >
          Shut down
        </button>
        <label>
          <input type="checkbox" checked={pominBlokady} onChange={(e) => setPominBlokady(e.target.checked)} />
          {" "}override inhibitors
        </label>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Boot state read <Czas wartosc={snapshot.observed_at} />
        </p>
      )}

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod, potwierdzenie) =>
            zlec.mutate({
              action: zamiar.akcja,
              reason: powod,
              // Wylaczenie wymaga przepisanej nazwy celu: panel nie potrafi
              // wlaczyc tej maszyny z powrotem. Reszta operacji jej nie
              // potrzebuje, ale wyslana nie przeszkadza.
              target_confirmation: potwierdzenie,
              payload: zamiar.payload,
            })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}

/**
 * Okno serwisowe. Nie jest operacja na hoscie i nie idzie przez kolejke zadan:
 * zmienia to, co panel o hoscie sadzi. Kampanie omijaja host w oknie, a alerty
 * z niego nie budza dyzurnego.
 */
function OknoSerwisowe({ host }: { host: Host }) {
  const queryClient = useQueryClient();
  const [minuty, setMinuty] = useState(120);
  const [powod, setPowod] = useState("");
  const [komunikat, setKomunikat] = useState("");

  const ustaw = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Host>(`/api/v1/hosts/${host.id}/maintenance`, tresc),
    onSuccess: () => {
      setKomunikat("");
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const trwa = host.maintenance && new Date(host.maintenance.until).getTime() > Date.now();

  return (
    <>
      <h2>Maintenance window</h2>
      <p className="podtytul">
        A window says somebody is working on this machine: campaigns skip it and
        its alerts stay quiet. It always has an end — a window without one ends
        as a host nobody patches and nobody remembers.
      </p>
      {trwa ? (
        <table>
          <tbody>
            <tr><th>Until</th><td><Czas wartosc={host.maintenance!.until} /></td></tr>
            <tr><th>Reason</th><td>{host.maintenance!.reason || "—"}</td></tr>
            <tr><th>Declared by</th><td>{host.maintenance!.set_by || "—"}</td></tr>
          </tbody>
        </table>
      ) : (
        <Pusto>This host is not in a maintenance window.</Pusto>
      )}
      <div className="filtry">
        <input
          type="number"
          min={1}
          value={minuty}
          onChange={(e) => setMinuty(Number(e.target.value))}
          style={{ width: 100 }}
        />
        <span className="zrodlo">minutes</span>
        <input
          value={powod}
          onChange={(e) => setPowod(e.target.value)}
          placeholder="Reason"
          style={{ minWidth: 280 }}
        />
        <button
          onClick={() => ustaw.mutate({ duration_minutes: minuty, reason: powod })}
          disabled={!powod.trim() || ustaw.isPending}
        >
          {trwa ? "Extend window" : "Start window"}
        </button>
        <button className="wtorny" onClick={() => ustaw.mutate({ clear: true })} disabled={!trwa || ustaw.isPending}>
          End window
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}
    </>
  );
}
