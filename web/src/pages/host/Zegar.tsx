import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Zrodlo = {
  address: string;
  mode?: string;
  state?: string;
  stratum?: number | null;
  poll_seconds?: number | null;
  reachability?: string;
  last_rx_seconds?: number | null;
  offset_seconds?: number | null;
  error_seconds?: number | null;
};

type Serwer = { address: string; source?: string; pool?: boolean; managed: boolean };

type Pomiar = {
  server: string;
  address?: string;
  reachable: boolean;
  stratum?: number | null;
  offset_seconds?: number | null;
  delay_seconds?: number | null;
  error?: string;
};

type Snapshot = {
  now?: string;
  timezone?: string;
  utc_offset_seconds?: number | null;
  rtc_in_local_time?: boolean | null;
  ntp_enabled?: boolean | null;
  synchronized?: boolean | null;
  service?: string;
  unit?: string;
  service_active?: boolean | null;
  reference_name?: string;
  stratum?: number | null;
  offset_seconds?: number | null;
  root_delay_seconds?: number | null;
  root_dispersion_seconds?: number | null;
  frequency_ppm?: number | null;
  leap_status?: string;
  last_sync_at?: string;
  sources?: Zrodlo[];
  configured_servers?: Serwer[];
  managed_config?: string;
  managed_path?: string;
  config_path?: string;
  can_add_source_dir?: boolean;
  write_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type WynikCzasu = { kind?: string; message?: string; probes?: Pomiar[] };

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/** Prog, powyzej ktorego przesuniecie przestaje byc szumem pomiaru. */
const PROG_SKOKU = 1;

const nieznane = <span className="znacznik nieznany">unknown</span>;

/** Brak pomiaru to nie zero: pusta wartosc ma zostac napisem, a nie liczba. */
function sekundy(wartosc?: number | null, cyfry = 6) {
  if (wartosc === undefined || wartosc === null) return nieznane;
  return `${wartosc.toFixed(cyfry)} s`;
}

function flaga(wartosc?: boolean | null) {
  if (wartosc === undefined || wartosc === null) return nieznane;
  return wartosc ? "yes" : "no";
}

/**
 * Czas hosta i jego synchronizacja.
 *
 * Zegar jest zalozeniem, na ktorym stoi reszta: Kerberos odrzuca bilety spoza
 * okna, mTLS - certyfikaty jeszcze niewazne, a dziennik z przesunietego hosta
 * uklada sie w zla kolejnosc. Dlatego zakladka mierzy przesuniecie, a nie
 * tylko pokazuje, ze demon czasu dziala.
 */
export function Zegar() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "time");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [serwery, setSerwery] = useState("");
  const [strefa, setStrefa] = useState("");
  const [zgodaNaSkok, setZgodaNaSkok] = useState(false);
  const [zgodaNaKatalog, setZgodaNaKatalog] = useState(false);
  const [zadanieTestu, setZadanieTestu] = useState("");

  // Wynik testu nalezy do zadania, a nie do stanu hosta: to odpowiedz na
  // pytanie zadane w jednej chwili, wobec serwerow, ktorych host moze jeszcze
  // nie uzywac.
  const test = useQuery({
    queryKey: ["job-attempts", zadanieTestu],
    queryFn: () =>
      api.get<{ items: { status?: string; detail?: WynikCzasu }[] }>(
        `/api/v1/jobs/${zadanieTestu}/attempts`,
      ),
    enabled: zadanieTestu !== "",
    refetchInterval: (zapytanie) => {
      const proby = (zapytanie.state.data as { items?: { status?: string }[] } | undefined)?.items;
      const ostatnia = proby?.[proby.length - 1];
      return ostatnia?.status ? false : 2000;
    },
  });

  const proby = test.data?.items ?? [];
  const ostatniaProba = proby[proby.length - 1];
  const pomiary = ostatniaProba?.detail?.probes ?? [];

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie, tresc) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      if (!zadanie.requires_approval && (tresc as { action?: string }).action === "time.sync.test") {
        setZadanieTestu(zadanie.id);
      }
      setZamiar(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["inventory", host.id, "time"] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its clock yet.</Pusto>;

  const listaSerwerow = serwery.split(",").map((wpis) => wpis.trim()).filter(Boolean);
  const przesuniecie = snapshot?.offset_seconds;
  const rozjechany = przesuniecie !== undefined && przesuniecie !== null && Math.abs(przesuniecie) >= PROG_SKOKU;

  return (
    <>
      <p className="podtytul">
        The clock is what everything else assumes. Kerberos refuses tickets from
        outside its window, mTLS refuses certificates that are not valid yet, and
        a journal from a host with a shifted clock sorts into the wrong order.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Clock state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}
      {snapshot?.write_reason && (
        <p className="ostrzezenie">
          <span>{snapshot.write_reason}</span>
        </p>
      )}
      {/* Rozjechany zegar wyglada z zewnatrz jak zepsuty katalog albo zepsute
          certyfikaty, wiec zakladka nazywa to wprost. */}
      {rozjechany && (
        <p className="ostrzezenie">
          <span>
            This host is {sekundy(przesuniecie, 3)} away from its time source.
            Expect Kerberos and mTLS failures before anything else looks wrong.
          </span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Host time</th><td>{snapshot?.now ? <Czas wartosc={snapshot.now} /> : nieznane}</td></tr>
          <tr><th>Timezone</th><td>{snapshot?.timezone || nieznane}</td></tr>
          <tr>
            <th>UTC offset</th>
            <td>
              {snapshot?.utc_offset_seconds === undefined || snapshot?.utc_offset_seconds === null
                ? nieznane
                : `${snapshot.utc_offset_seconds / 3600} h`}
            </td>
          </tr>
          {/* Zegar sprzetowy w czasie lokalnym psuje godzine przy kazdej
              zmianie czasu letniego - i dopiero po restarcie. */}
          <tr><th>Hardware clock in local time</th><td>{flaga(snapshot?.rtc_in_local_time)}</td></tr>
          <tr><th>Synchronized</th><td>{flaga(snapshot?.synchronized)}</td></tr>
          <tr>
            <th>Daemon</th>
            <td>
              {snapshot?.service || nieznane}
              {snapshot?.unit && ` · ${snapshot.unit}`}
              {snapshot?.service_active === false && " · not running"}
            </td>
          </tr>
          <tr><th>Reference</th><td>{snapshot?.reference_name || nieznane}</td></tr>
          <tr><th>Stratum</th><td>{snapshot?.stratum ?? nieznane}</td></tr>
          <tr><th>Offset</th><td>{sekundy(snapshot?.offset_seconds)}</td></tr>
          <tr><th>Root delay</th><td>{sekundy(snapshot?.root_delay_seconds)}</td></tr>
          <tr><th>Root dispersion</th><td>{sekundy(snapshot?.root_dispersion_seconds)}</td></tr>
          <tr><th>Leap status</th><td>{snapshot?.leap_status || nieznane}</td></tr>
          <tr>
            <th>Last sync</th>
            <td>{snapshot?.last_sync_at ? <Czas wartosc={snapshot.last_sync_at} /> : nieznane}</td>
          </tr>
          <tr><th>Managed file</th><td>{snapshot?.managed_path || "—"}</td></tr>
          {/* Glowny plik demona nalezy do dystrybucji. Pokazujemy go, zeby
              bylo widac, czego zmiana panelu nie dotyczy. */}
          {snapshot?.config_path && (
            <tr><th>Daemon config</th><td>{snapshot.config_path}</td></tr>
          )}
        </tbody>
      </table>

      <h2>Sources</h2>
      {!snapshot?.sources?.length ? (
        <Pusto>The time daemon reports no sources on this host.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Address</th><th>Mode</th><th>State</th><th>Stratum</th><th>Poll</th><th>Reach</th><th>Offset</th></tr>
          </thead>
          <tbody>
            {snapshot.sources.map((zrodlo) => (
              <tr key={zrodlo.address}>
                <td>{zrodlo.address}</td>
                <td>{zrodlo.mode || "—"}</td>
                <td>{zrodlo.state || "—"}</td>
                <td>{zrodlo.stratum ?? nieznane}</td>
                <td>{zrodlo.poll_seconds ? `${zrodlo.poll_seconds} s` : nieznane}</td>
                <td>{zrodlo.reachability || "—"}</td>
                <td>{sekundy(zrodlo.offset_seconds)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Configured servers</h2>
      <p className="podtytul">
        Configuration, not reachability: a server written here that never answers
        does not show up in the source list above at all.
      </p>
      {!snapshot?.configured_servers?.length ? (
        <Pusto>No time servers are configured on this host.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Address</th><th>From</th><th>Kind</th><th>Owner</th></tr></thead>
          <tbody>
            {snapshot.configured_servers.map((serwer, i) => (
              <tr key={`${serwer.address}-${i}`}>
                <td>{serwer.address}</td>
                <td>{serwer.source || "—"}</td>
                <td>{serwer.pool ? "pool" : "server"}</td>
                <td>{serwer.managed ? "Flotestro" : "host admin"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Test time sources</h2>
      <p className="podtytul">
        The query goes out from the host, not from the panel. Leave the field
        empty to ask the sources this host already uses.
      </p>
      <div className="filtry">
        <input
          value={serwery}
          onChange={(e) => setSerwery(e.target.value)}
          placeholder="Servers, comma separated (optional)"
          style={{ minWidth: 320 }}
        />
        <button
          onClick={() =>
            zlec.mutate({
              action: "time.sync.test",
              payload: { time: { probe: listaSerwerow } },
            })
          }
          disabled={zlec.isPending}
        >
          Test
        </button>
        <button
          className="wtorny"
          onClick={() =>
            setZamiar({
              akcja: "time.config.apply",
              etykieta: "Set time servers",
              opis:
                `${host.hostname} will use ${listaSerwerow.join(", ")} as its time sources. ` +
                "Each server is queried before the change; if none answers, the host keeps what it has. " +
                (zgodaNaKatalog
                  ? `One line will be appended to ${snapshot?.config_path} so chrony reads the panel's sources directory. `
                  : "") +
                (zgodaNaSkok
                  ? "A step of the clock is allowed: databases, tokens and certificates will see time move."
                  : "A change that would step the clock by more than a second is refused."),
              payload: {
                time: {
                  servers: listaSerwerow,
                  allow_step: zgodaNaSkok,
                  enable_dropin: zgodaNaKatalog,
                },
              },
            })
          }
          disabled={!listaSerwerow.length || (Boolean(snapshot?.write_reason) && !zgodaNaKatalog)}
          title={snapshot?.write_reason}
        >
          Set as sources
        </button>
        <label>
          <input type="checkbox" checked={zgodaNaSkok} onChange={(e) => setZgodaNaSkok(e.target.checked)} />
          {" "}allow a step of the clock
        </label>
      </div>

      {/* Host, na ktorym chrony nie wlacza zadnego katalogu, da sie
          doprowadzic do stanu zapisywalnego jednym dopisanym wierszem. To
          jedyne miejsce, w ktorym panel dotyka cudzej konfiguracji, wiec
          pyta o zgode osobno i mowi dokladnie, co dopisze. */}
      {snapshot?.can_add_source_dir && (
        <p className="podtytul">
          <label>
            <input
              type="checkbox"
              checked={zgodaNaKatalog}
              onChange={(e) => setZgodaNaKatalog(e.target.checked)}
            />
            {" "}append one line to {snapshot.config_path} so that chrony reads
            /etc/chrony/sources.d — a directory that accepts nothing but time
            servers. Nothing already in that file is changed or removed.
          </label>
        </p>
      )}

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {zadanieTestu && (
        <table>
          <thead>
            <tr><th>Server</th><th>Answered from</th><th>Stratum</th><th>Offset</th><th>Round trip</th></tr>
          </thead>
          <tbody>
            {pomiary.map((pomiar) => (
              <tr key={pomiar.server}>
                <td>{pomiar.server}</td>
                <td>
                  {pomiar.reachable
                    ? pomiar.address || "—"
                    : <span className="znacznik nieznany">{pomiar.error || "no answer"}</span>}
                </td>
                <td>{pomiar.stratum ?? nieznane}</td>
                <td>{sekundy(pomiar.offset_seconds)}</td>
                <td>{sekundy(pomiar.delay_seconds, 3)}</td>
              </tr>
            ))}
            {!pomiary.length && (
              <tr><td colSpan={5}>{ostatniaProba?.status ? "No measurements." : "Running…"}</td></tr>
            )}
          </tbody>
        </table>
      )}

      <h2>Timezone</h2>
      <div className="filtry">
        <input
          value={strefa}
          onChange={(e) => setStrefa(e.target.value)}
          placeholder="e.g. Europe/Warsaw"
          style={{ minWidth: 240 }}
        />
        <button
          onClick={() =>
            setZamiar({
              akcja: "time.timezone.set",
              etykieta: "Set timezone",
              opis:
                `${host.hostname} will report local time as ${strefa}. This changes what the host ` +
                "shows people and writes to the journal; it does not move the moment the host lives in.",
              payload: { time: { timezone: strefa } },
            })
          }
          disabled={!strefa}
        >
          Set timezone
        </button>
      </div>

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Clock read <Czas wartosc={snapshot.observed_at} />
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
              // Nazwa celu jest potrzebna operacjom nieodwracalnym; tutaj
              // nie zmienia niczego, ale wyslana nie przeszkadza.
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
