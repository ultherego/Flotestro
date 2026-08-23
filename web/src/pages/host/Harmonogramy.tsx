import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Harmonogram = {
  id: string;
  kind: string;
  source: string;
  enabled: boolean;
  expression: string;
  command?: string[];
  command_line?: string;
  user?: string;
  path?: string;
  line?: number;
  next_run?: string;
  timezone?: string;
  last_result?: string;
  comment?: string;
};

type Snapshot = {
  schedules?: Harmonogram[];
  timezone?: string;
  unavailable_reason?: string;
};

/** Operacja czekajaca na potwierdzenie celu. */
type Zamiar = {
  akcja: string;
  etykieta: string;
  opis: string;
  payload: Record<string, unknown>;
};

/**
 * Zadania cykliczne hosta.
 *
 * Panel rozroznia wpisy wlasne od zastanych. Wpis zastany nalezy do
 * administratora hosta; zeby panel mogl nim zarzadzac, trzeba go jawnie
 * przejac - inaczej pierwsza operacja z panelu kasowalaby cudza prace.
 */
export function Harmonogramy() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "schedules");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [formularz, setFormularz] = useState(false);

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
      setFormularz(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  const wpisy = snapshot?.schedules ?? [];

  return (
    <>
      <p className="podtytul">
        Cron entries and systemd timers under one list. Entries created here
        belong to Flotestro and live in their own files; entries found on the
        host stay untouched until you adopt them.
      </p>

      <div className="filtry">
        <button onClick={() => setFormularz((otwarty) => !otwarty)}>
          {formularz ? "Cancel" : "New schedule"}
        </button>
      </div>

      {formularz && (
        <NowyWpis
          onZlec={(payload) =>
            zlec.mutate({ action: "schedule.ensure", payload: { schedule: payload } })
          }
        />
      )}

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {/* Brak wpisow i brak odczytu to dwie rozne rzeczy: pusta lista bez
          wyjasnienia wygladalaby jak host bez zadan cyklicznych. */}
      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Schedules could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      {!modul.data ? (
        <Pusto>This host has not reported its schedules yet.</Pusto>
      ) : !wpisy.length ? (
        <Pusto>No cron entries and no timers on this host.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Kind</th><th>Owner</th><th>Schedule</th>
              <th>Next run</th><th>Command</th><th>State</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {wpisy.map((wpis) => (
              <tr key={`${wpis.path ?? ""}:${wpis.line ?? 0}:${wpis.id}`}>
                <td>{wpis.id}</td>
                <td>{wpis.kind}</td>
                {/* Wlasnosc wpisu decyduje o tym, co panel wolno z nim zrobic. */}
                <td>
                  {wpis.source === "managed" ? (
                    "Flotestro"
                  ) : (
                    <span className="znacznik nieznany" title={wpis.path}>
                      host admin
                    </span>
                  )}
                </td>
                <td>
                  {wpis.expression || <span className="znacznik nieznany">event-based</span>}
                  {wpis.timezone && <span className="zrodlo"> · {wpis.timezone}</span>}
                </td>
                <td>{wpis.next_run ? <Czas wartosc={wpis.next_run} /> : "—"}</td>
                {/* Wpis zastany jest wierszem powloki, wlasny - lista
                    argumentow. Pokazujemy to, co host naprawde uruchomi. */}
                <td title={polecenie(wpis)}>{polecenie(wpis).slice(0, 50)}</td>
                <td>{wpis.enabled ? "enabled" : "disabled"}</td>
                <td>
                  <div className="operacje">
                    <button
                      onClick={() =>
                        setZamiar({
                          akcja: "schedule.run_now",
                          etykieta: "Run now",
                          opis: `${polecenie(wpis)} will run immediately on ${host.hostname}, outside its schedule.`,
                          payload: { schedule: { id: wpis.id } },
                        })
                      }
                      disabled={wpis.source !== "managed"}
                      title={
                        wpis.source === "managed"
                          ? ""
                          : "Only entries owned by Flotestro can be run from the panel."
                      }
                    >
                      Run now
                    </button>
                    {/* Wlaczenie i wylaczenie sa odwracalne jednym klikiem
                        i nie kasuja tresci wpisu, wiec nie zatrzymujemy na
                        nie operatora osobnym potwierdzeniem. */}
                    <button
                      onClick={() =>
                        zlec.mutate({
                          action: "schedule.disable",
                          payload: { schedule: { id: wpis.id, enabled: !wpis.enabled } },
                        })
                      }
                      disabled={wpis.source !== "managed"}
                    >
                      {wpis.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "schedule.remove",
                          etykieta: "Remove",
                          opis: `${wpis.id} will be removed from ${wpis.path || "the host"}.`,
                          payload: { schedule: { id: wpis.id } },
                        })
                      }
                      disabled={wpis.source !== "managed"}
                    >
                      Remove
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {snapshot && (
        <p className="zrodlo" style={{ marginTop: 12 }}>
          {wpisy.filter((wpis) => wpis.source === "managed").length} managed ·{" "}
          {wpisy.filter((wpis) => wpis.source !== "managed").length} found on the host
          {snapshot.timezone && ` · host timezone ${snapshot.timezone}`}
        </p>
      )}
      <SwiezoscModulu fragment={modul.data} />

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({ action: zamiar.akcja, reason: powod, payload: zamiar.payload })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}

/** Polecenie wpisu w postaci, w jakiej host je uruchomi. */
function polecenie(wpis: Harmonogram): string {
  return wpis.command_line || (wpis.command ?? []).join(" ");
}

/**
 * Formularz nowego wpisu. Polecenie jest lista argumentow, a nie wierszem
 * powloki: rozdzielamy je po bialych znakach i pokazujemy operatorowi, co
 * naprawde trafi na host.
 */
function NowyWpis({
  onZlec,
}: {
  onZlec: (payload: Record<string, unknown>) => void;
}) {
  const [id, setId] = useState("");
  const [wyrazenie, setWyrazenie] = useState("0 3 * * *");
  const [polecenie, setPolecenie] = useState("");
  const [uzytkownik, setUzytkownik] = useState("root");
  const [komentarz, setKomentarz] = useState("");
  const argumenty = polecenie.trim().split(/\s+/).filter(Boolean);

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <div className="filtry">
        <input placeholder="Name, e.g. nightly-backup" value={id} onChange={(e) => setId(e.target.value)} />
        <input placeholder="Cron expression" value={wyrazenie} onChange={(e) => setWyrazenie(e.target.value)} />
        <input placeholder="Run as user" value={uzytkownik} onChange={(e) => setUzytkownik(e.target.value)} />
      </div>
      <div className="filtry">
        <input
          placeholder="Command with an absolute path, e.g. /usr/bin/systemctl restart nginx"
          value={polecenie}
          onChange={(e) => setPolecenie(e.target.value)}
          style={{ minWidth: 420 }}
        />
        <input placeholder="Comment (optional)" value={komentarz} onChange={(e) => setKomentarz(e.target.value)} />
      </div>
      {/* Argumenty pokazane wprost: operator ma zobaczyc, ze panel nie
          uruchamia powloki i ze cudzyslowy nic tu nie znacza. */}
      {argumenty.length > 0 && (
        <p className="zrodlo">
          Will run: {argumenty.map((argument, i) => `[${i}] ${argument}`).join("  ")}
        </p>
      )}
      <button
        onClick={() =>
          onZlec({
            id,
            expression: wyrazenie,
            command: argumenty,
            user: uzytkownik,
            comment: komentarz,
            enabled: true,
          })
        }
        disabled={!id || !wyrazenie || argumenty.length === 0}
      >
        Create
      </button>
    </div>
  );
}
