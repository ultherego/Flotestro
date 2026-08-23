import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto } from "../../components/ui";
import { useHost } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type PlikZarzadzany = {
  path: string;
  desired_sha256: string;
  mode?: string;
  owner?: string;
  group?: string;
  validator?: string;
  updated_by: string;
  updated_at: string;
  observed_sha256?: string;
  exists: boolean;
  drift: boolean;
  observed_mode?: string;
  observed_owner?: string;
  unavailable_reason?: string;
};

type Wersja = {
  sha256: string;
  size_bytes: number;
  job_id?: string;
  applied_by: string;
  applied_at: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Pliki konfiguracyjne hosta.
 *
 * To nie jest menedzer plikow roota: zakres sciezek wyznacza administrator
 * hosta, a pliki z hashami hasel, klucze prywatne i reguly sudo nie sa tu
 * edytowalne w ogole - kazda z tych rzeczy ma wlasny modul.
 */
export function Pliki() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [wybrany, setWybrany] = useState("");
  const [nowy, setNowy] = useState(false);

  const pliki = useQuery({
    queryKey: ["managed-files", host.id],
    queryFn: () => api.get<{ items: PlikZarzadzany[] }>(`/api/v1/hosts/${host.id}/files`),
  });

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
      setNowy(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["managed-files", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (pliki.error) return <Blad error={pliki.error} />;
  const lista = pliki.data?.items ?? [];

  return (
    <>
      <p className="podtytul">
        Files the panel manages, with the content it expects and the content the
        host actually has. Paths are limited by the host's own allowlist, and
        password files, private keys and sudo rules are never editable here.
      </p>

      <div className="filtry">
        <button onClick={() => setNowy((otwarty) => !otwarty)}>
          {nowy ? "Cancel" : "Manage a file"}
        </button>
        <button
          className="wtorny"
          onClick={() => zlec.mutate({ action: "file.plan", payload: { file: { path: "/" } } })}
          disabled={host.connection_state !== "online"}
        >
          Refresh from host
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {nowy && <NowyPlik onZamiar={setZamiar} />}

      {!lista.length ? (
        <Pusto>The panel does not manage any file on this host yet.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Path</th><th>State</th><th>Mode</th><th>Last change</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {lista.map((plik) => (
              <tr key={plik.path}>
                <td>
                  <a href="#" onClick={(e) => { e.preventDefault(); setWybrany(wybrany === plik.path ? "" : plik.path); }}>
                    {plik.path}
                  </a>
                </td>
                {/* Drift to rozjazd stwierdzony, a nie domyslny: plik,
                    ktorego host nie odczytal, nie jest ani zgodny, ani
                    rozjechany. */}
                <td>
                  {plik.unavailable_reason ? (
                    <span className="znacznik nieznany">{plik.unavailable_reason}</span>
                  ) : !plik.exists ? (
                    <span className="znacznik nieznany">missing on host</span>
                  ) : plik.drift ? (
                    <span className="znacznik nieznany">changed outside the panel</span>
                  ) : (
                    "matches"
                  )}
                </td>
                <td>
                  {plik.observed_mode || plik.mode || "—"}
                  {plik.mode && plik.observed_mode && plik.mode.replace(/^0+/, "") !== plik.observed_mode.replace(/^0+/, "") && (
                    <span className="znacznik nieznany"> want {plik.mode}</span>
                  )}
                </td>
                <td>
                  <Czas wartosc={plik.updated_at} /> <span className="zrodlo">by {plik.updated_by}</span>
                </td>
                <td>
                  <div className="operacje">
                    <button
                      onClick={() =>
                        zlec.mutate({ action: "file.read", payload: { file: { path: plik.path } } })
                      }
                    >
                      Read
                    </button>
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "file.remove",
                          etykieta: "Stop managing and remove",
                          opis: `${plik.path} will be removed from ${host.hostname} and the panel will stop tracking it. Its history stays.`,
                          payload: {
                            file: { path: plik.path, expected_sha256: plik.observed_sha256 ?? "" },
                          },
                        })
                      }
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

      {wybrany && (
        <Historia
          hostID={host.id}
          hostname={host.hostname}
          plik={lista.find((plik) => plik.path === wybrany)}
          onZamiar={setZamiar}
        />
      )}

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

/**
 * Historia wersji pliku wraz z podgladem roznic.
 *
 * Powrot jest do konkretnej wersji, a nie "cofnij ostatnia zmiane": operator
 * wybiera tresc, ktora widzial.
 */
function Historia({
  hostID, hostname, plik, onZamiar,
}: {
  hostID: string;
  hostname: string;
  plik?: PlikZarzadzany;
  onZamiar: (zamiar: Zamiar) => void;
}) {
  const [porownanie, setPorownanie] = useState("");

  const historia = useQuery({
    queryKey: ["file-history", hostID, plik?.path],
    queryFn: () =>
      api.get<{ items: Wersja[] }>(
        `/api/v1/hosts/${hostID}/files/history?path=${encodeURIComponent(plik?.path ?? "")}`,
      ),
    enabled: Boolean(plik?.path),
  });

  const biezaca = useQuery({
    queryKey: ["file-version", plik?.desired_sha256],
    queryFn: () => api.get<{ content: string }>(`/api/v1/files/versions/${plik?.desired_sha256}`),
    enabled: Boolean(plik?.desired_sha256),
  });

  const wybrana = useQuery({
    queryKey: ["file-version", porownanie],
    queryFn: () => api.get<{ content: string }>(`/api/v1/files/versions/${porownanie}`),
    enabled: porownanie !== "",
  });

  if (!plik) return null;

  return (
    <>
      <h2>{plik.path}</h2>
      <table>
        <thead><tr><th>Version</th><th>Size</th><th>Applied</th><th>By</th><th>Actions</th></tr></thead>
        <tbody>
          {(historia.data?.items ?? []).map((wersja) => (
            <tr key={`${wersja.sha256}-${wersja.applied_at}`}>
              <td className="zrodlo">
                {wersja.sha256.slice(0, 12)}
                {wersja.sha256 === plik.desired_sha256 && <span className="znacznik"> current</span>}
              </td>
              <td>{wersja.size_bytes} B</td>
              <td><Czas wartosc={wersja.applied_at} /></td>
              <td>{wersja.applied_by}</td>
              <td>
                <div className="operacje">
                  <button onClick={() => setPorownanie(wersja.sha256)}>Compare</button>
                  <button
                    className="wtorny"
                    disabled={wersja.sha256 === plik.desired_sha256 && !plik.drift}
                    onClick={() =>
                      onZamiar({
                        akcja: "file.rollback",
                        etykieta: "Roll back file",
                        opis: `${plik.path} on ${hostname} goes back to version ${wersja.sha256.slice(0, 12)} from ${new Date(wersja.applied_at).toLocaleString()}.`,
                        payload: {
                          file: {
                            path: plik.path,
                            version_sha256: wersja.sha256,
                            expected_sha256: plik.observed_sha256 ?? "",
                            mode: plik.mode ?? "",
                          },
                        },
                      })
                    }
                  >
                    Roll back
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {porownanie && wybrana.data && biezaca.data && (
        <>
          <h2>Difference</h2>
          <p className="podtytul">
            Left: version {porownanie.slice(0, 12)}. Right: what the panel
            expects now.
          </p>
          <Roznica stara={wybrana.data.content} nowa={biezaca.data.content} />
        </>
      )}
    </>
  );
}

/**
 * Podglad roznic wierszami.
 *
 * Prosty podzial na wiersze wystarcza dla plikow konfiguracyjnych: operator
 * pyta, ktory wiersz sie zmienil, a nie o zmiane w polowie slowa.
 */
function Roznica({ stara, nowa }: { stara: string; nowa: string }) {
  const stare = stara.split("\n");
  const nowe = nowa.split("\n");
  const wiersze: { znak: string; tresc: string }[] = [];

  let i = 0;
  let j = 0;
  while (i < stare.length || j < nowe.length) {
    if (i < stare.length && j < nowe.length && stare[i] === nowe[j]) {
      wiersze.push({ znak: " ", tresc: stare[i] });
      i += 1;
      j += 1;
      continue;
    }
    // Wiersz, ktory pojawia sie dalej po drugiej stronie, jest dodaniem
    // albo usunieciem; reszte pokazujemy jako zmiane w miejscu.
    if (i < stare.length && !nowe.includes(stare[i])) {
      wiersze.push({ znak: "-", tresc: stare[i] });
      i += 1;
      continue;
    }
    if (j < nowe.length && !stare.includes(nowe[j])) {
      wiersze.push({ znak: "+", tresc: nowe[j] });
      j += 1;
      continue;
    }
    if (i < stare.length) {
      wiersze.push({ znak: "-", tresc: stare[i] });
      i += 1;
    }
    if (j < nowe.length) {
      wiersze.push({ znak: "+", tresc: nowe[j] });
      j += 1;
    }
  }

  return (
    <pre style={{ marginTop: 8, maxHeight: 420, overflowY: "auto" }}>
      {wiersze.map((wiersz, indeks) => (
        <div
          key={indeks}
          style={{
            color: wiersz.znak === "+" ? "#3fa34d" : wiersz.znak === "-" ? "#c0392b" : undefined,
          }}
        >
          {wiersz.znak} {wiersz.tresc}
        </div>
      ))}
    </pre>
  );
}

/** Formularz pierwszego zapisu pliku. */
function NowyPlik({ onZamiar }: { onZamiar: (zamiar: Zamiar) => void }) {
  const [sciezka, setSciezka] = useState("");
  const [tresc, setTresc] = useState("");
  const [tryb, setTryb] = useState("644");
  const [odcisk, setOdcisk] = useState("");

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Manage a file</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        A file that already exists needs the checksum of the content you
        reviewed — read it first. Without that, a change someone made after you
        looked would vanish under this write.
      </p>
      <div className="filtry">
        <input value={sciezka} onChange={(e) => setSciezka(e.target.value)} placeholder="/etc/example.conf" style={{ minWidth: 280 }} />
        <input value={tryb} onChange={(e) => setTryb(e.target.value)} placeholder="Mode" style={{ width: 100 }} />
        <input value={odcisk} onChange={(e) => setOdcisk(e.target.value)} placeholder="Expected sha256 (existing file)" style={{ minWidth: 260 }} />
      </div>
      <label>
        Content
        <textarea rows={10} value={tresc} onChange={(e) => setTresc(e.target.value)} />
      </label>
      <button
        onClick={() =>
          onZamiar({
            akcja: "file.ensure",
            etykieta: "Write file",
            opis: `${sciezka} will be written with ${tresc.split("\n").length} lines, mode ${tryb}. The host validates the content first where it knows how.`,
            payload: {
              file: { path: sciezka, content: tresc, mode: tryb, expected_sha256: odcisk },
            },
          })
        }
        disabled={!sciezka || !tresc}
      >
        Write
      </button>
    </div>
  );
}
