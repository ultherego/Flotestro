import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto } from "../../components/ui";
import { useHost } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Definicja = {
  id: string;
  name: string;
  tool: string;
  repository?: string;
  paths?: string[];
  excludes?: string[];
  tags?: string[];
  keep_last?: number;
  keep_daily?: number;
  keep_weekly?: number;
  keep_monthly?: number;
  prune?: boolean;
  runbook?: string;
  initialize?: boolean;
  password_secret?: string;
  env_secrets?: Record<string, string>;
  note?: string;
  updated_by: string;
  updated_at: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  last_run_at?: string;
  last_verify_at?: string;
  unverified: boolean;
  snapshots?: number;
  repository_size?: number;
};

type Narzedzie = { name: string; available: boolean; version?: string };

type Raport = {
  host_id: string;
  definitions: Definicja[];
  status: string;
  tools?: { tools?: Narzedzie[]; runbooks?: string[]; runbooks_known?: boolean };
};

type Snapshot = { id: string; time: string; paths?: string[]; tags?: string[]; size_bytes?: number };

type StanRepozytorium = {
  tool?: string;
  tool_version?: string;
  snapshots?: Snapshot[];
  last_success_at?: string;
  total_size_bytes?: number;
  unavailable_reason?: string;
};

type SzczegolProby = {
  kind?: string;
  message?: string;
  state?: StanRepozytorium;
  outcome?: { snapshot_id?: string; bytes_added?: number; message?: string };
};

type Proba = { status?: string; message?: string; detail?: SzczegolProby };

type Przebieg = {
  definition: string;
  kind: string;
  outcome: string;
  snapshot_id?: string;
  bytes_added?: number;
  files_new?: number;
  duration_seconds?: number;
  snapshots?: number;
  repository_size?: number;
  message?: string;
  started_by?: string;
  recorded_at: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/** Rozmiar w postaci, ktora czyta czlowiek. Brak wartosci nie jest zerem. */
function rozmiar(bajty?: number) {
  if (bajty === undefined || bajty === null) return <span className="znacznik nieznany">unknown</span>;
  const jednostki = ["B", "KiB", "MiB", "GiB", "TiB"];
  let wartosc = bajty;
  let i = 0;
  while (wartosc >= 1024 && i < jednostki.length - 1) {
    wartosc /= 1024;
    i += 1;
  }
  return `${wartosc.toFixed(i === 0 ? 0 : 1)} ${jednostki[i]}`;
}

function ZnacznikStanu({ stan, wiek }: { stan: string; wiek?: number }) {
  const klasa =
    stan === "ok" ? "ok" : stan === "warning" ? "uwaga" : stan === "unknown" ? "nieznany" : "blad";
  const opis =
    stan === "never"
      ? "no backup yet"
      : wiek === undefined
        ? stan
        : wiek < 48
          ? `${Math.round(wiek)} h old`
          : `${Math.round(wiek / 24)} d old`;
  return <span className={`znacznik ${klasa}`}>{opis}</span>;
}

/**
 * Kopie zapasowe hosta.
 *
 * Dane nie plyna przez panel: host rozmawia z repozytorium wprost, a panel
 * widzi metadane - kiedy kopia sie udala, ile zajmuje i czy ktos ja
 * kiedykolwiek sprawdzil. Haslo repozytorium wskazuje sie nazwa sekretu; jego
 * wartosc host pobiera raz, w chwili operacji.
 */
export function Kopie() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [formularz, setFormularz] = useState(false);
  const [wybrana, setWybrana] = useState("");
  const [zadaniePlanu, setZadaniePlanu] = useState("");

  const raport = useQuery({
    queryKey: ["backups", host.id],
    queryFn: () => api.get<Raport>(`/api/v1/hosts/${host.id}/backups`),
  });

  // Lista kopii nalezy do zadania, a nie do stanu panelu: to odpowiedz
  // repozytorium z jednej chwili, po podaniu hasla.
  const plan = useQuery({
    queryKey: ["job-attempts", zadaniePlanu],
    queryFn: () => api.get<{ items: Proba[] }>(`/api/v1/jobs/${zadaniePlanu}/attempts`),
    enabled: zadaniePlanu !== "",
    refetchInterval: (zapytanie) => {
      const proby = (zapytanie.state.data as { items?: Proba[] } | undefined)?.items;
      return proby?.[proby.length - 1]?.status ? false : 2000;
    },
  });
  const probyPlanu = plan.data?.items ?? [];
  const ostatniPlan = probyPlanu[probyPlanu.length - 1];
  const stanRepozytorium = ostatniPlan?.detail?.state;

  const historia = useQuery({
    queryKey: ["backup-runs", host.id, wybrana],
    queryFn: () =>
      api.get<{ items: Przebieg[] }>(
        `/api/v1/hosts/${host.id}/backups/runs?definition=${encodeURIComponent(wybrana)}`,
      ),
    enabled: wybrana !== "",
  });

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie, zmienne) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      if ((zmienne as { action?: string }).action === "backup.plan") setZadaniePlanu(zadanie.id);
      setZamiar(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const zapisz = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Definicja>(`/api/v1/hosts/${host.id}/backups`, tresc),
    onSuccess: (definicja) => {
      setKomunikat(`Definition ${definicja.name} saved. Plan it to read the repository.`);
      setFormularz(false);
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const usun = useMutation({
    mutationFn: (nazwa: string) =>
      api.del(`/api/v1/hosts/${host.id}/backups?name=${encodeURIComponent(nazwa)}`),
    onSuccess: () => {
      setKomunikat("Definition removed. The history of its runs stays.");
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (raport.error) return <Blad error={raport.error} />;
  const definicje = raport.data?.definitions ?? [];
  const narzedzia = raport.data?.tools?.tools ?? [];
  const runbooki = raport.data?.tools?.runbooks ?? [];
  const definicja = definicje.find((pozycja) => pozycja.name === wybrana);

  const zlecenieDefinicji = (pozycja: Definicja, dodatkowe: Record<string, unknown> = {}) => ({
    id: pozycja.name,
    tool: pozycja.tool,
    repository: pozycja.repository ?? "",
    paths: pozycja.paths ?? [],
    excludes: pozycja.excludes ?? [],
    tags: pozycja.tags ?? [],
    keep_last: pozycja.keep_last ?? 0,
    keep_daily: pozycja.keep_daily ?? 0,
    keep_weekly: pozycja.keep_weekly ?? 0,
    keep_monthly: pozycja.keep_monthly ?? 0,
    prune: pozycja.prune ?? false,
    runbook: pozycja.runbook ?? "",
    initialize: pozycja.initialize ?? false,
    ...(pozycja.password_secret ? { password_secret: { name: pozycja.password_secret } } : {}),
    ...(pozycja.env_secrets && Object.keys(pozycja.env_secrets).length
      ? {
          env_secrets: Object.fromEntries(
            Object.entries(pozycja.env_secrets).map(([zmienna, sekret]) => [zmienna, { name: sekret }]),
          ),
        }
      : {}),
    ...dodatkowe,
  });

  return (
    <>
      <p className="podtytul">
        Backups run with the tools this host already has. The data never passes
        through the panel — the host talks to the repository directly, and what
        you see here is metadata: when a copy last succeeded, how much it takes
        and whether anyone has ever read it back.
      </p>

      <div className="filtry">
        {narzedzia.map((narzedzie) => (
          <span key={narzedzie.name} className={`znacznik ${narzedzie.available ? "ok" : ""}`}>
            {narzedzie.name}
            {narzedzie.available && narzedzie.version ? ` · ${narzedzie.version.split("\n")[0]}` : ""}
            {!narzedzie.available ? " · not installed" : ""}
          </span>
        ))}
        {runbooki.length > 0 && (
          <span className="zrodlo">runbooks: {runbooki.join(", ")}</span>
        )}
        <button className="wtorny" onClick={() => setFormularz((otwarty) => !otwarty)}>
          {formularz ? "Cancel" : "Define a backup"}
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {formularz && <FormularzDefinicji runbooki={runbooki} onZapisz={(t) => zapisz.mutate(t)} />}

      {!definicje.length ? (
        <Pusto>
          The panel does not back up anything on this host yet. A definition says
          what to copy, where to and how long it stays.
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Definition</th><th>Destination</th><th>Last copy</th>
              <th>Verified</th><th>Size</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {definicje.map((pozycja) => (
              <tr key={pozycja.name}>
                <td>
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setWybrana(wybrana === pozycja.name ? "" : pozycja.name);
                    }}
                  >
                    {pozycja.name}
                  </a>
                  <div className="zrodlo">
                    {pozycja.tool}
                    {pozycja.runbook ? ` · ${pozycja.runbook}` : ""}
                    {pozycja.paths?.length ? ` · ${pozycja.paths.join(", ")}` : ""}
                  </div>
                </td>
                <td className="zrodlo">
                  {pozycja.repository}
                  {pozycja.password_secret && (
                    <div>password from {pozycja.password_secret}</div>
                  )}
                </td>
                <td>
                  <ZnacznikStanu stan={pozycja.status} wiek={pozycja.age_hours} />
                  {pozycja.last_success_at && (
                    <div className="zrodlo"><Czas wartosc={pozycja.last_success_at} /></div>
                  )}
                </td>
                <td>
                  {/* Kopia, ktorej nikt nigdy nie odczytal, jest obietnica,
                      a nie zabezpieczeniem - i tak ma wygladac. */}
                  {pozycja.unverified ? (
                    <span className="znacznik uwaga">not verified</span>
                  ) : (
                    <>
                      <span className="znacznik ok">verified</span>
                      <div className="zrodlo"><Czas wartosc={pozycja.last_verify_at} /></div>
                    </>
                  )}
                </td>
                <td>
                  {rozmiar(pozycja.repository_size)}
                  {pozycja.snapshots !== undefined && (
                    <div className="zrodlo">{pozycja.snapshots} copies</div>
                  )}
                </td>
                <td>
                  <div className="operacje">
                    <button
                      className="wtorny"
                      disabled={host.connection_state !== "online"}
                      onClick={() =>
                        zlec.mutate({
                          action: "backup.plan",
                          payload: { backup: zlecenieDefinicji(pozycja) },
                        })
                      }
                    >
                      Read repository
                    </button>
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "backup.run",
                          etykieta: "Run backup",
                          opis: `${pozycja.name} copies ${(pozycja.paths ?? []).join(", ")} from ${host.hostname} to ${pozycja.repository}. The data goes straight from the host; the panel only records that it happened.`,
                          payload: { backup: zlecenieDefinicji(pozycja) },
                        })
                      }
                    >
                      Back up now
                    </button>
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "backup.verify",
                          etykieta: "Verify backup",
                          opis: `${pozycja.name} is checked on ${host.hostname}, including reading part of the data back. Until something reads a copy, it is a promise, not a safeguard.`,
                          payload: { backup: zlecenieDefinicji(pozycja, { read_data: true }) },
                        })
                      }
                    >
                      Verify
                    </button>
                    <button className="wtorny" onClick={() => usun.mutate(pozycja.name)}>
                      Forget
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {stanRepozytorium && (
        <>
          <h2>Copies in the repository</h2>
          {stanRepozytorium.unavailable_reason ? (
            <p className="ostrzezenie">
              <span>The repository could not be read: {stanRepozytorium.unavailable_reason}</span>
            </p>
          ) : !stanRepozytorium.snapshots?.length ? (
            <Pusto>The repository holds no copy yet.</Pusto>
          ) : (
            <table>
              <thead>
                <tr><th>Copy</th><th>Taken</th><th>Paths</th><th>Restore</th></tr>
              </thead>
              <tbody>
                {[...stanRepozytorium.snapshots].reverse().map((snapshot) => (
                  <tr key={snapshot.id}>
                    <td className="zrodlo">{snapshot.id}</td>
                    <td><Czas wartosc={snapshot.time} /></td>
                    <td className="zrodlo">{snapshot.paths?.join(", ")}</td>
                    <td>
                      <button
                        className="wtorny"
                        disabled={!definicja}
                        onClick={() => {
                          const cel = window.prompt(
                            "Restore into which directory? The panel never restores straight into system directories, and not into /tmp either — the host helper has its own private one, where restored data would vanish with the operation.",
                            "/srv/flotestro-restore",
                          );
                          if (!cel || !definicja) return;
                          setZamiar({
                            akcja: "backup.restore",
                            etykieta: "Restore copy",
                            opis: `Copy ${snapshot.id} is unpacked into ${cel} on ${host.hostname}. The target must be empty; what goes back from there to its place is a separate decision.`,
                            payload: {
                              backup: zlecenieDefinicji(definicja, {
                                snapshot_id: snapshot.id,
                                target: cel,
                                overwrite: "empty-target",
                              }),
                            },
                          });
                        }}
                      >
                        Restore…
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="zrodlo">
            Read from the repository by job {zadaniePlanu.slice(0, 8)}
            {stanRepozytorium.tool_version
              ? ` · ${stanRepozytorium.tool_version.split("\n")[0]}`
              : ""}
          </p>
        </>
      )}

      {wybrana && (
        <>
          <h2>History of {wybrana}</h2>
          {!(historia.data?.items ?? []).length ? (
            <Pusto>Nothing has run for this definition yet.</Pusto>
          ) : (
            <table>
              <thead>
                <tr><th>When</th><th>Operation</th><th>Result</th><th>Copy</th><th>Added</th><th>By</th></tr>
              </thead>
              <tbody>
                {(historia.data?.items ?? []).map((przebieg, indeks) => (
                  <tr key={`${przebieg.recorded_at}-${indeks}`}>
                    <td><Czas wartosc={przebieg.recorded_at} /></td>
                    <td>{przebieg.kind}</td>
                    <td>
                      {przebieg.outcome === "succeeded" ? (
                        <span className="znacznik ok">succeeded</span>
                      ) : (
                        <span className="znacznik blad">failed</span>
                      )}
                      {przebieg.message && <div className="zrodlo">{przebieg.message}</div>}
                    </td>
                    <td className="zrodlo">{przebieg.snapshot_id || "—"}</td>
                    <td>{przebieg.bytes_added === undefined ? "—" : rozmiar(przebieg.bytes_added)}</td>
                    <td className="zrodlo">{przebieg.started_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
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

/** Formularz definicji kopii. Haslo repozytorium wskazuje sie nazwa sekretu. */
function FormularzDefinicji({
  runbooki, onZapisz,
}: {
  runbooki: string[];
  onZapisz: (tresc: Record<string, unknown>) => void;
}) {
  const [nazwa, setNazwa] = useState("");
  const [narzedzie, setNarzedzie] = useState("restic");
  const [repozytorium, setRepozytorium] = useState("");
  const [sciezki, setSciezki] = useState("");
  const [wykluczenia, setWykluczenia] = useState("");
  const [sekret, setSekret] = useState("");
  const [runbook, setRunbook] = useState("");
  const [keepLast, setKeepLast] = useState("7");
  const [zaloz, setZaloz] = useState(true);

  const runbookowy = narzedzie === "runbook";
  const gotowe = nazwa !== "" && (runbookowy ? runbook !== "" : repozytorium !== "" && sciezki !== "");

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Backup definition</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        The repository password is named, not pasted: the host fetches its value
        from the secret store once, while the backup runs, and passes it to the
        tool through the environment — never as a command-line argument, which
        every user on the host can read.
      </p>
      <div className="filtry">
        <input value={nazwa} onChange={(e) => setNazwa(e.target.value)}
               placeholder="nightly" style={{ minWidth: 160 }} />
        <select value={narzedzie} onChange={(e) => setNarzedzie(e.target.value)}>
          <option value="restic">restic</option>
          <option value="borg">borg</option>
          <option value="runbook">runbook</option>
        </select>
        {runbookowy ? (
          <select value={runbook} onChange={(e) => setRunbook(e.target.value)}>
            <option value="">choose a runbook</option>
            {runbooki.map((nazwaRunbooka) => (
              <option key={nazwaRunbooka} value={nazwaRunbooka}>{nazwaRunbooka}</option>
            ))}
          </select>
        ) : null}
        <input value={repozytorium} onChange={(e) => setRepozytorium(e.target.value)}
               placeholder="/srv/backup or s3:https://…" style={{ minWidth: 280 }} />
      </div>
      <div className="filtry">
        <input value={sciezki} onChange={(e) => setSciezki(e.target.value)}
               placeholder="Paths (/etc /var/lib/app)" style={{ minWidth: 280 }} />
        <input value={wykluczenia} onChange={(e) => setWykluczenia(e.target.value)}
               placeholder="Excludes (*.tmp)" style={{ minWidth: 200 }} />
        <input value={sekret} onChange={(e) => setSekret(e.target.value)}
               placeholder="Password secret (name only)" style={{ minWidth: 220 }} />
        <input value={keepLast} onChange={(e) => setKeepLast(e.target.value)}
               placeholder="Keep last" style={{ width: 110 }} />
      </div>
      <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={zaloz} onChange={(e) => setZaloz(e.target.checked)} />
        Create the repository on the first backup if it does not exist yet
      </label>
      <button
        disabled={!gotowe}
        onClick={() =>
          onZapisz({
            name: nazwa, tool: narzedzie, repository: repozytorium, initialize: zaloz,
            paths: sciezki.split(/[\s,]+/).filter(Boolean),
            excludes: wykluczenia.split(/[\s,]+/).filter(Boolean),
            keep_last: Number(keepLast) || 0,
            runbook: runbookowy ? runbook : "",
            password_secret: sekret,
          })
        }
      >
        Save definition
      </button>
    </div>
  );
}
