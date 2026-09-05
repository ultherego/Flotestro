import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type MetadaneKlucza = {
  path: string;
  exists: boolean;
  mode?: string;
  owner?: string;
  group?: string;
  world_readable?: boolean;
  reason?: string;
};

type Sledzenie = {
  request?: string;
  status?: string;
  ca?: string;
  key_path?: string;
  auto_renew?: boolean;
  expires?: string;
};

type Certyfikat = {
  path: string;
  subject?: string;
  issuer?: string;
  serial?: string;
  sans?: string[];
  not_before?: string;
  not_after?: string;
  fingerprint_sha256?: string;
  key_algorithm?: string;
  key_bits?: number;
  self_signed?: boolean;
  is_ca?: boolean;
  chain_length?: number;
  key?: MetadaneKlucza;
  source: string;
  owner_service?: string;
  renewal: string;
  tracking?: Sledzenie;
  unavailable_reason?: string;
  status: string;
  days_to_expiry?: number;
  watched: boolean;
  managed: boolean;
  deployed_at?: string;
  deployed_by?: string;
  key_secret?: string;
  reload_unit?: string;
  probe_target?: string;
};

type Cel = {
  id: string;
  path: string;
  key_path?: string;
  key_secret?: string;
  reload_unit?: string;
  probe_target?: string;
  service?: string;
  note?: string;
  updated_by: string;
  updated_at: string;
};

type Raport = {
  host_id: string;
  certificates: Certyfikat[];
  targets: Cel[];
  status: string;
  tracking_known: boolean;
  tracking_reason?: string;
  keys_known: boolean;
  missing?: Record<string, string>;
  observed_at?: string;
  revision?: string;
  stale: boolean;
  unavailable_reason?: string;
};

type Wdrozenie = {
  path: string;
  fingerprint_sha256: string;
  subject?: string;
  not_after?: string;
  key_secret?: string;
  key_secret_version?: number;
  job_id?: string;
  deployed_by: string;
  deployed_at: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

const nieznane = <span className="znacznik nieznany">unknown</span>;

/** Stan terminu jest ocena panelu, a nie faktem z hosta - stad wlasny wyglad. */
function ZnacznikStanu({ stan, dni }: { stan: string; dni?: number }) {
  const klasa =
    stan === "valid" ? "ok" : stan === "expired" || stan === "critical" ? "blad"
      : stan === "warning" ? "uwaga" : "nieznany";
  const opis =
    stan === "expired"
      ? dni === undefined ? "expired" : `expired ${Math.abs(dni)} d ago`
      : stan === "unknown"
        ? "unknown"
        : dni === undefined ? stan : `${dni} d left`;
  return <span className={`znacznik ${klasa}`}>{opis}</span>;
}

/**
 * Certyfikaty hosta.
 *
 * Zakres jest wyliczony, a nie wyszukany: panel oglada pliki, ktore mu
 * wskazano, oraz te, ktorych pilnuje certmonger. Przeszukanie calego systemu
 * plikow znalazloby przede wszystkim magazyn zaufania - kilkaset zaswiadczen
 * urzedow, ktore nie naleza do zadnej uslugi.
 *
 * Klucza prywatnego panel nie oglada nigdy: wie tylko, gdzie lezy, jakie ma
 * prawa i z ktorego sekretu pochodzi.
 */
export function Certyfikaty() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [formularz, setFormularz] = useState<"" | "watch" | "deploy">("");
  const [wybrany, setWybrany] = useState("");

  const modul = useModul<unknown>(host.id, "certificates");
  const raport = useQuery({
    queryKey: ["certificates", host.id],
    queryFn: () => api.get<Raport>(`/api/v1/hosts/${host.id}/certificates`),
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
      setFormularz("");
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const obserwuj = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Cel>(`/api/v1/hosts/${host.id}/certificates/targets`, tresc),
    onSuccess: (cel) => {
      setKomunikat(`The panel now watches ${cel.path}. Scan the host to read it.`);
      setFormularz("");
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const zapomnij = useMutation({
    mutationFn: (sciezka: string) =>
      api.del(`/api/v1/hosts/${host.id}/certificates/targets?path=${encodeURIComponent(sciezka)}`),
    onSuccess: () => {
      setKomunikat("The panel stopped watching that path.");
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (raport.error) return <Blad error={raport.error} />;
  const dane = raport.data;
  const lista = dane?.certificates ?? [];
  const cele = dane?.targets ?? [];

  return (
    <>
      <p className="podtytul">
        Certificates on the paths the panel watches, plus everything certmonger
        tracks on this host. Nothing here comes from walking the filesystem, and
        the private key is never read — only its location and permissions.
      </p>

      {dane?.stale && (
        <p className="ostrzezenie">
          <span>
            This picture is older than a day and a half. Scan the host to see
            what is on disk now.
          </span>
        </p>
      )}
      {dane && !dane.tracking_known && (
        <p className="ostrzezenie">
          <span>
            The panel could not tell what renews these certificates
            {dane.tracking_reason ? `: ${dane.tracking_reason}` : "."}
          </span>
        </p>
      )}

      <div className="filtry">
        <button
          onClick={() =>
            zlec.mutate({
              action: "certificate.scan",
              payload: {
                certificate: {
                  targets: cele.map((cel) => ({
                    path: cel.path,
                    key_path: cel.key_path ?? "",
                    service: cel.service ?? "",
                  })),
                },
              },
            })
          }
          disabled={host.connection_state !== "online" || zlec.isPending}
        >
          Scan host
        </button>
        <button className="wtorny" onClick={() => setFormularz(formularz === "watch" ? "" : "watch")}>
          {formularz === "watch" ? "Cancel" : "Watch a path"}
        </button>
        <button className="wtorny" onClick={() => setFormularz(formularz === "deploy" ? "" : "deploy")}>
          {formularz === "deploy" ? "Cancel" : "Deploy a certificate"}
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {formularz === "watch" && <FormularzObserwacji onZapisz={(tresc) => obserwuj.mutate(tresc)} />}
      {formularz === "deploy" && (
        <FormularzWdrozenia cele={cele} hostname={host.hostname} onZamiar={setZamiar} />
      )}

      {!lista.length ? (
        <Pusto>
          No certificate is watched on this host yet. Add a path, or scan the
          host if certmonger tracks something here.
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Path</th><th>Subject</th><th>Expires</th><th>Renewal</th>
              <th>Source</th><th>Key</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {lista.map((certyfikat) => (
              <tr key={certyfikat.path}>
                <td>
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setWybrany(wybrany === certyfikat.path ? "" : certyfikat.path);
                    }}
                  >
                    {certyfikat.path}
                  </a>
                  {certyfikat.owner_service && (
                    <div className="zrodlo">{certyfikat.owner_service}</div>
                  )}
                </td>
                <td>
                  {certyfikat.unavailable_reason ? (
                    <span className="znacznik nieznany">{certyfikat.unavailable_reason}</span>
                  ) : (
                    <>
                      {certyfikat.subject}
                      {certyfikat.sans?.length ? (
                        <div className="zrodlo">{certyfikat.sans.join(", ")}</div>
                      ) : null}
                    </>
                  )}
                </td>
                <td>
                  <ZnacznikStanu stan={certyfikat.status} dni={certyfikat.days_to_expiry} />
                  {certyfikat.not_after && (
                    <div className="zrodlo"><Czas wartosc={certyfikat.not_after} /></div>
                  )}
                </td>
                <td>
                  {/* "Reczne" jest ustaleniem: demon odpowiedzial, ze tego
                      pliku nie pilnuje. "Nieznane" jest brakiem odpowiedzi. */}
                  {certyfikat.renewal === "tracked" ? (
                    <>
                      <span className="znacznik ok">certmonger</span>
                      {certyfikat.tracking?.status && (
                        <div className="zrodlo">{certyfikat.tracking.status}</div>
                      )}
                    </>
                  ) : certyfikat.renewal === "manual" ? (
                    <span className="znacznik uwaga">manual</span>
                  ) : (
                    nieznane
                  )}
                </td>
                <td>
                  {certyfikat.managed ? (
                    <>
                      <span className="znacznik ok">panel</span>
                      {certyfikat.deployed_at && (
                        <div className="zrodlo">
                          <Czas wartosc={certyfikat.deployed_at} /> · {certyfikat.deployed_by}
                        </div>
                      )}
                    </>
                  ) : certyfikat.source === "certmonger" ? (
                    <span className="znacznik">certmonger</span>
                  ) : (
                    <span className="znacznik">outside the panel</span>
                  )}
                </td>
                <td>
                  {!certyfikat.key ? (
                    <span className="zrodlo">—</span>
                  ) : certyfikat.key.reason ? (
                    <span className="znacznik nieznany">{certyfikat.key.reason}</span>
                  ) : !certyfikat.key.exists ? (
                    <span className="znacznik blad">missing</span>
                  ) : certyfikat.key.world_readable ? (
                    <span className="znacznik blad">mode {certyfikat.key.mode}, world-readable</span>
                  ) : (
                    <span className="zrodlo">
                      {certyfikat.key.mode} {certyfikat.key.owner}
                    </span>
                  )}
                  {certyfikat.key_secret && (
                    <div className="zrodlo">secret {certyfikat.key_secret}</div>
                  )}
                </td>
                <td>
                  <div className="operacje">
                    <button
                      className="wtorny"
                      disabled={certyfikat.renewal !== "tracked" || !certyfikat.tracking?.request}
                      onClick={() =>
                        setZamiar({
                          akcja: "certificate.renew",
                          etykieta: "Renew certificate",
                          opis: `certmonger on ${host.hostname} is asked to reissue request ${certyfikat.tracking?.request} for ${certyfikat.path}${certyfikat.reload_unit ? `, then ${certyfikat.reload_unit} is reloaded` : ""}.`,
                          payload: {
                            certificate: {
                              request: certyfikat.tracking?.request ?? "",
                              path: certyfikat.path,
                              reload_unit: certyfikat.reload_unit ?? "",
                              probe_target: certyfikat.probe_target ?? "",
                            },
                          },
                        })
                      }
                    >
                      Renew
                    </button>
                    {certyfikat.watched && (
                      <button className="wtorny" onClick={() => zapomnij.mutate(certyfikat.path)}>
                        Stop watching
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {wybrany && <Szczegoly hostID={host.id} certyfikat={lista.find((c) => c.path === wybrany)} />}

      {dane?.missing && Object.keys(dane.missing).length > 0 && (
        <>
          <h2>Not established</h2>
          <p className="podtytul">
            Facts the host could not collect. Each one is an answer of "not
            known", not a value of zero.
          </p>
          <table>
            <thead><tr><th>Fact</th><th>Reason</th></tr></thead>
            <tbody>
              {Object.entries(dane.missing).map(([fakt, powod]) => (
                <tr key={fakt}><td>{fakt}</td><td className="zrodlo">{powod}</td></tr>
              ))}
            </tbody>
          </table>
        </>
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

/** Szczegoly certyfikatu wraz z historia wdrozen tego pliku. */
function Szczegoly({ hostID, certyfikat }: { hostID: string; certyfikat?: Certyfikat }) {
  const historia = useQuery({
    queryKey: ["certificate-deployments", hostID, certyfikat?.path],
    queryFn: () =>
      api.get<{ items: Wdrozenie[] }>(
        `/api/v1/hosts/${hostID}/certificates/deployments?path=${encodeURIComponent(certyfikat?.path ?? "")}`,
      ),
    enabled: !!certyfikat,
  });
  if (!certyfikat) return null;

  return (
    <>
      <h2>{certyfikat.path}</h2>
      <table>
        <tbody>
          <tr><td>Issuer</td><td>{certyfikat.issuer || nieznane}</td></tr>
          <tr><td>Serial</td><td className="zrodlo">{certyfikat.serial || "—"}</td></tr>
          <tr>
            <td>Fingerprint</td>
            <td className="zrodlo">{certyfikat.fingerprint_sha256 || "—"}</td>
          </tr>
          <tr>
            <td>Key</td>
            <td>
              {certyfikat.key_algorithm
                ? `${certyfikat.key_algorithm} ${certyfikat.key_bits}`
                : nieznane}
            </td>
          </tr>
          <tr>
            <td>Chain</td>
            <td>
              {/* Sam lisc bez lancucha jest najczestszym powodem, dla ktorego
                  klient odrzuca polaczenie mimo waznego certyfikatu. */}
              {certyfikat.chain_length
                ? certyfikat.chain_length === 1
                  ? "leaf only — clients that need the issuer will reject it"
                  : `${certyfikat.chain_length} certificates`
                : nieznane}
            </td>
          </tr>
          <tr><td>Valid from</td><td><Czas wartosc={certyfikat.not_before} /></td></tr>
          <tr><td>Valid until</td><td><Czas wartosc={certyfikat.not_after} /></td></tr>
          {certyfikat.tracking?.request && (
            <tr>
              <td>certmonger</td>
              <td className="zrodlo">
                request {certyfikat.tracking.request} · CA {certyfikat.tracking.ca} ·
                auto-renew {certyfikat.tracking.auto_renew ? "yes" : "no"}
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <h2>Deployments from the panel</h2>
      {!(historia.data?.items ?? []).length ? (
        <Pusto>The panel has never deployed this file.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Fingerprint</th><th>Expires</th><th>Key</th><th>Deployed</th><th>By</th></tr>
          </thead>
          <tbody>
            {(historia.data?.items ?? []).map((wdrozenie) => (
              <tr key={`${wdrozenie.fingerprint_sha256}-${wdrozenie.deployed_at}`}>
                <td className="zrodlo">
                  {wdrozenie.fingerprint_sha256.slice(0, 16)}
                  {wdrozenie.fingerprint_sha256 === certyfikat.fingerprint_sha256 && (
                    <span className="znacznik"> on host</span>
                  )}
                </td>
                <td><Czas wartosc={wdrozenie.not_after} /></td>
                <td className="zrodlo">
                  {wdrozenie.key_secret
                    ? `${wdrozenie.key_secret}@v${wdrozenie.key_secret_version}`
                    : "—"}
                </td>
                <td><Czas wartosc={wdrozenie.deployed_at} /></td>
                <td>{wdrozenie.deployed_by}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Formularz zakresu obserwacji. To nie jest operacja na hoscie. */
function FormularzObserwacji({ onZapisz }: { onZapisz: (tresc: Record<string, unknown>) => void }) {
  const [sciezka, setSciezka] = useState("");
  const [klucz, setKlucz] = useState("");
  const [sekret, setSekret] = useState("");
  const [jednostka, setJednostka] = useState("");
  const [sonda, setSonda] = useState("");
  const [usluga, setUsluga] = useState("");

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Watch a path</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        This changes what the panel looks at, not the host. The service that
        reads the file and the address where the result is visible are yours to
        fill in — the panel does not guess them from a directory name.
      </p>
      <div className="filtry">
        <input value={sciezka} onChange={(e) => setSciezka(e.target.value)}
          placeholder="/etc/pki/tls/certs/usluga.crt" style={{ minWidth: 300 }} />
        <input value={klucz} onChange={(e) => setKlucz(e.target.value)}
          placeholder="/etc/pki/tls/private/usluga.key" style={{ minWidth: 300 }} />
      </div>
      <div className="filtry">
        <input value={sekret} onChange={(e) => setSekret(e.target.value)}
          placeholder="Key secret (name only)" style={{ minWidth: 200 }} />
        <input value={jednostka} onChange={(e) => setJednostka(e.target.value)}
          placeholder="Reload unit (httpd.service)" style={{ minWidth: 200 }} />
        <input value={sonda} onChange={(e) => setSonda(e.target.value)}
          placeholder="Probe target (host:443)" style={{ minWidth: 180 }} />
        <input value={usluga} onChange={(e) => setUsluga(e.target.value)}
          placeholder="Owner service" style={{ minWidth: 160 }} />
      </div>
      <button
        disabled={!sciezka}
        onClick={() =>
          onZapisz({
            path: sciezka, key_path: klucz, key_secret: sekret,
            reload_unit: jednostka, probe_target: sonda, service: usluga,
          })
        }
      >
        Watch
      </button>
    </div>
  );
}

/** Formularz wdrozenia certyfikatu. Klucz wskazujemy nazwa sekretu. */
function FormularzWdrozenia({
  cele, hostname, onZamiar,
}: {
  cele: Cel[];
  hostname: string;
  onZamiar: (zamiar: Zamiar) => void;
}) {
  const [sciezka, setSciezka] = useState(cele[0]?.path ?? "");
  const [tresc, setTresc] = useState("");
  const wybrany = cele.find((cel) => cel.path === sciezka);

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Deploy a certificate</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        Paste the certificate with its chain, leaf first. The private key is not
        pasted here and never travels in the job: the host fetches it from the
        secret named on the watched path, once, while it runs the operation.
      </p>
      <label>
        Watched path
        <select value={sciezka} onChange={(e) => setSciezka(e.target.value)}>
          {cele.length === 0 && <option value="">no watched path on this host</option>}
          {cele.map((cel) => (
            <option key={cel.id} value={cel.path}>{cel.path}</option>
          ))}
        </select>
      </label>
      {wybrany && (
        <p className="zrodlo" style={{ margin: 0 }}>
          Key: {wybrany.key_path || "not set"}
          {wybrany.key_secret ? ` from secret ${wybrany.key_secret}` : " — no secret set, the key stays as it is"} ·
          reload {wybrany.reload_unit || "nothing"} ·
          probe {wybrany.probe_target || "none"}
        </p>
      )}
      <label>
        Certificate (PEM, leaf first)
        <textarea rows={10} value={tresc} onChange={(e) => setTresc(e.target.value)}
          placeholder="-----BEGIN CERTIFICATE-----" />
      </label>
      <button
        disabled={!sciezka || !tresc.includes("BEGIN CERTIFICATE")}
        onClick={() =>
          onZamiar({
            akcja: "certificate.deploy",
            etykieta: "Deploy certificate",
            opis: `${sciezka} on ${hostname} is replaced${wybrany?.key_secret ? `, with the key from secret ${wybrany.key_secret}` : ""}${wybrany?.reload_unit ? `, then ${wybrany.reload_unit} is reloaded` : ""}${wybrany?.probe_target ? ` and ${wybrany.probe_target} is checked` : ""}. The host verifies key and chain before the swap and rolls back if the service does not come back with the new certificate.`,
            payload: {
              certificate: {
                path: sciezka,
                key_path: wybrany?.key_path ?? "",
                certificate: tresc,
                reload_unit: wybrany?.reload_unit ?? "",
                probe_target: wybrany?.probe_target ?? "",
                ...(wybrany?.key_secret ? { key_secret: { name: wybrany.key_secret } } : {}),
              },
            },
          })
        }
      >
        Deploy
      </button>
    </div>
  );
}
