import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { LiczbaOpcjonalna, Para, Pary, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul, ZlecOperacje } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Repozytorium = {
  id: string;
  name?: string;
  url?: string;
  suites?: string[];
  components?: string[];
  enabled: boolean;
  priority?: number;
  gpg_key_fingerprint?: string;
  signed: boolean;
  username?: string;
  secret_name?: string;
  managed: boolean;
  path?: string;
  unavailable_reason?: string;
};

type ObrazRepozytoriow = {
  repositories?: Repozytorium[];
  repositories_known?: boolean;
  repositories_unavailable_reason?: string;
};

type StanPakietow = {
  manager?: string;
  installed?: number;
  upgradable?: number;
  security_upgradable?: number;
  unavailable_reason?: string;
  repositories?: ObrazRepozytoriow;
};

type PlanUsuniecia = {
  mode?: string;
  removals?: string[];
  protected?: string[];
};

type Proba = { status?: string; message?: string; detail?: PlanUsuniecia };

/**
 * Pakiety hosta.
 *
 * Instalacja i usuniecie sa oddzielone od aktualizacji: to trzy rozne decyzje
 * o tym samym hoscie. Usuniecie przechodzi przez plan, bo jeden pakiet potrafi
 * pociagnac kilkadziesiat zaleznych.
 */
export function Pakiety() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<StanPakietow>(host.id, "packages");
  const pakiety = modul.data?.payload;

  const [nazwy, setNazwy] = useState("");
  const [plan, setPlan] = useState<PlanUsuniecia | null>(null);
  const [doUsuniecia, setDoUsuniecia] = useState<string[] | null>(null);
  const [zamiarZrodla, setZamiarZrodla] = useState<ZamiarZrodla | null>(null);
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
      setDoUsuniecia(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const lista = () =>
    nazwy.split(/[\s,]+/).map((nazwa) => nazwa.trim()).filter(Boolean);

  // Plan usuniecia liczy sie na hoscie, wiec ekran czeka na jego wynik.
  const zaplanujUsuniecie = useMutation({
    mutationFn: async () => {
      const zadanie = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.plan",
        payload: { package_plan: { mode: "remove", only_packages: lista() } },
      });
      for (let proba = 0; proba < 30; proba++) {
        await new Promise((gotowe) => setTimeout(gotowe, 1500));
        const proby = await api.get<{ items: Proba[] }>(`/api/v1/jobs/${zadanie.id}/attempts`);
        const ostatnia = proby.items[proby.items.length - 1];
        if (!ostatnia?.status) continue;
        if (ostatnia.status !== "succeeded") {
          throw new Error(ostatnia.message || "The host refused to plan the removal.");
        }
        return ostatnia.detail ?? {};
      }
      throw new Error("The plan did not arrive in time.");
    },
    onSuccess: (wynik) => { setPlan(wynik); setKomunikat(""); },
    onError: (error) => {
      setPlan(null);
      setKomunikat(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <>
      <Pary>
        <Para etykieta="Manager">{pakiety?.manager || "—"}</Para>
        <Para etykieta="Installed">
          {pakiety?.installed ?? <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Upgradable"><LiczbaOpcjonalna wartosc={host.pending_updates} /></Para>
        <Para etykieta="Security updates">
          <LiczbaOpcjonalna wartosc={host.pending_security_updates} />
        </Para>
        <Para etykieta="Package database">
          {host.package_database_broken
            ? <span className="znacznik blad">needs repair</span>
            : "healthy"}
        </Para>
      </Pary>
      <SwiezoscModulu fragment={modul.data} />

      <ZlecOperacje
        host={host}
        opis="Count available updates without changing host state."
        akcja="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        etykieta="Plan updates"
      />

      <Repozytoria
        obraz={pakiety?.repositories}
        menedzer={pakiety?.manager}
        onZamiar={setZamiarZrodla}
      />

      <h2>Install, remove or hold</h2>
      <div className="formularz">
        <label>
          Package names (space or comma separated)
          <input value={nazwy} onChange={(e) => { setNazwy(e.target.value); setPlan(null); }}
                 placeholder="nginx htop" />
        </label>
        <div className="operacje">
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.install",
              payload: { package_change: { packages: lista() } },
            })}
          >
            Install
          </button>
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.hold.set",
              payload: { package_change: { packages: lista(), hold: true } },
            })}
          >
            Hold
          </button>
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.hold.set",
              payload: { package_change: { packages: lista(), hold: false } },
            })}
          >
            Unhold
          </button>
          {/* Usuniecie nie idzie wprost: jeden pakiet potrafi pociagnac
              kilkadziesiat zaleznych i operator ma je zobaczyc wczesniej. */}
          <button
            className="wtorny"
            disabled={zaplanujUsuniecie.isPending || lista().length === 0}
            onClick={() => zaplanujUsuniecie.mutate()}
          >
            {zaplanujUsuniecie.isPending ? "Planning…" : "Plan removal"}
          </button>
        </div>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginTop: 12 }}>{komunikat}</p>}

      {plan && (
        <>
          <h2>Removal plan</h2>
          {plan.protected && plan.protected.length > 0 && (
            <p className="ostrzezenie">
              <span>
                These packages are protected and will not be removed:{" "}
                {plan.protected.join(", ")}. Removing them would leave the host
                unmanageable or unbootable.
              </span>
            </p>
          )}
          {!plan.removals?.length ? (
            <Pusto>Nothing would be removed.</Pusto>
          ) : (
            <>
              <table>
                <thead><tr><th>Package</th><th>Reason</th></tr></thead>
                <tbody>
                  {plan.removals.map((pakiet) => (
                    <tr key={pakiet}>
                      <td>{pakiet}</td>
                      <td>{lista().includes(pakiet) ? "requested" : "dependency"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="zrodlo" style={{ marginTop: 8 }}>
                {plan.removals.length} package(s) would be removed. The host recomputes
                this set before removing; a difference cancels the operation.
              </p>
              {(!plan.protected || plan.protected.length === 0) && (
                <div className="operacje" style={{ marginTop: 12 }}>
                  <button onClick={() => setDoUsuniecia(plan.removals ?? [])}>
                    Remove these packages
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}

      {zamiarZrodla && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiarZrodla.etykieta}
          opis={zamiarZrodla.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({
              action: "packages.repository.set",
              reason: powod,
              payload: { repository: zamiarZrodla.payload },
            })
          }
          onAnuluj={() => setZamiarZrodla(null)}
        />
      )}

      {doUsuniecia && (
        <PotwierdzenieCelu
          host={host}
          etykieta="Remove packages"
          opis={`${doUsuniecia.length} package(s) will be removed: ${doUsuniecia.slice(0, 6).join(", ")}${doUsuniecia.length > 6 ? "…" : ""}.`}
          pracuje={zlec.isPending}
          onPotwierdz={(powod, potwierdzenie) =>
            zlec.mutate({
              action: "packages.remove",
              reason: powod,
              target_confirmation: potwierdzenie,
              payload: {
                package_change: { packages: lista(), expected_removals: doUsuniecia },
              },
            })
          }
          onAnuluj={() => setDoUsuniecia(null)}
        />
      )}
    </>
  );
}

type ZamiarZrodla = { etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Zrodla pakietow.
 *
 * Dopisanie zrodla nie instaluje niczego dzisiaj, ale rozstrzyga, czyje
 * pakiety host przyjmie jutro - razem z ich skryptami, ktore chodza jako root.
 * Dlatego zrodlo bez sprawdzania podpisow wymaga jawnej zgody, a haslo do
 * zrodla prywatnego wskazuje sie nazwa sekretu, nie wartoscia.
 */
function Repozytoria({
  obraz, menedzer, onZamiar,
}: {
  obraz?: ObrazRepozytoriow;
  menedzer?: string;
  onZamiar: (zamiar: ZamiarZrodla) => void;
}) {
  const [formularz, setFormularz] = useState(false);
  const zrodla = obraz?.repositories ?? [];

  return (
    <>
      <h2>Repositories</h2>
      <p className="podtytul">
        Where this host takes software from. Adding a source installs nothing
        today; it decides whose packages the host will accept tomorrow, with
        their scripts running as root.
      </p>
      {obraz && obraz.repositories_known === false && (
        <p className="ostrzezenie">
          <span>
            The list of sources could not be read
            {obraz.repositories_unavailable_reason
              ? `: ${obraz.repositories_unavailable_reason}`
              : "."}
          </span>
        </p>
      )}

      <div className="filtry">
        <button className="wtorny" onClick={() => setFormularz((otwarty) => !otwarty)}>
          {formularz ? "Cancel" : "Add or change a source"}
        </button>
      </div>
      {formularz && <FormularzZrodla menedzer={menedzer} onZamiar={onZamiar} />}

      {!zrodla.length ? (
        <Pusto>This host reports no package source.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Source</th><th>Address</th><th>State</th><th>Signatures</th>
              <th>Managed by</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {zrodla.map((zrodlo) => (
              <tr key={`${zrodlo.path}-${zrodlo.id}`}>
                <td>
                  {zrodlo.id}
                  {zrodlo.path && <div className="zrodlo">{zrodlo.path}</div>}
                </td>
                <td className="zrodlo">
                  {zrodlo.unavailable_reason ? (
                    <span className="znacznik nieznany">{zrodlo.unavailable_reason}</span>
                  ) : (
                    <>
                      {zrodlo.url}
                      {zrodlo.suites?.length ? (
                        <div>{zrodlo.suites.join(" ")} {zrodlo.components?.join(" ")}</div>
                      ) : null}
                    </>
                  )}
                </td>
                <td>
                  {zrodlo.enabled
                    ? <span className="znacznik ok">enabled</span>
                    : <span className="znacznik">disabled</span>}
                </td>
                <td>
                  {/* Zrodlo bez sprawdzania podpisow jest zdalna powloka
                      roota, a nie ustawieniem - i tak ma wygladac. */}
                  {zrodlo.signed
                    ? <span className="znacznik ok">checked</span>
                    : <span className="znacznik blad">not checked</span>}
                </td>
                <td>
                  {zrodlo.managed ? (
                    <>
                      <span className="znacznik ok">panel</span>
                      {zrodlo.secret_name && (
                        <div className="zrodlo">password from {zrodlo.secret_name}</div>
                      )}
                    </>
                  ) : (
                    <span className="znacznik">distribution</span>
                  )}
                </td>
                <td>
                  <div className="operacje">
                    <button
                      className="wtorny"
                      disabled={!zrodlo.managed}
                      onClick={() =>
                        onZamiar({
                          etykieta: zrodlo.enabled ? "Disable source" : "Enable source",
                          opis: `${zrodlo.id} will be ${zrodlo.enabled ? "disabled" : "enabled"}. The files stay on the host.`,
                          payload: {
                            id: zrodlo.id, url: zrodlo.url, name: zrodlo.name,
                            suites: zrodlo.suites, components: zrodlo.components,
                            enabled: !zrodlo.enabled, allow_unsigned: !zrodlo.signed,
                          },
                        })
                      }
                    >
                      {zrodlo.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      className="wtorny"
                      disabled={!zrodlo.managed}
                      onClick={() =>
                        onZamiar({
                          etykieta: "Remove source",
                          opis: `${zrodlo.id} will be removed from this host, together with its key and its password file.`,
                          payload: { id: zrodlo.id, remove: true },
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
    </>
  );
}

/** Formularz zrodla. Klucz wkleja sie w ramce ASCII; haslo wskazuje nazwa sekretu. */
function FormularzZrodla({
  menedzer, onZamiar,
}: {
  menedzer?: string;
  onZamiar: (zamiar: ZamiarZrodla) => void;
}) {
  const [id, setId] = useState("");
  const [url, setUrl] = useState("");
  const [suites, setSuites] = useState("");
  const [components, setComponents] = useState("");
  const [klucz, setKlucz] = useState("");
  const [bezPodpisow, setBezPodpisow] = useState(false);
  const [uzytkownik, setUzytkownik] = useState("");
  const [sekret, setSekret] = useState("");
  const apt = menedzer === "apt";

  const gotowe = id !== "" && url !== "" && (bezPodpisow || klucz.includes("BEGIN PGP")) &&
    (!apt || suites.trim() !== "");

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Package source</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        The key travels in the job — it is public, and the plan should show what
        the host will trust. The password does not: name a secret and the host
        fetches its value once, while it writes the file.
      </p>
      <div className="filtry">
        <input value={id} onChange={(e) => setId(e.target.value)}
               placeholder="internal" style={{ minWidth: 160 }} />
        <input value={url} onChange={(e) => setUrl(e.target.value)}
               placeholder="https://packages.example.com/debian" style={{ minWidth: 320 }} />
      </div>
      {apt && (
        <div className="filtry">
          <input value={suites} onChange={(e) => setSuites(e.target.value)}
                 placeholder="Suites (stable)" style={{ minWidth: 200 }} />
          <input value={components} onChange={(e) => setComponents(e.target.value)}
                 placeholder="Components (main)" style={{ minWidth: 200 }} />
        </div>
      )}
      <div className="filtry">
        <input value={uzytkownik} onChange={(e) => setUzytkownik(e.target.value)}
               placeholder="Username (private source)" style={{ minWidth: 200 }} />
        <input value={sekret} onChange={(e) => setSekret(e.target.value)}
               placeholder="Password secret (name only)" style={{ minWidth: 220 }} />
      </div>
      <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={bezPodpisow}
               onChange={(e) => setBezPodpisow(e.target.checked)} />
        Do not check signatures (the host will install anything from this address)
      </label>
      {!bezPodpisow && (
        <label>
          Signing key (ASCII-armored public key)
          <textarea rows={8} value={klucz} onChange={(e) => setKlucz(e.target.value)}
                    placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" />
        </label>
      )}
      <button
        disabled={!gotowe}
        onClick={() =>
          onZamiar({
            etykieta: "Write source",
            opis: `${id} (${url}) becomes a package source on this host${bezPodpisow ? ", with signature checking off — the host will install whatever comes from that address" : ""}${sekret ? `, authenticating as ${uzytkownik} with the value of secret ${sekret}` : ""}. The host fetches its metadata before the change counts as done, and rolls back if it cannot.`,
            payload: {
              id, url, enabled: true, allow_unsigned: bezPodpisow,
              ...(apt ? {
                suites: suites.split(/[\s,]+/).filter(Boolean),
                components: components.split(/[\s,]+/).filter(Boolean),
              } : {}),
              ...(bezPodpisow ? {} : { gpg_key: klucz }),
              ...(sekret ? { username: uzytkownik, password_secret: { name: sekret } } : {}),
            },
          })
        }
      >
        Write source
      </button>
    </div>
  );
}
