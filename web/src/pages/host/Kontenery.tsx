import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Para, Pary, Pusto } from "../../components/ui";
import { bytes } from "../../lib/format";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Podsumowanie = {
  engine_version?: string;
  api_version?: string;
  containers?: number;
  running?: number;
  paused?: number;
  stopped?: number;
  unhealthy?: number;
  restart_looping?: number;
  images?: number;
  volumes?: number;
  networks?: number;
  volumes_unused?: number;
  networks_unused?: number;
  projects?: { name: string; services: string[]; running: number; total: number }[];
  unavailable_reason?: string;
};

type Kontener = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  health?: string;
  restart_count: number;
  ports?: { host_port?: number; container_port: number; protocol: string }[];
  networks?: { name: string; ipv4?: string }[];
  compose?: { project: string; service: string };
};

type Siec = {
  id: string;
  name: string;
  driver: string;
  scope?: string;
  subnets?: string[];
  gateways?: string[];
  internal: boolean;
  attachable: boolean;
  ipv6: boolean;
  predefined: boolean;
  compose?: string;
  containers?: { id: string; name: string; state?: string; ipv4?: string }[];
  in_use: boolean;
};

type Wolumen = {
  name: string;
  driver: string;
  mountpoint?: string;
  scope?: string;
  compose?: string;
  created_at?: string;
  used_by?: { container_id: string; container_name: string; state?: string; destination: string; read_only: boolean }[];
  in_use: boolean;
  size_bytes?: number;
  size_reason?: string;
};

type StanPelny = {
  summary?: Podsumowanie;
  containers?: Kontener[];
  images?: { id: string; tags?: string[]; size_bytes: number; in_use: boolean }[];
  networks?: Siec[];
  volumes?: Wolumen[];
};

/** Operacja nieodwracalna czekajaca na potwierdzenie operatora. */
type DoPotwierdzenia =
  | { rodzaj: "usun-kontener"; id: string; nazwa: string }
  | { rodzaj: "usun-obraz"; id: string; nazwa: string }
  | { rodzaj: "usun-siec"; id: string; nazwa: string }
  | { rodzaj: "usun-wolumen"; id: string; nazwa: string };

type Widok = "kontenery" | "obrazy" | "sieci" | "wolumeny";

/**
 * Kontenery hosta.
 *
 * Podsumowanie pochodzi z cyklu inwentarza i jest tanie. Pelne listy sa
 * pobierane wtedy, gdy operator o nie poprosi: odpytywanie silnika o setki
 * obrazow przy kazdym cyklu obciazaloby host bez powodu.
 *
 * Sieci i wolumeny maja wlasne podzakladki, a nie sam licznik: to o nie
 * rozbija sie sprzatanie hosta i to one przezywaja kontenery, ktore je
 * utworzyly.
 */
export function Kontenery() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [widok, setWidok] = useState<Widok>("kontenery");
  const [doPotwierdzenia, setDoPotwierdzenia] = useState<DoPotwierdzenia | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const podsumowanie = useModul<Podsumowanie>(host.id, "containers");
  const pelny = useModul<StanPelny>(host.id, "containers.full");

  const odswiez = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.read",
        payload: { docker_read: {} },
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs", host.id] }),
  });

  // Operacje odwracalne ida wprost; nieodwracalne przechodza przez okno
  // potwierdzenia, ktore dokleda powod i nazwe hosta.
  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setDoPotwierdzenia(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  function operacjaKontenera(akcja: string, kontener: Kontener) {
    zlec.mutate({
      action: akcja,
      payload: {
        docker_container: {
          container_id: kontener.id,
          name: kontener.name,
          timeout_seconds: 10,
        },
      },
    });
  }

  function potwierdz(powod: string, potwierdzenie: string) {
    if (!doPotwierdzenia) return;
    if (doPotwierdzenia.rodzaj === "usun-kontener") {
      zlec.mutate({
        action: "docker.container.remove",
        reason: powod,
        target_confirmation: potwierdzenie,
        payload: {
          docker_container: {
            container_id: doPotwierdzenia.id,
            name: doPotwierdzenia.nazwa,
          },
        },
      });
      return;
    }
    // Sprzatanie usuwa dokladnie to, co operator zobaczyl: lista jest jawna,
    // a nie filtrem, ktory dopasuje sie takze do obiektu utworzonego po
    // otwarciu tego widoku.
    const sprzatanie =
      doPotwierdzenia.rodzaj === "usun-obraz"
        ? { image_ids: [doPotwierdzenia.id] }
        : doPotwierdzenia.rodzaj === "usun-siec"
          ? { network_ids: [doPotwierdzenia.id] }
          : { volume_names: [doPotwierdzenia.nazwa] };
    zlec.mutate({
      action: "docker.prune",
      reason: powod,
      target_confirmation: potwierdzenie,
      payload: { docker_prune: sprzatanie },
    });
  }

  const stan = podsumowanie.data?.payload;
  const listy = pelny.data?.payload;
  const przeczytano = pelny.data !== undefined;

  return (
    <>
      <Pary>
        <Para etykieta="Engine">{stan?.engine_version || <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="API">{stan?.api_version || "—"}</Para>
        <Para etykieta="Containers">
          {stan?.containers ?? <span className="znacznik nieznany">unknown</span>}
          {stan?.running !== undefined && ` (${stan.running} running, ${stan.stopped ?? 0} stopped)`}
        </Para>
        <Para etykieta="Unhealthy">
          {stan?.unhealthy ? <span className="znacznik blad">{stan.unhealthy}</span> : (stan?.unhealthy ?? "—")}
        </Para>
        {/* Kontener wstajacy w kolko jest sprawny w kazdej pojedynczej chwili
            i mimo to zepsuty - bez tego licznika nie widac tego wcale. */}
        <Para etykieta="Restart looping">
          {stan?.restart_looping ? <span className="znacznik uwaga">{stan.restart_looping}</span> : (stan?.restart_looping ?? "—")}
        </Para>
        <Para etykieta="Images">{stan?.images ?? "—"}</Para>
        {/* Licznik nieuzywanych mowi, ile z tego mozna sprzatnac - i to jest
            jedyny powod, dla ktorego te liczby w ogole sa w podsumowaniu. */}
        <Para etykieta="Networks">
          {stan?.networks ?? "—"}
          {stan?.networks_unused ? ` (${stan.networks_unused} unused)` : ""}
        </Para>
        <Para etykieta="Volumes">
          {stan?.volumes ?? "—"}
          {stan?.volumes_unused ? ` (${stan.volumes_unused} unused)` : ""}
        </Para>
      </Pary>
      <SwiezoscModulu fragment={podsumowanie.data} />

      {stan?.projects && stan.projects.length > 0 && (
        <>
          <h2>Compose projects</h2>
          <table>
            <thead><tr><th>Project</th><th>Services</th><th>Running</th></tr></thead>
            <tbody>
              {stan.projects.map((projekt) => (
                <tr key={projekt.name}>
                  <td>{projekt.name}</td>
                  <td>{projekt.services.join(", ") || "—"}</td>
                  <td>{projekt.running} / {projekt.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <p className="podtytul" style={{ marginTop: 16 }}>
        Full lists are read from the host on request, not on every inventory cycle.{" "}
        <button
          className="wtorny"
          onClick={() => odswiez.mutate()}
          disabled={odswiez.isPending || host.connection_state !== "online"}
        >
          {odswiez.isPending ? "Requesting…" : "Read from host"}
        </button>
      </p>

      <div className="zakladki">
        <button className={widok === "kontenery" ? "aktywna" : ""} onClick={() => setWidok("kontenery")}>
          Containers{listy?.containers?.length ? ` (${listy.containers.length})` : ""}
        </button>
        <button className={widok === "obrazy" ? "aktywna" : ""} onClick={() => setWidok("obrazy")}>
          Images{listy?.images?.length ? ` (${listy.images.length})` : ""}
        </button>
        <button className={widok === "sieci" ? "aktywna" : ""} onClick={() => setWidok("sieci")}>
          Networks{listy?.networks?.length ? ` (${listy.networks.length})` : ""}
        </button>
        <button className={widok === "wolumeny" ? "aktywna" : ""} onClick={() => setWidok("wolumeny")}>
          Volumes{listy?.volumes?.length ? ` (${listy.volumes.length})` : ""}
        </button>
      </div>

      {widok === "kontenery" && (
        <TabelaKontenerow
          kontenery={listy?.containers}
          przeczytano={przeczytano}
          operacja={operacjaKontenera}
          usun={(kontener) =>
            setDoPotwierdzenia({ rodzaj: "usun-kontener", id: kontener.id, nazwa: kontener.name })
          }
        />
      )}
      {widok === "obrazy" && (
        <TabelaObrazow
          obrazy={listy?.images}
          przeczytano={przeczytano}
          usun={(obraz) =>
            setDoPotwierdzenia({
              rodzaj: "usun-obraz",
              id: obraz.id,
              nazwa: obraz.tags?.[0] || obraz.id.slice(7, 19),
            })
          }
        />
      )}
      {widok === "sieci" && (
        <TabelaSieci
          sieci={listy?.networks}
          przeczytano={przeczytano}
          usun={(siec) => setDoPotwierdzenia({ rodzaj: "usun-siec", id: siec.id, nazwa: siec.name })}
        />
      )}
      {widok === "wolumeny" && (
        <TabelaWolumenow
          wolumeny={listy?.volumes}
          przeczytano={przeczytano}
          usun={(wolumen) =>
            setDoPotwierdzenia({ rodzaj: "usun-wolumen", id: wolumen.name, nazwa: wolumen.name })
          }
        />
      )}

      {doPotwierdzenia && (
        <PotwierdzenieCelu
          host={host}
          etykieta={etykietaUsuniecia(doPotwierdzenia)}
          opis={opisUsuniecia(doPotwierdzenia)}
          pracuje={zlec.isPending}
          onPotwierdz={potwierdz}
          onAnuluj={() => setDoPotwierdzenia(null)}
        />
      )}

      {komunikat && <p className="zrodlo" style={{ marginTop: 12 }}>{komunikat}</p>}

      {pelny.data && (
        <p className="zrodlo" style={{ marginTop: 16 }}>
          Full state read from the host <Czas wartosc={pelny.data.observed_at} />
          {listy?.summary?.unavailable_reason && ` · ${listy.summary.unavailable_reason}`}
        </p>
      )}
    </>
  );
}

function etykietaUsuniecia(cel: DoPotwierdzenia): string {
  switch (cel.rodzaj) {
    case "usun-kontener":
      return "Remove container";
    case "usun-obraz":
      return "Remove image";
    case "usun-siec":
      return "Remove network";
    case "usun-wolumen":
      return "Remove volume";
  }
}

function opisUsuniecia(cel: DoPotwierdzenia): string {
  switch (cel.rodzaj) {
    case "usun-kontener":
      return `Container ${cel.nazwa} will be removed. Data outside volumes is lost.`;
    case "usun-obraz":
      return `Image ${cel.nazwa} will be removed from this host.`;
    case "usun-siec":
      return `Network ${cel.nazwa} will be removed. Containers attached later will not find it.`;
    case "usun-wolumen":
      // Wolumen jest tym, co przezywa kontener - i dlatego jego usuniecie
      // jest jedyna operacja tej zakladki, ktora naprawde kasuje dane.
      return `Volume ${cel.nazwa} will be removed with everything stored in it. This cannot be undone.`;
  }
}

/** Pusty widok mowi, czy host nie ma czego pokazac, czy nikt go nie pytal. */
function PustaLista({ przeczytano, czego }: { przeczytano: boolean; czego: string }) {
  return (
    <Pusto>
      {przeczytano
        ? `No ${czego} were reported the last time this host was read.`
        : "This host has not been read yet. Use “Read from host”."}
    </Pusto>
  );
}

function TabelaKontenerow({
  kontenery,
  przeczytano,
  operacja,
  usun,
}: {
  kontenery?: Kontener[];
  przeczytano: boolean;
  operacja: (akcja: string, kontener: Kontener) => void;
  usun: (kontener: Kontener) => void;
}) {
  if (!kontenery?.length) return <PustaLista przeczytano={przeczytano} czego="containers" />;
  return (
    <table>
      <thead>
        <tr>
          <th>Name</th><th>State</th><th>Image</th><th>Health</th>
          <th>Restarts</th><th>Ports</th><th>Networks</th><th>Compose</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {kontenery.map((kontener) => (
          <tr key={kontener.id}>
            <td>{kontener.name}</td>
            <td>
              <span className={kontener.state === "running" ? "znacznik ok" : "znacznik"}>
                {kontener.state}
              </span>
            </td>
            <td>{kontener.image}</td>
            {/* Obraz bez health checku i obraz niezdrowy to dwie rozne rzeczy. */}
            <td>
              {!kontener.health ? (
                <span className="znacznik nieznany">no check</span>
              ) : kontener.health === "healthy" ? (
                <span className="znacznik ok">healthy</span>
              ) : (
                <span className="znacznik blad">{kontener.health}</span>
              )}
            </td>
            <td>{kontener.restart_count}</td>
            <td>
              {(kontener.ports ?? [])
                .map((port) =>
                  port.host_port
                    ? `${port.host_port}→${port.container_port}/${port.protocol}`
                    : `${port.container_port}/${port.protocol}`,
                )
                .join(", ") || "—"}
            </td>
            <td>
              {(kontener.networks ?? [])
                .map((siec) => (siec.ipv4 ? `${siec.name} ${siec.ipv4}` : siec.name))
                .join(", ") || "—"}
            </td>
            <td>{kontener.compose ? `${kontener.compose.project}/${kontener.compose.service}` : "—"}</td>
            <td>
              <div className="operacje">
                {kontener.state === "running" ? (
                  <>
                    <button onClick={() => operacja("docker.container.restart", kontener)}>Restart</button>
                    <button onClick={() => operacja("docker.container.stop", kontener)}>Stop</button>
                  </>
                ) : (
                  <button onClick={() => operacja("docker.container.start", kontener)}>Start</button>
                )}
                {/* Usuniecie jest nieodwracalne, wiec nie idzie wprost
                    z klikniecia - otwiera potwierdzenie celu. */}
                <button onClick={() => usun(kontener)}>Remove</button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TabelaObrazow({
  obrazy,
  przeczytano,
  usun,
}: {
  obrazy?: StanPelny["images"];
  przeczytano: boolean;
  usun: (obraz: NonNullable<StanPelny["images"]>[number]) => void;
}) {
  if (!obrazy?.length) return <PustaLista przeczytano={przeczytano} czego="images" />;
  return (
    <table>
      <thead><tr><th>Tags</th><th>Size</th><th>In use</th><th>Actions</th></tr></thead>
      <tbody>
        {obrazy.map((obraz) => (
          <tr key={obraz.id}>
            <td>{obraz.tags?.join(", ") || <span className="znacznik nieznany">untagged</span>}</td>
            <td>{bytes(obraz.size_bytes)}</td>
            <td>{obraz.in_use ? "yes" : "no"}</td>
            <td>
              {/* Obraz w uzyciu nie moze zostac usuniety przez pomylke:
                  przycisku przy nim po prostu nie ma. */}
              {obraz.in_use ? (
                "—"
              ) : (
                <button className="wtorny" onClick={() => usun(obraz)}>Remove</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Sieci hosta.
 *
 * Kolumna z kontenerami jest tu najwazniejsza: to ona odpowiada na pytanie,
 * czy siec mozna usunac. Siec wbudowana silnika nie ma przycisku wcale -
 * silnik i tak by odmowil, a przycisk, ktory zawsze konczy sie bledem, jest
 * gorszy niz jego brak.
 */
function TabelaSieci({
  sieci,
  przeczytano,
  usun,
}: {
  sieci?: Siec[];
  przeczytano: boolean;
  usun: (siec: Siec) => void;
}) {
  if (!sieci?.length) return <PustaLista przeczytano={przeczytano} czego="networks" />;
  return (
    <table>
      <thead>
        <tr>
          <th>Name</th><th>Driver</th><th>Subnets</th><th>Flags</th>
          <th>Compose</th><th>Attached containers</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {sieci.map((siec) => (
          <tr key={siec.id}>
            <td>
              {siec.name}
              {siec.predefined && <span className="znacznik" style={{ marginLeft: 6 }}>built-in</span>}
            </td>
            <td>{siec.driver}{siec.scope && siec.scope !== "local" ? ` · ${siec.scope}` : ""}</td>
            <td>
              {(siec.subnets ?? []).length ? (
                <>
                  {siec.subnets!.join(", ")}
                  {siec.gateways?.length ? <div className="zrodlo">gw {siec.gateways.join(", ")}</div> : null}
                </>
              ) : (
                "—"
              )}
            </td>
            <td>
              {[
                siec.internal && "internal",
                siec.attachable && "attachable",
                siec.ipv6 && "ipv6",
              ]
                .filter(Boolean)
                .join(", ") || "—"}
            </td>
            <td>{siec.compose || "—"}</td>
            <td>
              {siec.containers?.length
                ? siec.containers
                    .map((kontener) => (kontener.ipv4 ? `${kontener.name} ${kontener.ipv4}` : kontener.name))
                    .join(", ")
                : <span className="znacznik">unused</span>}
            </td>
            <td>
              {siec.predefined || siec.in_use ? (
                "—"
              ) : (
                <button className="wtorny" onClick={() => usun(siec)}>Remove</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Wolumeny hosta.
 *
 * Rozmiar bywa nieznany i tak jest pokazywany: zero znaczyloby wolumen pusty
 * i gotowy do skasowania, a to zupelnie inna informacja. Uzycie obejmuje
 * kontenery zatrzymane - wolumen zatrzymanego kontenera nie jest niczyj.
 */
function TabelaWolumenow({
  wolumeny,
  przeczytano,
  usun,
}: {
  wolumeny?: Wolumen[];
  przeczytano: boolean;
  usun: (wolumen: Wolumen) => void;
}) {
  if (!wolumeny?.length) return <PustaLista przeczytano={przeczytano} czego="volumes" />;
  return (
    <table>
      <thead>
        <tr>
          <th>Name</th><th>Driver</th><th>Size</th><th>Mountpoint</th>
          <th>Compose</th><th>Used by</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {wolumeny.map((wolumen) => (
          <tr key={wolumen.name}>
            <td>{wolumen.name}</td>
            <td>{wolumen.driver}</td>
            <td>
              {wolumen.size_bytes !== undefined ? (
                bytes(wolumen.size_bytes)
              ) : (
                <span className="znacznik nieznany" title={wolumen.size_reason || undefined}>unknown</span>
              )}
            </td>
            <td>{wolumen.mountpoint || "—"}</td>
            <td>{wolumen.compose || "—"}</td>
            <td>
              {wolumen.used_by?.length
                ? wolumen.used_by
                    .map(
                      (uzycie) =>
                        `${uzycie.container_name}:${uzycie.destination}${uzycie.read_only ? " ro" : ""}` +
                        (uzycie.state && uzycie.state !== "running" ? ` (${uzycie.state})` : ""),
                    )
                    .join(", ")
                : <span className="znacznik">unused</span>}
            </td>
            <td>
              {/* Wolumen w uzyciu nie ma przycisku: jego usuniecie to utrata
                  danych uslugi, ktora wlasnie z niego korzysta. */}
              {wolumen.in_use ? (
                "—"
              ) : (
                <button className="wtorny" onClick={() => usun(wolumen)}>Remove</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
