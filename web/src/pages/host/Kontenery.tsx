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
  compose?: { project: string; service: string };
};

type StanPelny = {
  summary?: Podsumowanie;
  containers?: Kontener[];
  images?: { id: string; tags?: string[]; size_bytes: number; in_use: boolean }[];
};

/**
 * Kontenery hosta.
 *
 * Podsumowanie pochodzi z cyklu inwentarza i jest tanie. Pelne listy sa
 * pobierane wtedy, gdy operator o nie poprosi: odpytywanie silnika o setki
 * obrazow przy kazdym cyklu obciazaloby host bez powodu.
 */
/** Operacja nieodwracalna czekajaca na potwierdzenie operatora. */
type DoPotwierdzenia =
  | { rodzaj: "usun-kontener"; id: string; nazwa: string }
  | { rodzaj: "usun-obraz"; id: string; nazwa: string };

export function Kontenery() {
  const host = useHost();
  const queryClient = useQueryClient();
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
    zlec.mutate({
      action: "docker.prune",
      reason: powod,
      target_confirmation: potwierdzenie,
      payload: { docker_prune: { image_ids: [doPotwierdzenia.id] } },
    });
  }

  const stan = podsumowanie.data?.payload;
  const listy = pelny.data?.payload;

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
        <Para etykieta="Networks">{stan?.networks ?? "—"}</Para>
        <Para etykieta="Volumes">{stan?.volumes ?? "—"}</Para>
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

      <h2>Containers</h2>
      <p className="podtytul">
        Full lists are read from the host on request, not on every inventory cycle.{" "}
        <button
          className="wtorny"
          onClick={() => odswiez.mutate()}
          disabled={odswiez.isPending || host.connection_state !== "online"}
        >
          {odswiez.isPending ? "Requesting…" : "Read from host"}
        </button>
      </p>

      {!listy?.containers?.length ? (
        <Pusto>
          {pelny.data
            ? "No containers were reported the last time this host was read."
            : "This host has not been read yet. Use “Read from host”."}
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th><th>State</th><th>Image</th><th>Health</th>
              <th>Restarts</th><th>Ports</th><th>Compose</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {listy.containers.map((kontener) => (
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
                <td>{kontener.compose ? `${kontener.compose.project}/${kontener.compose.service}` : "—"}</td>
                <td>
                  <div className="operacje">
                    {kontener.state === "running" ? (
                      <>
                        <button onClick={() => operacjaKontenera("docker.container.restart", kontener)}>Restart</button>
                        <button onClick={() => operacjaKontenera("docker.container.stop", kontener)}>Stop</button>
                      </>
                    ) : (
                      <button onClick={() => operacjaKontenera("docker.container.start", kontener)}>Start</button>
                    )}
                    {/* Usuniecie jest nieodwracalne, wiec nie idzie wprost
                        z klikniecia - otwiera potwierdzenie celu. */}
                    <button
                      onClick={() =>
                        setDoPotwierdzenia({ rodzaj: "usun-kontener", id: kontener.id, nazwa: kontener.name })
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

      {listy?.images && listy.images.length > 0 && (
        <>
          <h2>Images</h2>
          <table>
            <thead><tr><th>Tags</th><th>Size</th><th>In use</th><th>Actions</th></tr></thead>
            <tbody>
              {listy.images.map((obraz) => (
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
                      <button
                        className="wtorny"
                        onClick={() =>
                          setDoPotwierdzenia({
                            rodzaj: "usun-obraz",
                            id: obraz.id,
                            nazwa: obraz.tags?.[0] || obraz.id.slice(7, 19),
                          })
                        }
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {doPotwierdzenia && (
        <PotwierdzenieCelu
          host={host}
          etykieta={doPotwierdzenia.rodzaj === "usun-kontener" ? "Remove container" : "Remove image"}
          opis={
            doPotwierdzenia.rodzaj === "usun-kontener"
              ? `Container ${doPotwierdzenia.nazwa} will be removed. Data outside volumes is lost.`
              : `Image ${doPotwierdzenia.nazwa} will be removed from this host.`
          }
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
