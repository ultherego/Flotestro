import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Pair, Pairs, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Summary = {
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

type Container = {
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

type Network = {
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

type Volume = {
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

type FullState = {
  summary?: Summary;
  containers?: Container[];
  images?: { id: string; tags?: string[]; size_bytes: number; in_use: boolean }[];
  networks?: Network[];
  volumes?: Volume[];
};

/** An irreversible operation waiting for the operator's confirmation. */
type Pending =
  | { kind: "remove-container"; id: string; name: string }
  | { kind: "remove-image"; id: string; name: string }
  | { kind: "remove-network"; id: string; name: string }
  | { kind: "remove-volume"; id: string; name: string };

type View = "containers" | "images" | "networks" | "volumes" | "events";

type Event = {
  time: string;
  type: string;
  action: string;
  actor_id?: string;
  actor_name?: string;
  attributes?: Record<string, string>;
};

type EventsResult = {
  kind?: string;
  events?: {
    events?: Event[];
    since?: string;
    until?: string;
    types?: string[];
    truncated?: boolean;
    truncated_reason?: string;
  };
  truncated?: boolean;
  truncated_reason?: string;
  unavailable_reason?: string;
};

/**
 * The host's containers.
 *
 * The summary comes from the inventory cycle and is cheap. The full lists
 * are fetched when the operator asks for them: querying the engine about
 * hundreds of images on every cycle would load the host for no reason.
 *
 * Networks and volumes have sub-tabs of their own, not just a counter: they
 * are what host clean-up trips over, and they outlive the containers that
 * created them.
 */
export function Containers() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [view, setView] = useState<View>("containers");
  const [pending, setPending] = useState<Pending | null>(null);
  const [message, setMessage] = useState("");
  const summary = useModule<Summary>(host.id, "containers");
  const full = useModule<FullState>(host.id, "containers.full");
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  const refresh = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.read",
        payload: { docker_read: {} },
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs", host.id] }),
  });

  // Reversible operations go straight through; irreversible ones pass
  // through the confirmation dialog, which adds the reason and the hostname.
  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setPending(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  function containerOperation(action: string, container: Container) {
    request.mutate({
      action,
      payload: {
        docker_container: {
          container_id: container.id,
          name: container.name,
          timeout_seconds: 10,
        },
      },
    });
  }

  function confirm(reason: string, confirmation: string) {
    if (!pending) return;
    if (pending.kind === "remove-container") {
      request.mutate({
        action: "docker.container.remove",
        reason,
        target_confirmation: confirmation,
        payload: {
          docker_container: {
            container_id: pending.id,
            name: pending.name,
          },
        },
      });
      return;
    }
    // Pruning removes exactly what the operator saw: the list is explicit,
    // not a filter that would also match an object created after this view
    // was opened.
    const prune =
      pending.kind === "remove-image"
        ? { image_ids: [pending.id] }
        : pending.kind === "remove-network"
          ? { network_ids: [pending.id] }
          : { volume_names: [pending.name] };
    request.mutate({
      action: "docker.prune",
      reason,
      target_confirmation: confirmation,
      payload: { docker_prune: prune },
    });
  }

  const state = summary.data?.payload;
  const lists = full.data?.payload;
  const read = full.data !== undefined;

  return (
    <>
      <Pairs>
        <Pair label={t("Engine")}>{state?.engine_version || unknown}</Pair>
        <Pair label="API">{state?.api_version || "—"}</Pair>
        <Pair label={t("Containers")}>
          {state?.containers ?? unknown}
          {state?.running !== undefined && ` (${t("{running} running, {stopped} stopped", { running: state.running, stopped: state.stopped ?? 0 })})`}
        </Pair>
        <Pair label={t("Unhealthy")}>
          {state?.unhealthy ? <span className="badge error">{state.unhealthy}</span> : (state?.unhealthy ?? "—")}
        </Pair>
        {/* A container that keeps coming up is healthy at every single
            moment and broken nonetheless - without this counter that is
            not visible at all. */}
        <Pair label={t("Restart looping")}>
          {state?.restart_looping ? <span className="badge warn">{state.restart_looping}</span> : (state?.restart_looping ?? "—")}
        </Pair>
        <Pair label={t("Images")}>{state?.images ?? "—"}</Pair>
        {/* The unused counter says how much of this can be cleaned up - and
            that is the only reason these numbers are in the summary at all. */}
        <Pair label={t("Networks")}>
          {state?.networks ?? "—"}
          {state?.networks_unused ? ` (${t("{n} unused", { n: state.networks_unused })})` : ""}
        </Pair>
        <Pair label={t("Volumes")}>
          {state?.volumes ?? "—"}
          {state?.volumes_unused ? ` (${t("{n} unused", { n: state.volumes_unused })})` : ""}
        </Pair>
      </Pairs>
      <ModuleFreshness fragment={summary.data} />

      {state?.projects && state.projects.length > 0 && (
        <>
          <h2>{t("Compose projects")}</h2>
          <table>
            <thead><tr><th>{t("Project")}</th><th>{t("Services")}</th><th>{t("Running")}</th></tr></thead>
            <tbody>
              {state.projects.map((project) => (
                <tr key={project.name}>
                  <td>{project.name}</td>
                  <td>{project.services.join(", ") || "—"}</td>
                  <td>{project.running} / {project.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <p className="subtitle" style={{ marginTop: 16 }}>
        {t("Full lists are read from the host on request, not on every inventory cycle.")}{" "}
        <button
          className="secondary"
          onClick={() => refresh.mutate()}
          disabled={refresh.isPending || host.connection_state !== "online"}
        >
          {refresh.isPending ? t("Requesting…") : t("Read from host")}
        </button>
      </p>

      <div className="tabs">
        <button className={view === "containers" ? "active" : ""} onClick={() => setView("containers")}>
          {t("Containers")}{lists?.containers?.length ? ` (${lists.containers.length})` : ""}
        </button>
        <button className={view === "images" ? "active" : ""} onClick={() => setView("images")}>
          {t("Images")}{lists?.images?.length ? ` (${lists.images.length})` : ""}
        </button>
        <button className={view === "networks" ? "active" : ""} onClick={() => setView("networks")}>
          {t("Networks")}{lists?.networks?.length ? ` (${lists.networks.length})` : ""}
        </button>
        <button className={view === "volumes" ? "active" : ""} onClick={() => setView("volumes")}>
          {t("Volumes")}{lists?.volumes?.length ? ` (${lists.volumes.length})` : ""}
        </button>
        <button className={view === "events" ? "active" : ""} onClick={() => setView("events")}>
          {t("Events")}
        </button>
      </div>

      {view === "containers" && (
        <ContainerTable
          containers={lists?.containers}
          read={read}
          operation={containerOperation}
          remove={(container) =>
            setPending({ kind: "remove-container", id: container.id, name: container.name })
          }
        />
      )}
      {view === "images" && (
        <ImageTable
          images={lists?.images}
          read={read}
          remove={(image) =>
            setPending({
              kind: "remove-image",
              id: image.id,
              name: image.tags?.[0] || image.id.slice(7, 19),
            })
          }
        />
      )}
      {view === "networks" && (
        <NetworkTable
          networks={lists?.networks}
          read={read}
          remove={(network) => setPending({ kind: "remove-network", id: network.id, name: network.name })}
        />
      )}
      {view === "volumes" && (
        <VolumeTable
          volumes={lists?.volumes}
          read={read}
          remove={(volume) =>
            setPending({ kind: "remove-volume", id: volume.name, name: volume.name })
          }
        />
      )}

      {view === "events" && <Events />}

      {pending && (
        <TargetConfirmation
          host={host}
          label={removalLabel(t, pending)}
          description={removalDescription(t, pending)}
          busy={request.isPending}
          onConfirm={confirm}
          onCancel={() => setPending(null)}
        />
      )}

      {message && <p className="source" style={{ marginTop: 12 }}>{message}</p>}

      {full.data && (
        <p className="source" style={{ marginTop: 16 }}>
          {t("Full state read from the host")} <Time value={full.data.observed_at} />
          {lists?.summary?.unavailable_reason && ` · ${lists.summary.unavailable_reason}`}
        </p>
      )}
    </>
  );
}

/**
 * The engine's event log.
 *
 * The read is an order with a closed window, not a live preview: a job that
 * reads events until cancelled would stay on the host forever. That is why
 * the window, the follow time and the limit are form fields - the operator
 * asks about a specific range around one failure.
 *
 * The events are an answer from one moment, so they stay in the job result
 * and do not enter the inventory: the host state says how it is now, and the
 * log - what happened along the way, including to a container that no
 * longer exists.
 */
function Events() {
  const t = useT();
  const host = useHost();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");
  const [window, setWindow] = useState(3600);
  const [follow, setFollow] = useState(0);
  const [kinds, setKinds] = useState<string[]>([]);

  const request = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.events",
        payload: {
          docker_events: {
            since_seconds: window,
            follow_seconds: follow,
            types: kinds,
            max_events: 200,
          },
        },
      }),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // The read lasts as long as the follow window, so the result arrives with
  // a delay. We poll the attempts until the job has a final status.
  const result = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () =>
      api.get<{ items: { status?: string; message?: string; detail?: EventsResult }[] }>(
        `/api/v1/jobs/${job}/attempts`,
      ),
    enabled: job !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return attempts?.[attempts.length - 1]?.status ? false : 2000;
    },
  });

  const attempts = result.data?.items ?? [];
  const last = attempts[attempts.length - 1];
  const reading = last?.detail;
  const list = reading?.events?.events ?? [];
  const busy = request.isPending || (job !== "" && !last?.status);

  function toggle(kind: string) {
    setKinds((current) =>
      current.includes(kind) ? current.filter((name) => name !== kind) : [...current, kind],
    );
  }

  return (
    <>
      <div className="form" style={{ marginBottom: 12 }}>
        <label>
          {t("Look back")}
          <select value={window} onChange={(e) => setWindow(Number(e.target.value))}>
            <option value={900}>{t("15 minutes")}</option>
            <option value={3600}>{t("1 hour")}</option>
            <option value={21600}>{t("6 hours")}</option>
            <option value={86400}>{t("24 hours")}</option>
          </select>
        </label>
        {/* Following has a hard limit: a job without an end would stay on
            the host forever, even when nobody looks at it any more. */}
        <label>
          {t("Then watch for")}
          <select value={follow} onChange={(e) => setFollow(Number(e.target.value))}>
            <option value={0}>{t("nothing, past only")}</option>
            <option value={15}>{t("15 seconds")}</option>
            <option value={30}>{t("30 seconds")}</option>
            <option value={60}>{t("60 seconds")}</option>
          </select>
        </label>
        <span className="operations">
          {["container", "image", "network", "volume"].map((kind) => (
            <button
              key={kind}
              type="button"
              className={kinds.includes(kind) ? "" : "secondary"}
              onClick={() => toggle(kind)}
            >
              {kind}
            </button>
          ))}
        </span>
        <button onClick={() => request.mutate()} disabled={busy || host.connection_state !== "online"}>
          {busy ? t("Reading…") : t("Read events")}
        </button>
      </div>
      <p className="subtitle">
        {t("The host reads a closed window and the task ends by itself. No filter selected means all four kinds.")}
      </p>

      {message && <p className="source">{message}</p>}
      {reading?.unavailable_reason && (
        <Empty>{t("The container engine did not answer: {reason}", { reason: reading.unavailable_reason })}</Empty>
      )}

      {job === "" ? (
        <Empty>{t("Events are read on request. Pick a window and read them.")}</Empty>
      ) : list.length === 0 && last?.status ? (
        <Empty>
          {t("Nothing happened in that window")}
          {reading?.events?.since && reading.events.until
            ? ` (${new Date(reading.events.since).toLocaleTimeString()} – ${new Date(reading.events.until).toLocaleTimeString()})`
            : ""}
          .
        </Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Time")}</th><th>{t("Kind")}</th><th>{t("Action")}</th><th>{t("Object")}</th><th>{t("Details")}</th></tr></thead>
          <tbody>
            {list.map((event, index) => (
              <tr key={`${event.time}-${index}`}>
                <td><Time value={event.time} /></td>
                <td>{event.type}</td>
                <td>{event.action}</td>
                <td>{event.actor_name || event.actor_id?.slice(0, 12) || "—"}</td>
                <td>
                  {Object.entries(event.attributes ?? {})
                    .filter(([key]) => key !== "name")
                    .map(([key, value]) => `${key}=${value}`)
                    .join(" ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* A cut-off list without this sentence would look complete, and the
          operator would draw conclusions from a log they did not see in
          full. */}
      {(reading?.truncated || reading?.events?.truncated) && (
        <p className="source">
          {t("Truncated: {reason}. Narrow the window or the kinds.", { reason: reading.truncated_reason || reading.events?.truncated_reason || "" })}
        </p>
      )}
    </>
  );
}

type Translate = (text: string, params?: Record<string, string | number>) => string;

function removalLabel(t: Translate, target: Pending): string {
  switch (target.kind) {
    case "remove-container":
      return t("Remove container");
    case "remove-image":
      return t("Remove image");
    case "remove-network":
      return t("Remove network");
    case "remove-volume":
      return t("Remove volume");
  }
}

function removalDescription(t: Translate, target: Pending): string {
  switch (target.kind) {
    case "remove-container":
      return t("Container {name} will be removed. Data outside volumes is lost.", { name: target.name });
    case "remove-image":
      return t("Image {name} will be removed from this host.", { name: target.name });
    case "remove-network":
      return t("Network {name} will be removed. Containers attached later will not find it.", { name: target.name });
    case "remove-volume":
      // A volume is what outlives the container - which is why removing it
      // is the only operation of this tab that really erases data.
      return t("Volume {name} will be removed with everything stored in it. This cannot be undone.", { name: target.name });
  }
}

/** An empty view says whether the host has nothing to show or nobody asked it. */
function EmptyList({ read, what }: { read: boolean; what: string }) {
  const t = useT();
  return (
    <Empty>
      {read
        ? t("No {what} were reported the last time this host was read.", { what })
        : t("This host has not been read yet. Use “Read from host”.")}
    </Empty>
  );
}

function ContainerTable({
  containers,
  read,
  operation,
  remove,
}: {
  containers?: Container[];
  read: boolean;
  operation: (action: string, container: Container) => void;
  remove: (container: Container) => void;
}) {
  const t = useT();
  if (!containers?.length) return <EmptyList read={read} what={t("containers")} />;
  return (
    <table>
      <thead>
        <tr>
          <th>{t("Name")}</th><th>{t("State")}</th><th>{t("Image")}</th><th>{t("Health")}</th>
          <th>{t("Restarts")}</th><th>{t("Ports")}</th><th>{t("Networks")}</th><th>Compose</th><th>{t("Actions")}</th>
        </tr>
      </thead>
      <tbody>
        {containers.map((container) => (
          <tr key={container.id}>
            <td>{container.name}</td>
            <td>
              <span className={container.state === "running" ? "badge ok" : "badge"}>
                {container.state}
              </span>
            </td>
            <td>{container.image}</td>
            {/* An image without a health check and an unhealthy image are
                two different things. */}
            <td>
              {!container.health ? (
                <span className="badge unknown">{t("no check")}</span>
              ) : container.health === "healthy" ? (
                <span className="badge ok">{t("healthy")}</span>
              ) : (
                <span className="badge error">{container.health}</span>
              )}
            </td>
            <td>{container.restart_count}</td>
            <td>
              {(container.ports ?? [])
                .map((port) =>
                  port.host_port
                    ? `${port.host_port}→${port.container_port}/${port.protocol}`
                    : `${port.container_port}/${port.protocol}`,
                )
                .join(", ") || "—"}
            </td>
            <td>
              {(container.networks ?? [])
                .map((network) => (network.ipv4 ? `${network.name} ${network.ipv4}` : network.name))
                .join(", ") || "—"}
            </td>
            <td>{container.compose ? `${container.compose.project}/${container.compose.service}` : "—"}</td>
            <td>
              <div className="operations">
                {container.state === "running" ? (
                  <>
                    <button onClick={() => operation("docker.container.restart", container)}>{t("Restart")}</button>
                    <button onClick={() => operation("docker.container.stop", container)}>{t("Stop")}</button>
                  </>
                ) : (
                  <button onClick={() => operation("docker.container.start", container)}>{t("Start")}</button>
                )}
                {/* Removal is irreversible, so it does not go straight from
                    the click - it opens the target confirmation. */}
                <button onClick={() => remove(container)}>{t("Remove")}</button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ImageTable({
  images,
  read,
  remove,
}: {
  images?: FullState["images"];
  read: boolean;
  remove: (image: NonNullable<FullState["images"]>[number]) => void;
}) {
  const t = useT();
  if (!images?.length) return <EmptyList read={read} what={t("images")} />;
  return (
    <table>
      <thead><tr><th>{t("Tags")}</th><th>{t("Size")}</th><th>{t("In use")}</th><th>{t("Actions")}</th></tr></thead>
      <tbody>
        {images.map((image) => (
          <tr key={image.id}>
            <td>{image.tags?.join(", ") || <span className="badge unknown">{t("untagged")}</span>}</td>
            <td>{bytes(image.size_bytes)}</td>
            <td>{image.in_use ? t("yes") : t("no")}</td>
            <td>
              {/* An image in use cannot be removed by mistake: the button is
                  simply not there. */}
              {image.in_use ? (
                "—"
              ) : (
                <button className="secondary" onClick={() => remove(image)}>{t("Remove")}</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * The host's networks.
 *
 * The container column is the most important one here: it answers whether
 * the network can be removed. A built-in engine network has no button at
 * all - the engine would refuse anyway, and a button that always ends in an
 * error is worse than its absence.
 */
function NetworkTable({
  networks,
  read,
  remove,
}: {
  networks?: Network[];
  read: boolean;
  remove: (network: Network) => void;
}) {
  const t = useT();
  if (!networks?.length) return <EmptyList read={read} what={t("networks")} />;
  return (
    <table>
      <thead>
        <tr>
          <th>{t("Name")}</th><th>{t("Driver")}</th><th>{t("Subnets")}</th><th>{t("Flags")}</th>
          <th>Compose</th><th>{t("Attached containers")}</th><th>{t("Actions")}</th>
        </tr>
      </thead>
      <tbody>
        {networks.map((network) => (
          <tr key={network.id}>
            <td>
              {network.name}
              {network.predefined && <span className="badge" style={{ marginLeft: 6 }}>{t("built-in")}</span>}
            </td>
            <td>{network.driver}{network.scope && network.scope !== "local" ? ` · ${network.scope}` : ""}</td>
            <td>
              {(network.subnets ?? []).length ? (
                <>
                  {network.subnets!.join(", ")}
                  {network.gateways?.length ? <div className="source">gw {network.gateways.join(", ")}</div> : null}
                </>
              ) : (
                "—"
              )}
            </td>
            <td>
              {[
                network.internal && "internal",
                network.attachable && "attachable",
                network.ipv6 && "ipv6",
              ]
                .filter(Boolean)
                .join(", ") || "—"}
            </td>
            <td>{network.compose || "—"}</td>
            <td>
              {network.containers?.length
                ? network.containers
                    .map((container) => (container.ipv4 ? `${container.name} ${container.ipv4}` : container.name))
                    .join(", ")
                : <span className="badge">{t("unused")}</span>}
            </td>
            <td>
              {network.predefined || network.in_use ? (
                "—"
              ) : (
                <button className="secondary" onClick={() => remove(network)}>{t("Remove")}</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * The host's volumes.
 *
 * The size is sometimes unknown and shown as such: zero would mean an empty
 * volume ready to be deleted, which is a completely different piece of
 * information. Usage includes stopped containers - the volume of a stopped
 * container is not nobody's.
 */
function VolumeTable({
  volumes,
  read,
  remove,
}: {
  volumes?: Volume[];
  read: boolean;
  remove: (volume: Volume) => void;
}) {
  const t = useT();
  if (!volumes?.length) return <EmptyList read={read} what={t("volumes")} />;
  return (
    <table>
      <thead>
        <tr>
          <th>{t("Name")}</th><th>{t("Driver")}</th><th>{t("Size")}</th><th>{t("Mountpoint")}</th>
          <th>Compose</th><th>{t("Used by")}</th><th>{t("Actions")}</th>
        </tr>
      </thead>
      <tbody>
        {volumes.map((volume) => (
          <tr key={volume.name}>
            <td>{volume.name}</td>
            <td>{volume.driver}</td>
            <td>
              {volume.size_bytes !== undefined ? (
                bytes(volume.size_bytes)
              ) : (
                <span className="badge unknown" title={volume.size_reason || undefined}>{t("unknown")}</span>
              )}
            </td>
            <td>{volume.mountpoint || "—"}</td>
            <td>{volume.compose || "—"}</td>
            <td>
              {volume.used_by?.length
                ? volume.used_by
                    .map(
                      (use) =>
                        `${use.container_name}:${use.destination}${use.read_only ? " ro" : ""}` +
                        (use.state && use.state !== "running" ? ` (${use.state})` : ""),
                    )
                    .join(", ")
                : <span className="badge">{t("unused")}</span>}
            </td>
            <td>
              {/* A volume in use has no button: removing it means losing
                  the data of the service that uses it right now. */}
              {volume.in_use ? (
                "—"
              ) : (
                <button className="secondary" onClick={() => remove(volume)}>{t("Remove")}</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
