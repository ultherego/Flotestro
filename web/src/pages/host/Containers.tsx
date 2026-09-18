import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown } from "../../components/widgets";
import {
  Check, Fact, Facts, Field, Fields, Foot, Form, FormActions, FormNote, JobNotice, Message, ModuleFreshness, ModuleHeader,
  ModulePage, Section, Summary as SummaryBar, Table, Widgets, useHost, useModule, useModuleRefresh, useReadOperation,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
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

/** The tail of one container's log, as the job result carries it. */
type LogsResult = {
  kind?: string;
  container_id?: string;
  container_name?: string;
  lines?: string[];
  truncated?: boolean;
  truncated_reason?: string;
  unavailable_reason?: string;
};

/** The bounds of a container log read; the host refuses anything beyond them. */
const LOG_LINES_MIN = 50;
const LOG_LINES_MAX = 5000;

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
/** The changes this page offers; when every one is refused, the page says so once. */
const CONTAINER_CHANGES = [
  "docker.container.start", "docker.container.stop", "docker.container.restart", "docker.container.remove",
  "docker.image.pull", "docker.prune",
];

export function Containers() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [view, setView] = useState<View>("containers");
  const [pending, setPending] = useState<Pending | null>(null);
  const [logsOf, setLogsOf] = useState<Container | null>(null);
  const [message, setMessage] = useState("");
  // The last job ordered from this page, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);
  const summary = useModule<Summary>(host.id, "containers");
  const full = useModule<FullState>(host.id, "containers.full");
  const unknown = <span className="badge unknown">{t("unknown")}</span>;
  // The state of the containers lands in the inventory when the read is over.
  const refetch = useModuleRefresh(host.id, ["containers", "containers.full"]);

  const refresh = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.read",
        payload: { docker_read: {} },
      }),
    onSuccess: (job) => {
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refetch(job);
    },
  });

  // Reversible operations go straight through; irreversible ones pass
  // through the confirmation dialog, which adds the reason and the hostname.
  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setOrdered(job);
      setMessage("");
      setPending(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refetch(job);
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
    <ModulePage>
      <ModuleHeader
        title={t("Containers")}
        description={t("Full lists are read from the host on request, not on every inventory cycle.")}
        actions={
          <ActionGuard action="docker.read" host={host.id} explain>
            <button
              onClick={() => refresh.mutate()}
              disabled={refresh.isPending || host.connection_state !== "online"}
            >
              {refresh.isPending ? t("Requesting…") : t("Read from host")}
            </button>
          </ActionGuard>
        }
      />
      <ModuleFreshness fragment={summary.data} />
      <ReadOnlyModuleNotice host={host.id} actions={CONTAINER_CHANGES} />
      <Message text={message} error />
      {ordered && <JobNotice job={ordered} hostID={host.id} />}

      <Widgets>
      {/* The containers by state. A container that keeps coming up is
          healthy at every single moment and broken nonetheless - without
          the restarting slot that is not visible at all. */}
      <SummaryBar
        title={t("Containers")}
        description={t("Counted by the inventory cycle; the lists below come from a read.")}
        span={8}
        segments={[
          { label: t("running"), value: state?.running, tone: "ok" },
          { label: t("unhealthy"), value: state?.unhealthy, tone: "error" },
          { label: t("restarting"), value: state?.restart_looping, tone: "warn" },
          { label: t("paused"), value: state?.paused, tone: "unknown" },
          { label: t("stopped"), value: state?.stopped, tone: "neutral" },
        ]}
      />

      {/* The engine and what it holds. The unused counters say how much of
          this can be cleaned up - the only reason the objects are counted
          in the summary at all. */}
      <Section title={t("Engine")} span={4} flush>
        <Facts>
          <Fact label={t("Engine")}>{state?.engine_version || unknown}</Fact>
          <Fact label="API">{state?.api_version || "—"}</Fact>
        </Facts>
        <div className="hm-section-body">
          <p className="widget-subhead">{t("Objects")}</p>
          {state?.images !== undefined || state?.networks !== undefined || state?.volumes !== undefined ? (
            <Breakdown
              items={[
                { label: t("Images"), value: state?.images ?? 0, tone: "info" },
                { label: t("Networks"), value: state?.networks ?? 0, tone: "info" },
                { label: t("unused"), value: state?.networks_unused ?? 0, tone: "warn" },
                { label: t("Volumes"), value: state?.volumes ?? 0, tone: "info" },
                { label: t("unused"), value: state?.volumes_unused ?? 0, tone: "warn" },
              ]}
            />
          ) : (
            <p className="source" style={{ margin: 0 }}>{t("Known after a read from the host.")}</p>
          )}
        </div>
      </Section>

      {state?.projects && state.projects.length > 0 && (
        <Section title={t("Compose projects")} count={state.projects.length} span={12} flush>
          <Table>
            <thead><tr><th>{t("Project")}</th><th>{t("Services")}</th><th className="hm-num">{t("Running")}</th></tr></thead>
            <tbody>
              {state.projects.map((project) => (
                <tr key={project.name}>
                  <td className="hm-mono hm-primary">{project.name}</td>
                  <td>{project.services.join(", ") || "—"}</td>
                  <td className="hm-num">{project.running} / {project.total}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      )}

      <Section title={t("Engine objects")} span={12} flush>
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
          <>
            <ContainerTable
              hostID={host.id}
              containers={lists?.containers}
              read={read}
              operation={containerOperation}
              logs={(container) => setLogsOf(logsOf?.id === container.id ? null : container)}
              remove={(container) =>
                setPending({ kind: "remove-container", id: container.id, name: container.name })
              }
            />
            {logsOf && <ContainerLogs key={logsOf.id} container={logsOf} onClose={() => setLogsOf(null)} />}
          </>
        )}
        {view === "images" && (
          <>
            <ImageTable
              hostID={host.id}
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
            <PullImage
              hostID={host.id}
              busy={request.isPending}
              onPull={(reference) => request.mutate({ action: "docker.image.pull", payload: { docker_image: { reference } } })}
            />
          </>
        )}
        {view === "networks" && (
          <NetworkTable
            hostID={host.id}
            networks={lists?.networks}
            read={read}
            remove={(network) => setPending({ kind: "remove-network", id: network.id, name: network.name })}
          />
        )}
        {view === "volumes" && (
          <VolumeTable
            hostID={host.id}
            volumes={lists?.volumes}
            read={read}
            remove={(volume) =>
              setPending({ kind: "remove-volume", id: volume.name, name: volume.name })
            }
          />
        )}

        {view === "events" && <Events />}

        {full.data && (
          <Foot>
            <span>
              {t("Full state read from the host")} <Time value={full.data.observed_at} />
              {lists?.summary?.unavailable_reason && ` · ${lists.summary.unavailable_reason}`}
            </span>
          </Foot>
        )}
      </Section>
      </Widgets>

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
    </ModulePage>
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
      <div className="hm-section-body">
        <Form>
          <Fields>
            <Field label={t("Look back")}>
              <select value={window} onChange={(e) => setWindow(Number(e.target.value))}>
                <option value={900}>{t("15 minutes")}</option>
                <option value={3600}>{t("1 hour")}</option>
                <option value={21600}>{t("6 hours")}</option>
                <option value={86400}>{t("24 hours")}</option>
              </select>
            </Field>
            {/* Following has a hard limit: a job without an end would stay on
                the host forever, even when nobody looks at it any more. */}
            <Field label={t("Then watch for")}>
              <select value={follow} onChange={(e) => setFollow(Number(e.target.value))}>
                <option value={0}>{t("nothing, past only")}</option>
                <option value={15}>{t("15 seconds")}</option>
                <option value={30}>{t("30 seconds")}</option>
                <option value={60}>{t("60 seconds")}</option>
              </select>
            </Field>
            {/* Not a label: a label around buttons would click the first
                one whenever the caption is clicked. */}
            <div className="hm-field">
              <span className="hm-field-label">{t("Kind")}</span>
              <span className="hm-choices">
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
            </div>
          </Fields>
          <FormActions>
            <ActionGuard action="docker.events" host={host.id} explain>
              <button onClick={() => request.mutate()} disabled={busy || host.connection_state !== "online"}>
                {busy ? t("Reading…") : t("Read events")}
              </button>
            </ActionGuard>
          </FormActions>
          <FormNote>
            {t("The host reads a closed window and the task ends by itself. No filter selected means all four kinds.")}
          </FormNote>
          <Message text={message} error />
        </Form>
      </div>

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
        <Table>
          <thead><tr><th>{t("Time")}</th><th>{t("Kind")}</th><th>{t("Action")}</th><th>{t("Object")}</th><th>{t("Details")}</th></tr></thead>
          <tbody>
            {list.map((event, index) => (
              <tr key={`${event.time}-${index}`}>
                <td><Time value={event.time} /></td>
                <td>{event.type}</td>
                <td className="hm-mono">{event.action}</td>
                <td className="hm-mono">{event.actor_name || event.actor_id?.slice(0, 12) || "—"}</td>
                <td className="source hm-mono">
                  {Object.entries(event.attributes ?? {})
                    .filter(([key]) => key !== "name")
                    .map(([key, value]) => `${key}=${value}`)
                    .join(" ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {/* A cut-off list without this sentence would look complete, and the
          operator would draw conclusions from a log they did not see in
          full. */}
      {(reading?.truncated || reading?.events?.truncated) && (
        <Foot>
          <span>{t("Truncated: {reason}. Narrow the window or the kinds.", { reason: reading.truncated_reason || reading.events?.truncated_reason || "" })}</span>
        </Foot>
      )}
    </>
  );
}

/**
 * The tail of one container's log.
 *
 * A read bounded by a line count and by the same byte limit as a log file:
 * a container that writes in a loop must not hand the panel its whole
 * history. The lines come back in the job result and stay there - the log
 * is what the application said at one moment, not the state of the host.
 * Stderr lines are marked in place, so the order of what the container
 * wrote is kept.
 */
function ContainerLogs({ container, onClose }: { container: Container; onClose: () => void }) {
  const t = useT();
  const host = useHost();
  const [lines, setLines] = useState(200);
  const [since, setSince] = useState("");
  const [timestamps, setTimestamps] = useState(false);
  const read = useReadOperation<LogsResult>(host);

  const result = read.attempt?.detail;
  const output = result?.lines ?? [];
  const refused = read.attempt && read.attempt.status !== "succeeded";
  const bounded = Math.min(LOG_LINES_MAX, Math.max(LOG_LINES_MIN, Math.trunc(lines) || LOG_LINES_MIN));

  return (
    <Section
      title={t("Log of {name}", { name: container.name })}
      count={read.attempt ? output.length : undefined}
      tools={<button className="secondary" onClick={onClose}>{t("Close")}</button>}
      flush
    >
      <div className="hm-section-body">
        <Form>
          <Fields>
            <Field label={t("Lines from the end")} help={t("Between {min} and {max}; the read is also cut at 1 MiB.", { min: LOG_LINES_MIN, max: LOG_LINES_MAX })} narrow>
              <input
                type="number"
                min={LOG_LINES_MIN}
                max={LOG_LINES_MAX}
                value={lines}
                onChange={(e) => setLines(Number(e.target.value))}
              />
            </Field>
            <Field label={t("Since")} help={t("A duration such as 15m, 2h or 1d, or an RFC 3339 timestamp. Empty reads the whole tail.")}>
              <input value={since} placeholder="15m" onChange={(e) => setSince(e.target.value)} />
            </Field>
            <div className="hm-field">
              <span className="hm-field-label">{t("Timestamps")}</span>
              <Check checked={timestamps} onChange={setTimestamps}>{t("Prefix every line with the engine's timestamp")}</Check>
            </div>
          </Fields>
          <FormActions>
            <ActionGuard action="docker.container.logs" host={host.id} explain>
              <button
                onClick={() =>
                  read.order({
                    action: "docker.container.logs",
                    payload: {
                      docker_logs: {
                        container_id: container.id,
                        lines: bounded,
                        since: since.trim(),
                        timestamps,
                      },
                    },
                  })
                }
                disabled={read.busy || host.connection_state !== "online"}
              >
                {read.busy ? t("Reading…") : t("Read log")}
              </button>
            </ActionGuard>
          </FormActions>
          <Message text={read.message} error />
        </Form>
      </div>

      {refused && (
        <Message text={read.attempt?.message || read.attempt?.error_code || t("The host refused the read.")} error />
      )}
      {result?.unavailable_reason && (
        <Empty>{t("The container engine did not answer: {reason}", { reason: result.unavailable_reason })}</Empty>
      )}

      {!read.ordered ? (
        <Empty>{t("The log is read on request. Pick the bounds and read it.")}</Empty>
      ) : read.attempt && !refused && !result?.unavailable_reason ? (
        output.length === 0 ? (
          <Empty>{t("The container wrote nothing in that range.")}</Empty>
        ) : (
          <div className="hm-section-body">
            <pre className="hm-log">{output.join("\n")}</pre>
          </div>
        )
      ) : null}

      {/* A cut-off log without this sentence would look complete. */}
      {result?.truncated && (
        <Foot>
          <span>{t("Truncated: {reason}. Narrow the window or the line count.", { reason: result.truncated_reason || "" })}</span>
        </Foot>
      )}
    </Section>
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
  hostID,
  containers,
  read,
  operation,
  logs,
  remove,
}: {
  hostID: string;
  containers?: Container[];
  read: boolean;
  operation: (action: string, container: Container) => void;
  logs: (container: Container) => void;
  remove: (container: Container) => void;
}) {
  const t = useT();
  if (!containers?.length) return <EmptyList read={read} what={t("containers")} />;
  return (
    <Table>
      <thead>
        <tr>
          <th>{t("Name")}</th><th>{t("State")}</th><th>{t("Image")}</th><th>{t("Health")}</th>
          <th className="hm-num">{t("Restarts")}</th><th>{t("Ports")}</th><th>{t("Networks")}</th><th>Compose</th><th>{t("Actions")}</th>
        </tr>
      </thead>
      <tbody>
        {containers.map((container) => (
          <tr key={container.id}>
            <td className="hm-mono hm-primary">{container.name}</td>
            <td>
              <span className={container.state === "running" ? "badge ok" : "badge"}>
                {container.state}
              </span>
            </td>
            <td className="hm-mono">{container.image}</td>
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
            <td className="hm-num">{container.restart_count}</td>
            <td className="hm-mono">
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
              {/* Every button stands behind the server's preview of what
                  this operator may order on this host: a viewer sees none
                  of them, and a refused order is not the way to learn about
                  a missing permission. */}
              <div className="operations">
                {container.state === "running" ? (
                  <>
                    <ActionGuard action="docker.container.restart" host={hostID}>
                      <button onClick={() => operation("docker.container.restart", container)}>{t("Restart")}</button>
                    </ActionGuard>
                    <ActionGuard action="docker.container.stop" host={hostID}>
                      <button onClick={() => operation("docker.container.stop", container)}>{t("Stop")}</button>
                    </ActionGuard>
                  </>
                ) : (
                  <ActionGuard action="docker.container.start" host={hostID}>
                    <button onClick={() => operation("docker.container.start", container)}>{t("Start")}</button>
                  </ActionGuard>
                )}
                {/* The log of a stopped container is still there: reading
                    it is often the reason the container is looked at. */}
                <ActionGuard action="docker.container.logs" host={hostID}>
                  <button className="secondary" onClick={() => logs(container)}>{t("Logs")}</button>
                </ActionGuard>
                {/* Removal is irreversible, so it does not go straight from
                    the click - it opens the target confirmation. */}
                <ActionGuard action="docker.container.remove" host={hostID}>
                  <button className="hm-danger" onClick={() => remove(container)}>{t("Remove")}</button>
                </ActionGuard>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function ImageTable({
  hostID,
  images,
  read,
  remove,
}: {
  hostID: string;
  images?: FullState["images"];
  read: boolean;
  remove: (image: NonNullable<FullState["images"]>[number]) => void;
}) {
  const t = useT();
  if (!images?.length) return <EmptyList read={read} what={t("images")} />;
  return (
    <Table>
      <thead><tr><th>{t("Tags")}</th><th className="hm-num">{t("Size")}</th><th>{t("In use")}</th><th>{t("Actions")}</th></tr></thead>
      <tbody>
        {images.map((image) => (
          <tr key={image.id}>
            <td className="hm-mono">{image.tags?.join(", ") || <span className="badge unknown">{t("untagged")}</span>}</td>
            <td className="hm-num">{bytes(image.size_bytes)}</td>
            <td>{image.in_use ? t("yes") : t("no")}</td>
            <td>
              {/* An image in use cannot be removed by mistake: the button is
                  simply not there. */}
              {image.in_use ? (
                "—"
              ) : (
                <ActionGuard action="docker.prune" host={hostID}>
                  <button className="hm-danger" onClick={() => remove(image)}>{t("Remove")}</button>
                </ActionGuard>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/** An image reference as the API takes it: a name with an optional registry, tag or digest, no spaces. */
const IMAGE_REFERENCE_PATTERN = /^[a-z0-9][A-Za-z0-9._\-/:@]{0,511}$/;

/**
 * Pulling an image ahead of a deploy: the download happens when somebody
 * is watching rather than in the middle of a compose apply. The pull is
 * a mutation and waits for approval like every other; it adds to the host
 * and removes nothing, so it needs no typed confirmation.
 */
function PullImage({ hostID, busy, onPull }: { hostID: string; busy: boolean; onPull: (reference: string) => void }) {
  const t = useT();
  const [reference, setReference] = useState("");
  const value = reference.trim();
  const valid = IMAGE_REFERENCE_PATTERN.test(value);
  // The whole form exists for one order; without the right to place it
  // the form is not drawn at all.
  return (
    <ActionGuard action="docker.image.pull" host={hostID}>
      <div className="hm-section-body">
        <Form>
          <Fields>
            <Field label={t("Pull an image")} help={t("The full reference, e.g. nginx:1.27 or registry.example.internal/team/app@sha256:…; the engine pulls it with its own credentials.")} wide>
              <input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="nginx:1.27" />
            </Field>
          </Fields>
          <FormActions>
            <button className="secondary" disabled={!valid || busy} onClick={() => onPull(value)}>
              {t("Pull image")}
            </button>
          </FormActions>
        </Form>
      </div>
    </ActionGuard>
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
  hostID,
  networks,
  read,
  remove,
}: {
  hostID: string;
  networks?: Network[];
  read: boolean;
  remove: (network: Network) => void;
}) {
  const t = useT();
  if (!networks?.length) return <EmptyList read={read} what={t("networks")} />;
  return (
    <Table>
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
              <span className="hm-mono hm-primary">{network.name}</span>
              {network.predefined && <span className="badge" style={{ marginLeft: 6 }}>{t("built-in")}</span>}
            </td>
            <td>{network.driver}{network.scope && network.scope !== "local" ? ` · ${network.scope}` : ""}</td>
            <td className="hm-mono">
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
                <ActionGuard action="docker.prune" host={hostID}>
                  <button className="hm-danger" onClick={() => remove(network)}>{t("Remove")}</button>
                </ActionGuard>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
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
  hostID,
  volumes,
  read,
  remove,
}: {
  hostID: string;
  volumes?: Volume[];
  read: boolean;
  remove: (volume: Volume) => void;
}) {
  const t = useT();
  if (!volumes?.length) return <EmptyList read={read} what={t("volumes")} />;
  return (
    <Table>
      <thead>
        <tr>
          <th>{t("Name")}</th><th>{t("Driver")}</th><th className="hm-num">{t("Size")}</th><th>{t("Mountpoint")}</th>
          <th>Compose</th><th>{t("Used by")}</th><th>{t("Actions")}</th>
        </tr>
      </thead>
      <tbody>
        {volumes.map((volume) => (
          <tr key={volume.name}>
            <td className="hm-mono hm-primary">{volume.name}</td>
            <td>{volume.driver}</td>
            <td className="hm-num">
              {volume.size_bytes !== undefined ? (
                bytes(volume.size_bytes)
              ) : (
                <span className="badge unknown" title={volume.size_reason || undefined}>{t("unknown")}</span>
              )}
            </td>
            <td className="hm-mono">{volume.mountpoint || "—"}</td>
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
                <ActionGuard action="docker.prune" host={hostID}>
                  <button className="hm-danger" onClick={() => remove(volume)}>{t("Remove")}</button>
                </ActionGuard>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
