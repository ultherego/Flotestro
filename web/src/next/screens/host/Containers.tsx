import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { needsReason, useAllowed, useModuleAccess } from "../../../lib/actions";
import { awaitJob } from "../../../lib/jobs";
import {
  body, count, flag, operationForm, payloadTextOf, readPayloadText, startingForm, text as textOf,
  type FieldSuggestions, type FieldValue, type FormProblem, type FormValue,
  type OperationEntry, type OperationField,
} from "../../../lib/operations";
import { bytes, relativeTime, absoluteTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Modal, Note,
  Pill, Problem, Readout, Row, Stack, Table, Tabs,
} from "../../kit";

/**
 * The host's containers.
 *
 * The summary comes with every inventory cycle and is cheap; the full
 * lists, the logs and the engine's events are read from the host when
 * somebody asks, because each of them costs the engine a walk over
 * everything it holds. Removing a volume is the one operation here that
 * really erases data, so it is confirmed by name with a reason first.
 */

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

type Image = { id: string; tags?: string[]; size_bytes: number; in_use: boolean };

type FullState = {
  summary?: Summary;
  containers?: Container[];
  images?: Image[];
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
export const LOG_LINES_MIN = 50;
export const LOG_LINES_MAX = 5000;

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

/** The changes this screen offers; when every one is refused, it says so once. */
export const CONTAINER_CHANGES = [
  "docker.container.start", "docker.container.stop", "docker.container.restart", "docker.container.remove",
  "docker.image.pull", "docker.prune",
  "docker.container.ensure", "docker.network.ensure", "docker.network.remove",
  "docker.volume.ensure", "docker.volume.remove",
];

/** The declarative operations offered per kind of object. */
export const DECLARATION_ACTIONS: Record<string, string[]> = {
  container: ["docker.container.ensure"],
  network: ["docker.network.ensure", "docker.network.remove"],
  volume: ["docker.volume.ensure", "docker.volume.remove"],
};

/** One difference the plan found between the host and the description. */
type PlanChange = { field: string; current: string; desired: string };

/** The plan as the host computes it; the change carries its digest back. */
type ComputedPlan = {
  kind?: string;
  name?: string;
  action?: string;
  exists?: boolean;
  changes?: PlanChange[];
  warnings?: string[];
  image_digest?: string;
  digest_source?: string;
  pinned_image?: string;
  digest?: string;
  current_id?: string;
  detaches?: string[];
  unavailable_reason?: string;
};

type DeclarationResult = { kind?: string; payload?: ComputedPlan; unavailable_reason?: string };

/** The verdict of a plan, as a sentence rather than a word. */
export function planVerdict(action: string | undefined): string {
  return PLAN_VERDICTS[action ?? ""] ?? "What the plan would do";
}

const PLAN_VERDICTS: Record<string, string> = {
  no_change: "The host already matches the description; nothing would change.",
  create: "The object is not on the host and would be created.",
  replace: "The object is on the host and differs, so it would be removed and created again.",
  start: "The container matches the description and is not running; it would be started.",
  stop: "The container matches the description and runs; it would be stopped.",
  remove: "The object is on the host and would be removed.",
  absent: "The object is not on the host, so a removal has nothing to do.",
};

/** A payload typed by hand, or null when it is not one. */
export function safePayload(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** What the engine on this host really carries, for the fields of a declaration. */
export function engineSuggestions(lists?: FullState): FieldSuggestions {
  if (!lists) return {};
  const named = (values: (string | undefined)[]) =>
    Array.from(new Set(values.filter((value): value is string => !!value))).sort();
  return {
    name: named([
      ...(lists.containers ?? []).map((one) => one.name),
      ...(lists.networks ?? []).map((one) => one.name),
      ...(lists.volumes ?? []).map((one) => one.name),
    ]),
    image: named((lists.images ?? []).flatMap((one) => one.tags ?? [])),
    network: named((lists.networks ?? []).map((one) => one.name)),
  };
}

/** The shortest reason the API takes for a change of this weight. */
export const MIN_REASON_LENGTH = 8;

/** An image reference as the API takes it: no spaces, an optional registry, tag or digest. */
export const IMAGE_REFERENCE_PATTERN = /^[a-z0-9][A-Za-z0-9._\-/:@]{0,511}$/;

/** A control that is drawn only where the order it places would be taken. */
function Allowed({ host, action, children }: { host: string; action: string; children: ReactNode }) {
  const verdict = useAllowed(host, action);
  return verdict.allowed ? <>{children}</> : null;
}

/** One attempt of a job as a result view reads it. */
type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/**
 * A read ordered through a job. The order goes out, the screen polls the
 * attempts until the host answers, and the last attempt is the result.
 */
function useReadOperation<T>(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");

  const order = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, payload),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<T>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items?.[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  return {
    order: order.mutate,
    ordered: job !== "",
    busy: order.isPending || (job !== "" && !last?.status),
    message,
    attempt: last?.status ? last : undefined,
    reset: () => { setJob(""); setMessage(""); },
  };
}

/**
 * A read whose answer lands in the inventory is settled when the job is
 * over, not when it is queued: the order answers at once and the host
 * later, so the module is read again only after the host has spoken.
 */
function useModuleRefresh(hostID: string, modules: string[]) {
  const queryClient = useQueryClient();
  return (job: Job) => {
    void awaitJob(api, job.id).then(() => {
      void queryClient.invalidateQueries({ queryKey: ["jobs", hostID] });
      for (const module of modules) {
        void queryClient.invalidateQueries({ queryKey: ["inventory", hostID, module] });
      }
      // The API answering with an error is not the screen's to report
      // here: the job list shows the job, and the refetch comes on its own.
    }, () => undefined);
  };
}

/** The answer to an order, with the job linked. */
function JobNotice({ job, hostID }: { job: Job; hostID: string }) {
  const t = useT();
  const sentence = job.requires_approval
    ? t("Job {id} is waiting for approval.")
    : t("Job {id} has been queued.");
  const [before, after = ""] = sentence.split("{id}");
  return (
    <Note>
      <span data-testid="job-notice">
        {before}
        <Link to={`/jobs/${job.id}`} className="fl-mono">{job.id.slice(0, 8)}</Link>
        {after}
        {" "}
        <Link to={`/hosts/${hostID}/jobs`}>{t("See all jobs")}</Link>
      </span>
    </Note>
  );
}

/* -------------------------------------------------------- the screen */

export function Containers({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const access = useModuleAccess(host.id, CONTAINER_CHANGES);
  const mayRead = useAllowed(host.id, "docker.read");

  const [view, setView] = useState<View>("containers");
  const [pending, setPending] = useState<Pending | null>(null);
  const [logsOf, setLogsOf] = useState<Container | null>(null);
  const [message, setMessage] = useState("");
  // The last job ordered from this screen, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);

  const summary = useQuery({
    queryKey: ["inventory", host.id, "containers"],
    queryFn: () => api.get<InventoryFragment<Summary>>(`/api/v1/hosts/${host.id}/inventory/containers`),
    retry: false,
  });
  const full = useQuery({
    queryKey: ["inventory", host.id, "containers.full"],
    queryFn: () => api.get<InventoryFragment<FullState>>(`/api/v1/hosts/${host.id}/inventory/containers.full`),
    retry: false,
  });
  // The state of the containers lands in the inventory when the read is over.
  const refetch = useModuleRefresh(host.id, ["containers", "containers.full"]);

  const refresh = useMutation({
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
      action: "docker.read",
      payload: { docker_read: {} },
    }),
    onSuccess: (job) => {
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refetch(job);
    },
  });

  // Reversible operations go straight through; irreversible ones pass
  // through the confirmation, which adds the reason and the hostname.
  const request = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, payload),
    onSuccess: (job) => {
      setOrdered(job);
      setMessage("");
      setPending(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refetch(job);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  function containerOperation(action: string, container: Container) {
    request.mutate({
      action,
      payload: {
        docker_container: { container_id: container.id, name: container.name, timeout_seconds: 10 },
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
        payload: { docker_container: { container_id: pending.id, name: pending.name } },
      });
      return;
    }
    // Pruning removes exactly what the operator saw: the list is explicit,
    // not a filter that would also match an object created since.
    const prune = pending.kind === "remove-image"
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

  if (summary.isLoading) return <Bones rows={5} />;

  const state = summary.data?.payload;
  const lists = full.data?.payload;
  const read = full.data !== undefined;
  const objects = state?.images !== undefined || state?.networks !== undefined || state?.volumes !== undefined;

  const notices: ReactNode[] = [];
  if (state?.unavailable_reason) {
    notices.push(
      <Banner key="unread" tone="error">
        {t("The container engine did not answer: {reason}", { reason: state.unavailable_reason })}
      </Banner>,
    );
  }
  if (access.known && !access.anyAllowed) {
    notices.push(
      <Banner key="access" tone="info">
        {access.permissions.length > 0 && access.reasons.length === 0
          ? t("You can read this module; changing it needs the permission {permissions}.", { permissions: access.permissions.join(", ") })
          : t("You can read this module; changing it is not possible here: {reasons}", {
              reasons: [
                ...access.reasons,
                ...access.permissions.map((one) => t("missing permission {permission}", { permission: one })),
              ].join("; "),
            })}
      </Banner>,
    );
  }
  if (message) notices.push(<Problem key="message">{message}</Problem>);
  if (ordered) notices.push(<JobNotice key="ordered" job={ordered} hostID={host.id} />);

  return (
    <>
      {pending && (
        <Confirm
          host={host}
          title={removalLabel(t, pending)}
          what={removalDescription(t, pending)}
          busy={request.isPending}
          danger
          onConfirm={confirm}
          onCancel={() => setPending(null)}
        />
      )}
      <Board screen={CONTAINERS_SCREEN} catalogue={CONTAINERS_BOARD} notices={notices.length > 0 ? <Stack>{notices}</Stack> : undefined} drawn={{
        running: (
          <Kpi
            hero
            icon="containers"
            label={t("Running")}
            value={state?.running ?? null}
            note={state?.containers === undefined ? undefined : t("of {n} on the engine", { n: state.containers })}
          />
        ),
        unhealthy: (
          <Kpi icon="containers" label={t("Unhealthy")} value={state?.unhealthy ?? null} tone="error" />
        ),
        restarting: (
          // A container that keeps coming up is healthy at every single
          // moment and broken nonetheless.
          <Kpi icon="containers" label={t("Restarting")} value={state?.restart_looping ?? null} tone="warn" />
        ),
        engineversion: (
          <Kpi
            icon="settings"
            label={t("Engine")}
            value={state?.engine_version ?? null}
            note={state?.api_version ? t("API {version}", { version: state.api_version }) : undefined}
          />
        ),
        states: (
          <Card
            title={t("Containers")}
            note={t("Counted by the inventory cycle; the lists below come from a read.")}
            tools={
              mayRead.allowed ? (
                <Button
                  kind="quiet"
                  testId="read-from-host"
                  onClick={() => refresh.mutate()}
                  disabled={refresh.isPending || host.connection_state !== "online"}
                >
                  {refresh.isPending ? t("Requesting…") : t("Read from host")}
                </Button>
              ) : mayRead.known ? (
                <Note>{mayRead.reason || t("This action is not available.")}</Note>
              ) : undefined
            }
          >
            <Bars items={[
              { label: t("running"), value: state?.running ?? 0, tone: state?.running === undefined ? "unknown" : "ok" },
              { label: t("unhealthy"), value: state?.unhealthy ?? 0, tone: state?.unhealthy === undefined ? "unknown" : "error" },
              { label: t("restarting"), value: state?.restart_looping ?? 0, tone: state?.restart_looping === undefined ? "unknown" : "warn" },
              { label: t("paused"), value: state?.paused ?? 0, tone: "unknown" },
              { label: t("stopped"), value: state?.stopped ?? 0, tone: state?.stopped === undefined ? "unknown" : "neutral" },
            ]} />
            {state === undefined && <Note>{t("This host has not reported its containers yet.")}</Note>}
          </Card>
        ),
        engine: (
          <Card title={t("Engine")}>
            <Facts>
              <Fact label={t("Engine")}>
                {state?.engine_version || <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label="API">{state?.api_version || <span className="fl-faint">—</span>}</Fact>
              {/* The unused counters say how much of this can be cleaned
                  up - the only reason the objects are counted at all. */}
              <Fact label={t("Objects")}>
                {objects ? (
                  <Bars items={[
                    { label: t("Images"), value: state?.images ?? 0, tone: "info" },
                    { label: t("Networks"), value: state?.networks ?? 0, tone: "info" },
                    { label: t("networks unused"), value: state?.networks_unused ?? 0, tone: "warn" },
                    { label: t("Volumes"), value: state?.volumes ?? 0, tone: "info" },
                    { label: t("volumes unused"), value: state?.volumes_unused ?? 0, tone: "warn" },
                  ]} />
                ) : <Note>{t("Known after a read from the host.")}</Note>}
              </Fact>
            </Facts>
          </Card>
        ),
        projects: state?.projects && state.projects.length > 0 ? (
          <Card title={t("Compose projects")} flush>
            <Table
              testId="projects"
              rows={state.projects}
              keyOf={(one) => one.name}
              rowTestId={(one) => `project-${one.name}`}
              columns={[
                { key: "name", head: t("Project"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
                { key: "services", head: t("Services"), cell: (one) => one.services.join(", ") || "—" },
                { key: "running", head: t("Running"), num: true, cell: (one) => `${one.running} / ${one.total}` },
              ]}
            />
          </Card>
        ) : undefined,
        objects: (
          <Card
            title={t("Engine objects")}
            foot={full.data
              ? (
                <>
                  {t("Full state read from the host")}{" "}
                  <span title={absoluteTime(full.data.observed_at)}>{relativeTime(full.data.observed_at)}</span>
                  {lists?.summary?.unavailable_reason ? ` · ${lists.summary.unavailable_reason}` : ""}
                </>
              )
              : undefined}
            flush
          >
            <Tabs
              value={view}
              onChange={setView}
              tabs={[
                { value: "containers", label: t("Containers"), count: lists?.containers?.length },
                { value: "images", label: t("Images"), count: lists?.images?.length },
                { value: "networks", label: t("Networks"), count: lists?.networks?.length },
                { value: "volumes", label: t("Volumes"), count: lists?.volumes?.length },
                { value: "events", label: t("Events") },
              ]}
            />

            {view === "containers" && (
              <ContainerTable
                hostID={host.id}
                containers={lists?.containers}
                read={read}
                operation={containerOperation}
                logs={(container) => setLogsOf(logsOf?.id === container.id ? null : container)}
                remove={(container) => setPending({ kind: "remove-container", id: container.id, name: container.name })}
              />
            )}
            {view === "images" && (
              <ImageTable
                hostID={host.id}
                images={lists?.images}
                read={read}
                remove={(image) => setPending({
                  kind: "remove-image",
                  id: image.id,
                  name: image.tags?.[0] || image.id.slice(7, 19),
                })}
              />
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
                remove={(volume) => setPending({ kind: "remove-volume", id: volume.name, name: volume.name })}
              />
            )}
            {view === "events" && <Events host={host} />}
          </Card>
        ),
        logs: logsOf ? (
          <ContainerLogs key={logsOf.id} host={host} container={logsOf} onClose={() => setLogsOf(null)} />
        ) : undefined,
        pull: view === "images" ? (
          <PullImage
            hostID={host.id}
            images={lists?.images}
            busy={request.isPending}
            onPull={(reference) => request.mutate({ action: "docker.image.pull", payload: { docker_image: { reference } } })}
          />
        ) : undefined,
        declare: view === "containers" || view === "networks" || view === "volumes" ? (
          <Declaration
            key={view}
            host={host}
            kind={view === "containers" ? "container" : view === "networks" ? "network" : "volume"}
            lists={lists}
          />
        ) : undefined,
        source: (
          <Card title={t("Where this came from")}>
            <Facts>
              <Fact label={t("Source")}>{summary.data?.source ?? <span className="fl-faint">—</span>}</Fact>
              <Fact label={t("Revision")}>
                <span className="fl-mono">{summary.data?.revision.slice(0, 12) ?? "—"}</span>
              </Fact>
              <Fact label={t("Observed")}>
                {summary.data
                  ? <span title={absoluteTime(summary.data.observed_at)}>{relativeTime(summary.data.observed_at)}</span>
                  : <span className="fl-faint">—</span>}
              </Fact>
              {summary.data?.unavailable_reason && (
                <Fact label={t("Could not be read")}>{summary.data.unavailable_reason}</Fact>
              )}
            </Facts>
          </Card>
        ),
      }} />
    </>
  );
}

/* --------------------------------------------------------- the lists */

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

function ContainerTable({ hostID, containers, read, operation, logs, remove }: {
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
    <Table
      testId="containers"
      rows={containers}
      keyOf={(one) => one.id}
      rowTestId={(one) => `container-${one.name}`}
      columns={[
        { key: "name", head: t("Name"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
        { key: "state", head: t("State"), cell: (one) => (
          <Pill tone={one.state === "running" ? "ok" : "neutral"}>{one.state}</Pill>
        ) },
        { key: "image", head: t("Image"), tight: true, cell: (one) => <span className="fl-mono">{one.image}</span> },
        // An image without a health check and an unhealthy image are two
        // different things.
        { key: "health", head: t("Health"), cell: (one) => (
          !one.health
            ? <Pill tone="unknown">{t("no check")}</Pill>
            : one.health === "healthy"
              ? <Pill tone="ok">{t("healthy")}</Pill>
              : <Pill tone="error">{one.health}</Pill>
        ) },
        { key: "restarts", head: t("Restarts"), num: true, cell: (one) => one.restart_count },
        { key: "ports", head: t("Ports"), minor: true, cell: (one) => (
          <span className="fl-mono">
            {(one.ports ?? [])
              .map((port) => port.host_port
                ? `${port.host_port}→${port.container_port}/${port.protocol}`
                : `${port.container_port}/${port.protocol}`)
              .join(", ") || "—"}
          </span>
        ) },
        { key: "networks", head: t("Networks"), minor: true, cell: (one) => (
          (one.networks ?? [])
            .map((network) => (network.ipv4 ? `${network.name} ${network.ipv4}` : network.name))
            .join(", ") || "—"
        ) },
        { key: "compose", head: "Compose", minor: true, cell: (one) => (
          one.compose ? `${one.compose.project}/${one.compose.service}` : "—"
        ) },
        // Every button stands behind the server's preview of what this
        // operator may order on this host: a viewer sees none of them, and
        // a refused order is not the way to learn about a missing permission.
        { key: "act", head: t("Actions"), actions: true, cell: (one) => (
          <Row>
            {one.state === "running" ? (
              <>
                <Allowed host={hostID} action="docker.container.restart">
                  <Button testId={`restart-${one.name}`} onClick={() => operation("docker.container.restart", one)}>
                    {t("Restart")}
                  </Button>
                </Allowed>
                <Allowed host={hostID} action="docker.container.stop">
                  <Button testId={`stop-${one.name}`} onClick={() => operation("docker.container.stop", one)}>
                    {t("Stop")}
                  </Button>
                </Allowed>
              </>
            ) : (
              <Allowed host={hostID} action="docker.container.start">
                <Button testId={`start-${one.name}`} onClick={() => operation("docker.container.start", one)}>
                  {t("Start")}
                </Button>
              </Allowed>
            )}
            {/* The log of a stopped container is still there: reading it is
                often the reason the container is looked at. */}
            <Allowed host={hostID} action="docker.container.logs">
              <Button kind="quiet" testId={`logs-${one.name}`} onClick={() => logs(one)}>{t("Logs")}</Button>
            </Allowed>
            {/* Removal is irreversible, so it does not go straight from the
                click - it opens the confirmation. */}
            <Allowed host={hostID} action="docker.container.remove">
              <Button kind="danger" testId={`remove-${one.name}`} onClick={() => remove(one)}>{t("Remove")}</Button>
            </Allowed>
          </Row>
        ) },
      ]}
    />
  );
}

function ImageTable({ hostID, images, read, remove }: {
  hostID: string;
  images?: Image[];
  read: boolean;
  remove: (image: Image) => void;
}) {
  const t = useT();
  if (!images?.length) return <EmptyList read={read} what={t("images")} />;
  return (
    <Table
      testId="images"
      rows={images}
      keyOf={(one) => one.id}
      rowTestId={(one) => `image-${one.id}`}
      columns={[
        { key: "tags", head: t("Tags"), tight: true, cell: (one) => (
          one.tags?.length
            ? <span className="fl-mono">{one.tags.join(", ")}</span>
            : <Pill tone="unknown">{t("untagged")}</Pill>
        ) },
        { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
        { key: "used", head: t("In use"), cell: (one) => one.in_use ? t("yes") : t("no") },
        // An image in use cannot be removed by mistake: the button is
        // simply not there.
        { key: "act", head: t("Actions"), actions: true, cell: (one) => (
          one.in_use ? <span className="fl-faint">—</span> : (
            <Allowed host={hostID} action="docker.prune">
              <Button kind="danger" testId={`remove-image-${one.id}`} onClick={() => remove(one)}>{t("Remove")}</Button>
            </Allowed>
          )
        ) },
      ]}
    />
  );
}

/**
 * The host's networks. The container column is the most important one
 * here: it answers whether the network can be removed.
 */
function NetworkTable({ hostID, networks, read, remove }: {
  hostID: string;
  networks?: Network[];
  read: boolean;
  remove: (network: Network) => void;
}) {
  const t = useT();
  if (!networks?.length) return <EmptyList read={read} what={t("networks")} />;
  return (
    <Table
      testId="networks"
      rows={networks}
      keyOf={(one) => one.id}
      rowTestId={(one) => `network-${one.name}`}
      columns={[
        { key: "name", head: t("Name"), cell: (one) => (
          <Stack>
            <span className="fl-mono">{one.name}</span>
            {one.predefined && <Pill tone="neutral">{t("built-in")}</Pill>}
          </Stack>
        ) },
        { key: "driver", head: t("Driver"), cell: (one) => (
          `${one.driver}${one.scope && one.scope !== "local" ? ` · ${one.scope}` : ""}`
        ) },
        { key: "subnets", head: t("Subnets"), minor: true, cell: (one) => (
          (one.subnets ?? []).length ? (
            <Stack>
              <span className="fl-mono">{(one.subnets ?? []).join(", ")}</span>
              {one.gateways?.length && <span className="fl-faint">gw {one.gateways.join(", ")}</span>}
            </Stack>
          ) : <span className="fl-faint">—</span>
        ) },
        { key: "flags", head: t("Flags"), minor: true, cell: (one) => (
          [one.internal && "internal", one.attachable && "attachable", one.ipv6 && "ipv6"]
            .filter(Boolean).join(", ") || "—"
        ) },
        { key: "compose", head: "Compose", minor: true, cell: (one) => one.compose || "—" },
        { key: "attached", head: t("Attached containers"), cell: (one) => (
          one.containers?.length
            ? one.containers.map((c) => (c.ipv4 ? `${c.name} ${c.ipv4}` : c.name)).join(", ")
            : <Pill tone="neutral">{t("unused")}</Pill>
        ) },
        { key: "act", head: t("Actions"), actions: true, cell: (one) => (
          one.predefined || one.in_use ? <span className="fl-faint">—</span> : (
            <Allowed host={hostID} action="docker.prune">
              <Button kind="danger" testId={`remove-network-${one.name}`} onClick={() => remove(one)}>{t("Remove")}</Button>
            </Allowed>
          )
        ) },
      ]}
    />
  );
}

function VolumeTable({ hostID, volumes, read, remove }: {
  hostID: string;
  volumes?: Volume[];
  read: boolean;
  remove: (volume: Volume) => void;
}) {
  const t = useT();
  if (!volumes?.length) return <EmptyList read={read} what={t("volumes")} />;
  return (
    <Table
      testId="volumes"
      rows={volumes}
      keyOf={(one) => one.name}
      rowTestId={(one) => `volume-${one.name}`}
      columns={[
        { key: "name", head: t("Name"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
        { key: "driver", head: t("Driver"), cell: (one) => one.driver },
        // A size the host could not measure is unknown, never nought.
        { key: "size", head: t("Size"), num: true, cell: (one) => (
          one.size_bytes !== undefined
            ? bytes(one.size_bytes)
            : <Pill tone="unknown" title={one.size_reason || undefined}>{t("unknown")}</Pill>
        ) },
        { key: "mount", head: t("Mountpoint"), minor: true, tight: true, cell: (one) => (
          one.mountpoint ? <span className="fl-mono">{one.mountpoint}</span> : <span className="fl-faint">—</span>
        ) },
        { key: "compose", head: "Compose", minor: true, cell: (one) => one.compose || "—" },
        { key: "used", head: t("Used by"), cell: (one) => (
          one.used_by?.length
            ? one.used_by.map((use) =>
                `${use.container_name}:${use.destination}${use.read_only ? " ro" : ""}`
                + (use.state && use.state !== "running" ? ` (${use.state})` : "")).join(", ")
            : <Pill tone="neutral">{t("unused")}</Pill>
        ) },
        // A volume in use has no button: removing it means losing the data
        // of the service that uses it right now.
        { key: "act", head: t("Actions"), actions: true, cell: (one) => (
          one.in_use ? <span className="fl-faint">—</span> : (
            <Allowed host={hostID} action="docker.prune">
              <Button kind="danger" testId={`remove-volume-${one.name}`} onClick={() => remove(one)}>{t("Remove")}</Button>
            </Allowed>
          )
        ) },
      ]}
    />
  );
}

/* ------------------------------------------------------- pulling one */

/**
 * Pulling an image ahead of a deploy: the download happens when somebody
 * is watching rather than in the middle of a compose apply.
 */
function PullImage({ hostID, images, busy, onPull }: {
  hostID: string;
  images?: { id: string; tags?: string[] }[];
  busy: boolean;
  onPull: (reference: string) => void;
}) {
  const t = useT();
  const [reference, setReference] = useState("");
  const value = reference.trim();
  const valid = IMAGE_REFERENCE_PATTERN.test(value);
  // The references this host already carries: fetching one again is how a
  // moving tag is brought up to date.
  const held = [...new Set((images ?? []).flatMap((one) => one.tags ?? []).filter((tag) => tag !== "<none>:<none>"))].sort();

  // The whole form exists for one order; without the right to place it the
  // form is not drawn at all.
  return (
    <Allowed host={hostID} action="docker.image.pull">
      <Card title={t("Pull an image")}>
        <Stack>
          <Fields>
            <Field
              label={t("Pull an image")}
              hint={held.length
                ? t("The full reference, with its registry where it is not the default one. The images this host already carries are on the list; the engine pulls with its own credentials.")
                : t("The full reference, with its registry where it is not the default one, and a tag or a digest. The engine pulls it with its own credentials.")}
              wide
            >
              <input
                value={reference}
                onChange={(event) => setReference(event.target.value)}
                list="fl-pull-image"
                placeholder="registry.example.test/team/app:1.4"
                data-testid="pull-reference"
              />
              <datalist id="fl-pull-image">
                {held.map((tag) => <option key={tag} value={tag} />)}
              </datalist>
            </Field>
          </Fields>
          <Button kind="quiet" testId="pull-image" disabled={!valid || busy} onClick={() => onPull(value)}>
            {t("Pull image")}
          </Button>
        </Stack>
      </Card>
    </Allowed>
  );
}

/* ------------------------------------------------------- the logs */

/** The tail of one container's log. */
function ContainerLogs({ host, container, onClose }: {
  host: Host;
  container: Container;
  onClose: () => void;
}) {
  const t = useT();
  const [lines, setLines] = useState(200);
  const [since, setSince] = useState("");
  const [timestamps, setTimestamps] = useState(false);
  const read = useReadOperation<LogsResult>(host);
  const mayRead = useAllowed(host.id, "docker.container.logs");

  const result = read.attempt?.detail;
  const output = result?.lines ?? [];
  const refused = read.attempt && read.attempt.status !== "succeeded";
  const bounded = Math.min(LOG_LINES_MAX, Math.max(LOG_LINES_MIN, Math.trunc(lines) || LOG_LINES_MIN));

  return (
    <Card
      title={t("Log of {name}", { name: container.name })}
      tools={<Button kind="quiet" onClick={onClose}>{t("Close")}</Button>}
      foot={result?.truncated
        // A cut-off log without this sentence would look complete.
        ? t("Truncated: {reason}. Narrow the window or the line count.", { reason: result.truncated_reason || "" })
        : undefined}
    >
      <Stack>
        <Fields>
          <Field
            label={t("Lines from the end")}
            hint={t("Between {min} and {max}; the read is also cut at 1 MiB.", { min: LOG_LINES_MIN, max: LOG_LINES_MAX })}
          >
            <input
              type="number"
              min={LOG_LINES_MIN}
              max={LOG_LINES_MAX}
              value={lines}
              data-testid="log-lines"
              onChange={(event) => setLines(Number(event.target.value))}
            />
          </Field>
          <Field
            label={t("Since")}
            hint={t("A duration such as 15m, 2h or 1d, or an RFC 3339 timestamp. Empty reads the whole tail.")}
          >
            <input value={since} placeholder="15m" onChange={(event) => setSince(event.target.value)} data-testid="log-since" />
          </Field>
          <Field label={t("Timestamps")}>
            <Check checked={timestamps} onChange={setTimestamps}>
              {t("Prefix every line with the engine's timestamp")}
            </Check>
          </Field>
        </Fields>
        {mayRead.allowed ? (
          <Button
            testId="read-log"
            disabled={read.busy || host.connection_state !== "online"}
            onClick={() => read.order({
              action: "docker.container.logs",
              payload: {
                docker_logs: {
                  container_id: container.id,
                  lines: bounded,
                  since: since.trim(),
                  timestamps,
                },
              },
            })}
          >
            {read.busy ? t("Reading…") : t("Read log")}
          </Button>
        ) : mayRead.known ? (
          <Note>{mayRead.reason || t("This action is not available.")}</Note>
        ) : null}

        {read.message && <Problem>{read.message}</Problem>}
        {refused && (
          <Problem>{read.attempt?.message || read.attempt?.error_code || t("The host refused the read.")}</Problem>
        )}
        {result?.unavailable_reason && (
          <Empty>{t("The container engine did not answer: {reason}", { reason: result.unavailable_reason })}</Empty>
        )}

        {!read.ordered ? (
          <Empty>{t("The log is read on request. Pick the bounds and read it.")}</Empty>
        ) : read.busy ? (
          <Bones rows={6} />
        ) : read.attempt && !refused && !result?.unavailable_reason ? (
          output.length === 0
            ? <Empty>{t("The container wrote nothing in that range.")}</Empty>
            : <Readout value={output.join("\n")} lines={20} testId="log-output" />
        ) : null}
      </Stack>
    </Card>
  );
}

/* ------------------------------------------------------ the events */

/** The engine's event log, read over a closed window. */
function Events({ host }: { host: Host }) {
  const t = useT();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");
  const [window, setWindow] = useState(3600);
  const [follow, setFollow] = useState(0);
  const [kinds, setKinds] = useState<string[]>([]);
  const mayRead = useAllowed(host.id, "docker.events");

  const request = useMutation({
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
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
    onSuccess: (created) => { setMessage(""); setJob(created.id); },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // The read lasts as long as the follow window, so the result arrives with
  // a delay. We poll the attempts until the job has a final status.
  const result = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: { status?: string; message?: string; detail?: EventsResult }[] }>(
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

  const toggle = (kind: string) =>
    setKinds((current) => current.includes(kind) ? current.filter((one) => one !== kind) : [...current, kind]);

  return (
    <Stack>
      <Fields>
        <Field label={t("Look back")}>
          <select value={window} onChange={(event) => setWindow(Number(event.target.value))} data-testid="events-window">
            <option value={900}>{t("15 minutes")}</option>
            <option value={3600}>{t("1 hour")}</option>
            <option value={21600}>{t("6 hours")}</option>
            <option value={86400}>{t("24 hours")}</option>
          </select>
        </Field>
        {/* Following has a hard limit: a job without an end would stay on
            the host forever, even when nobody looks at it any more. */}
        <Field label={t("Then watch for")}>
          <select value={follow} onChange={(event) => setFollow(Number(event.target.value))} data-testid="events-follow">
            <option value={0}>{t("nothing, past only")}</option>
            <option value={15}>{t("15 seconds")}</option>
            <option value={30}>{t("30 seconds")}</option>
            <option value={60}>{t("60 seconds")}</option>
          </select>
        </Field>
        <Field label={t("Kind")}>
          {/* Not a label: a label around buttons would click the first one
              whenever the caption is clicked. */}
          <Row>
            {["container", "image", "network", "volume"].map((kind) => (
              <Button
                key={kind}
                kind={kinds.includes(kind) ? "do" : "quiet"}
                testId={`events-kind-${kind}`}
                onClick={() => toggle(kind)}
              >
                {kind}
              </Button>
            ))}
          </Row>
        </Field>
      </Fields>
      {mayRead.allowed ? (
        <Button
          testId="read-events"
          onClick={() => request.mutate()}
          disabled={busy || host.connection_state !== "online"}
        >
          {busy ? t("Reading…") : t("Read events")}
        </Button>
      ) : mayRead.known ? (
        <Note>{mayRead.reason || t("This action is not available.")}</Note>
      ) : null}
      <Note>
        {t("The host reads a closed window and the task ends by itself. No filter selected means all four kinds.")}
      </Note>
      {message && <Problem>{message}</Problem>}

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
        <Table
          testId="events"
          rows={list}
          keyOf={(one, index) => `${one.time}-${index}`}
          loading={busy}
          columns={[
            { key: "time", head: t("Time"), cell: (one) => (
              <span title={absoluteTime(one.time)}>{relativeTime(one.time)}</span>
            ) },
            { key: "type", head: t("Kind"), cell: (one) => one.type },
            { key: "action", head: t("Action"), tight: true, cell: (one) => <span className="fl-mono">{one.action}</span> },
            { key: "object", head: t("Object"), tight: true, cell: (one) => (
              <span className="fl-mono">{one.actor_name || one.actor_id?.slice(0, 12) || "—"}</span>
            ) },
            { key: "detail", head: t("Details"), minor: true, tight: true, cell: (one) => (
              <span className="fl-mono">
                {Object.entries(one.attributes ?? {})
                  .filter(([key]) => key !== "name")
                  .map(([key, value]) => `${key}=${value}`)
                  .join(" ") || "—"}
              </span>
            ) },
          ]}
        />
      )}

      {/* A cut-off list without this sentence would look complete, and the
          operator would draw conclusions from a log they did not see. */}
      {(reading?.truncated || reading?.events?.truncated) && (
        <Note>
          {t("Truncated: {reason}. Narrow the window or the kinds.", {
            reason: reading.truncated_reason || reading.events?.truncated_reason || "",
          })}
        </Note>
      )}
    </Stack>
  );
}

/* -------------------------------------------------- the declaration */

/**
 * Declaring a container, a network or a volume. Nothing is ordered from
 * this panel without a plan: the host computes the difference, the change
 * carries that plan's digest, and the host refuses it when it has moved.
 */
function Declaration({ host, kind, lists }: {
  host: Host;
  kind: "container" | "network" | "volume";
  /** What the engine on this host reports, so the fields can offer it. */
  lists?: FullState;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const choices = DECLARATION_ACTIONS[kind];
  const [action, setAction] = useState(choices[0]);
  const entry = operationForm(action);
  const [form, setForm] = useState<FormValue>(() => startingForm(choices[0]));
  const [payloadText, setPayloadText] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [ordered, setOrdered] = useState<Job | null>(null);
  const [message, setMessage] = useState("");
  // The description the plan on the screen was computed for.
  const [plannedFor, setPlannedFor] = useState("");
  const plan = useReadOperation<DeclarationResult>(host);
  // Read before any early return: a hook that sits after one changes the
  // order of hooks between renders, and React then reads the wrong state.
  const mayPlan = useAllowed(host.id, "docker.plan").allowed;

  // A form filled for one operation says nothing about another: the
  // description of a network is not the name of a volume.
  function choose(next: string) {
    setAction(next);
    setForm(startingForm(next));
    setPayloadText("");
    setOrdered(null);
    plan.reset();
  }

  const payload = payloadText !== ""
    ? safePayload(payloadText)
    : entry ? entry.toPayload(form) : null;
  const section = payload ? (payload.docker_ensure as Record<string, unknown> | undefined) : undefined;
  const problems = entry && payloadText === "" ? entry.validate(form) : [];
  const computed = plan.attempt?.detail?.payload;
  const stale = computed !== undefined && plannedFor !== JSON.stringify(section ?? null);

  const apply = useMutation({
    mutationFn: (sent: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, sent),
    onSuccess: (job) => {
      setOrdered(job);
      setMessage("");
      setConfirming(false);
      plan.reset();
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  function order(reason?: string, confirmation?: string) {
    if (!section || !computed) return;
    apply.mutate({
      action,
      ...(reason ? { reason } : {}),
      ...(confirmation ? { target_confirmation: confirmation } : {}),
      payload: { docker_ensure: { ...section, plan_digest: computed.digest } },
    });
  }

  if (!entry) return null;
  const destructive = action.endsWith(".remove");
  const target = entry.summary(payload ?? {}) || t("this object");

  return (
    <Card title={t("Declare what this host is to carry")}>
      <Stack>
        {choices.length > 1 && (
          <Fields>
            <Field label={t("What to declare")}>
              <select value={action} onChange={(event) => choose(event.target.value)} data-testid="declare-action">
                {choices.map((one) => (
                  <option key={one} value={one}>{t(operationForm(one)?.title ?? one)}</option>
                ))}
              </select>
            </Field>
          </Fields>
        )}
        {/* The fields come from the operation registry, so this card and the
            Bulk wizard ask for the same things in the same words. */}
        <RegistryFields
          key={action}
          entry={entry}
          value={form}
          onChange={(next) => { setForm(next); setOrdered(null); }}
          json={payloadText}
          onJson={(next) => { setPayloadText(next); setOrdered(null); }}
          suggestions={engineSuggestions(lists)}
        />
        <Row>
          {/* The plan is a read and stands behind the read permission; the
              change behind its own. An operator who may look but not change
              sees the plan and no button to carry it out. */}
          {mayPlan && (
            <Button
              kind="quiet"
              testId="compute-plan"
              disabled={!section || problems.length > 0 || plan.busy}
              onClick={() => {
                setOrdered(null);
                setPlannedFor(JSON.stringify(section ?? null));
                plan.order({ action: "docker.plan", payload: { docker_ensure: section } });
              }}
            >
              {plan.busy ? t("Requesting…") : t("Compute the plan")}
            </Button>
          )}
          <Allowed host={host.id} action={action}>
            <Button
              kind={destructive ? "danger" : "do"}
              testId="carry-out"
              disabled={!computed || stale || !computed.digest || apply.isPending
                || computed.action === "no_change" || computed.action === "absent"}
              onClick={() => (destructive || needsReason(action) ? setConfirming(true) : order())}
            >
              {t("Carry the plan out")}
            </Button>
          </Allowed>
        </Row>
        <Note>
          {t("The change carries the digest of this plan. The host computes the plan once more right before it and refuses when the host moved in the meantime.")}
        </Note>
        {(message || plan.message) && <Problem>{message || plan.message}</Problem>}
        {plan.attempt && !computed && (
          <Problem>{plan.attempt.message || plan.attempt.error_code || t("The host sent no plan back.")}</Problem>
        )}
        {computed && <PlanView plan={computed} stale={stale} />}
        {ordered && <JobNotice job={ordered} hostID={host.id} />}
      </Stack>
      {confirming && (
        <Confirm
          host={host}
          danger={destructive}
          // A declaration of the highest risk is not a removal, and the
          // dialog says which of the two it is: the panel refuses either
          // without a reason, and a wording that threatens data loss over a
          // container being declared teaches the operator to read nothing.
          reasonOnly={!destructive}
          title={destructive ? t("Remove {name}", { name: target }) : t("Declare {name}", { name: target })}
          what={destructive
            ? t("What is stored in it goes with it, and the removal cannot be undone.")
            : t("This change is of the highest risk, so the panel keeps the reason in the audit trail and asks who is ordering it.")}
          busy={apply.isPending}
          onConfirm={(reason, confirmation) => order(reason, confirmation)}
          onCancel={() => setConfirming(false)}
        />
      )}
    </Card>
  );
}

/** What the plan says would happen. */
function PlanView({ plan, stale }: { plan: ComputedPlan; stale: boolean }) {
  const t = useT();
  if (plan.unavailable_reason) return <Problem>{plan.unavailable_reason}</Problem>;
  return (
    <Stack>
      <Note>{t(planVerdict(plan.action))}</Note>
      {stale && (
        <Problem>
          {t("The description changed since this plan was computed; compute it again before carrying it out.")}
        </Problem>
      )}
      {plan.pinned_image && (
        <Note>
          {t("The image is bound to {digest} ({source}).", { digest: plan.pinned_image, source: plan.digest_source ?? "" })}
        </Note>
      )}
      {plan.changes?.length ? (
        <Table
          testId="declaration-plan"
          rows={plan.changes}
          keyOf={(one) => one.field}
          columns={[
            { key: "field", head: t("Setting"), tight: true, cell: (one) => <span className="fl-mono">{one.field}</span> },
            { key: "current", head: t("On the host"), tight: true, cell: (one) => (
              <span className="fl-mono">{one.current || "—"}</span>
            ) },
            { key: "desired", head: t("Declared"), tight: true, cell: (one) => (
              <span className="fl-mono">{one.desired || "—"}</span>
            ) },
          ]}
        />
      ) : (
        <Note>{t("No setting differs.")}</Note>
      )}
      {plan.detaches?.length ? (
        <Note>
          {t("These containers lose the network and are not reattached: {names}", { names: plan.detaches.join(", ") })}
        </Note>
      ) : null}
      {plan.warnings?.map((warning) => <Note key={warning}>{warning}</Note>)}
    </Stack>
  );
}

/* ------------------------------------------------------- the words */

function removalLabel(t: Translate, target: Pending): string {
  switch (target.kind) {
    case "remove-container": return t("Remove container");
    case "remove-image": return t("Remove image");
    case "remove-network": return t("Remove network");
    case "remove-volume": return t("Remove volume");
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
      // is the only operation of this module that really erases data.
      return t("Volume {name} will be removed with everything stored in it. This cannot be undone.", { name: target.name });
  }
}

/* --------------------------------------------- the registry's fields */

/**
 * The form of one operation, drawn from the registry.
 *
 * The advanced view is the escape hatch for a payload the fields cannot
 * show; while it holds one, the payload travels exactly as typed.
 */
function RegistryFields({ entry, value, onChange, json, onJson, suggestions }: {
  entry: OperationEntry;
  value: FormValue;
  onChange: (value: FormValue) => void;
  json: string;
  onJson: (json: string) => void;
  suggestions?: FieldSuggestions;
}) {
  const t = useT();
  const [advanced, setAdvanced] = useState(json !== "");
  const [draft, setDraft] = useState(() => json || payloadTextOf(entry, value));
  const problems = entry.validate(value);
  const problemOf = (name: string) => problems.find((one) => one.field === name);
  const set = (field: OperationField, next: FieldValue) => onChange({ ...value, [field.name]: next });

  const editJson = (next: string) => {
    setDraft(next);
    const read = readPayloadText(entry, next);
    if (read) {
      onChange(read);
      onJson("");
      return;
    }
    onJson(next);
  };

  return (
    <Stack>
      <Check
        checked={advanced}
        onChange={(on) => {
          if (on) { setDraft(payloadTextOf(entry, value)); setAdvanced(true); return; }
          setAdvanced(false);
          onJson("");
        }}
      >
        {t("Advanced (JSON)")}
      </Check>
      {entry.note && <Note>{t(entry.note)}</Note>}
      {entry.plan && <Note>{t(entry.plan)}</Note>}

      {advanced ? (
        <Fields>
          <Field
            label={t("Payload (JSON, the same shape as a single-host operation)")}
            hint={advancedWords(t, entry, draft)}
            wide
          >
            <textarea
              className="fl-mono"
              rows={Math.min(24, Math.max(6, draft.split("\n").length + 1))}
              value={draft}
              data-testid="operation-json"
              onChange={(event) => editJson(event.target.value)}
              spellCheck={false}
            />
          </Field>
        </Fields>
      ) : (
        <>
          <Fields>
            {entry.fields.map((field) => (
              <OneField
                key={field.name}
                field={field}
                value={value}
                problem={problemOf(field.name)}
                set={set}
                suggestions={suggestions?.[field.name]}
              />
            ))}
          </Fields>
          {entry.fields.length === 0 && <Note>{t("This operation takes no settings.")}</Note>}
          {problems.length > 0 && (
            <Note>{problems.map((one) => t(one.message, one.params)).join(" ")}</Note>
          )}
        </>
      )}
    </Stack>
  );
}

/** What the advanced view is holding right now. */
export function advancedWords(t: Translate, entry: OperationEntry, draft: string): string {
  if (readPayloadText(entry, draft)) {
    return t("The fields can show this payload, so they are what the order carries; close the advanced view and they are filled in with it.");
  }
  if (safePayload(draft)) {
    return t("The fields cannot show this payload, so it travels exactly as typed. The server checks it and names what is wrong.");
  }
  return t("This is not valid JSON.");
}

/** One field of an operation's form. */
function OneField({ field, value, problem, set, suggestions }: {
  field: OperationField;
  value: FormValue;
  problem?: FormProblem;
  set: (field: OperationField, next: FieldValue) => void;
  suggestions?: string[];
}) {
  const t = useT();
  const hint = problem ? t(problem.message, problem.params) : field.hint ? t(field.hint) : undefined;

  if (field.kind === "boolean") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <Check checked={flag(value, field.name)} onChange={(on) => set(field, on)}>{t(field.label)}</Check>
      </Field>
    );
  }

  if (field.kind === "select") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <select
          value={textOf(value, field.name)}
          data-testid={`field-${field.name}`}
          onChange={(event) => set(field, event.target.value)}
        >
          {(field.options ?? []).map((one) => <option key={one.value} value={one.value}>{t(one.label)}</option>)}
        </select>
      </Field>
    );
  }

  if (field.kind === "number" || field.kind === "duration") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <input
          type="number"
          min={field.min}
          max={field.max}
          value={String(count(value, field.name))}
          data-testid={`field-${field.name}`}
          onChange={(event) => set(field, event.target.value === "" ? 0 : Number(event.target.value))}
        />
      </Field>
    );
  }

  if (["textarea", "list", "packages", "pairs"].includes(field.kind)) {
    const written = body(value, field.name);
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <textarea
          className="fl-mono"
          rows={Math.min(16, Math.max(field.kind === "textarea" ? 6 : 3, written.split("\n").length + 1))}
          value={written}
          placeholder={field.placeholder}
          data-testid={`field-${field.name}`}
          onChange={(event) => set(field, event.target.value)}
          spellCheck={false}
        />
      </Field>
    );
  }

  const listID = suggestions && suggestions.length > 0 ? `fl-field-${field.name}` : undefined;
  return (
    <Field label={t(field.label)} hint={hint} wide={field.wide}>
      <input
        type="text"
        value={body(value, field.name)}
        placeholder={field.placeholder}
        list={listID}
        data-testid={`field-${field.name}`}
        onChange={(event) => set(field, event.target.value)}
        spellCheck={field.kind === "text"}
      />
      {listID && (
        <datalist id={listID}>
          {(suggestions ?? []).map((one) => <option key={one} value={one} />)}
        </datalist>
      )}
    </Field>
  );
}

/* ----------------------------------------------------- the one change */

/** The confirmation of an irreversible operation. */
function Confirm({ host, title, what, busy, danger, target, reasonOnly, onConfirm, onCancel }: {
  host: Host;
  title: string;
  what: ReactNode;
  busy: boolean;
  danger?: boolean;
  /** What is typed to confirm; the hostname unless something narrower goes. */
  target?: string;
  /**
   * Ask for the reason and nothing else. An operation that takes data away
   * is confirmed by typing its name; one that is merely of the highest
   * risk needs the reason the panel refuses the order without, and asking
   * for a name there teaches the operator to type names without reading.
   */
  reasonOnly?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const expected = target ?? host.hostname;
  const ready = reason.trim().length >= MIN_REASON_LENGTH && (reasonOnly === true || typed === expected);

  return (
    <Modal
      title={title}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind={danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason, typed)}
            testId="confirm"
          >
            {busy ? t("Requesting…") : title}
          </Button>
        </>
      }
    >
      <Stack>
        <Note>{what}</Note>
        {/* The target repeated in the dialog: the operator approves a
            specific machine, not "the host I think I have open". */}
        <Note>
          {t("Target: {host}", { host: host.hostname })}
          {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
          {` · ${host.site} / ${host.environment}`}
        </Note>
        <Fields>
          <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
          </Field>
          {!reasonOnly && (
            <Field
              label={target === undefined ? t("Type the hostname to confirm:") : t("Type the name to confirm:")}
              hint={expected}
              wide
            >
              <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
            </Field>
          )}
        </Fields>
      </Stack>
    </Modal>
  );
}

/** The name this screen's arrangement is stored under. */
export const CONTAINERS_SCREEN = "next_host_containers";

/** The containers this screen can draw, and the shape each ships with. */
export const CONTAINERS_BOARD: BoardEntry[] = [
  { key: "running", title: "Running", width: 3, height: 2 },
  { key: "unhealthy", title: "Unhealthy", width: 3, height: 2 },
  { key: "restarting", title: "Restarting", width: 3, height: 2 },
  { key: "engineversion", title: "Engine", width: 3, height: 2 },
  { key: "states", title: "Containers by state", width: 8, height: 4 },
  { key: "engine", title: "Engine", width: 4, height: 4 },
  { key: "projects", title: "Compose projects", width: 12, height: 4 },
  { key: "objects", title: "Engine objects", width: 12, height: 9 },
  { key: "logs", title: "Container log", width: 12, height: 9 },
  { key: "pull", title: "Pull an image", width: 12, height: 4 },
  { key: "declare", title: "Declare what this host is to carry", width: 12, height: 9 },
  { key: "source", title: "Where this came from", width: 12, height: 2 },
];
