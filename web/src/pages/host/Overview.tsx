import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Time, OptionalFlag, OptionalNumber, Empty, ErrorBox, JobState } from "../../components/ui";
import { Icon, type IconName } from "../../components/icons";
import { Meter } from "../../components/widgets";
import { api, loadedItems } from "../../lib/api";
import { bytes } from "../../lib/format";
import type { DecommissionOutcome, Host, HostTimelineItem, HostTimelineKind, HostTimelinePage, Job } from "../../lib/types";
import {
  Check, Fact, Facts, Field, Fields, Foot, Form, FormActions, FormNote, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, usageTone, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type SystemState = {
  os?: Record<string, string>;
  hostname?: string;
  hardware?: {
    cpu_cores?: number;
    memory_bytes?: number;
    root_fs_bytes?: number;
    root_fs_free_bytes?: number;
    virtualization?: string;
  };
};

export function Overview() {
  const t = useT();
  const host = useHost();
  const module = useModule<SystemState>(host.id, "system");
  const hardware = module.data?.payload?.hardware;

  // A host that has not reported its adapters has an unknown registry,
  // not an empty one: the bar shows dashes until the first report.
  const adapters = host.capabilities?.length ? host.capabilities : undefined;
  const rootUsed = hardware?.root_fs_bytes !== undefined && hardware.root_fs_free_bytes !== undefined
    ? hardware.root_fs_bytes - hardware.root_fs_free_bytes
    : undefined;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Overview")}
        description={t("Identity, hardware and the adapters of this host, as the agent last reported them.")}
      />
      <ModuleFreshness fragment={module.data} />

      <Widgets>
        {/* The two bars are the host read from across the room: what the
            panel can do here, and what wants a decision. */}
        <Summary
          title={t("Adapters")}
          description={t("What the panel can read and change on this host.")}
          span={7}
          segments={[
            { label: t("available"), value: countWhere(adapters, (a) => a.available && !a.read_only), tone: "ok" },
            { label: t("read only"), value: countWhere(adapters, (a) => a.available && a.read_only), tone: "warn" },
            { label: t("unavailable"), value: countWhere(adapters, (a) => !a.available), tone: "neutral" },
          ]}
        />
        <Summary
          title={t("Needs attention")}
          description={t("Counted by the agent on its last report.")}
          span={5}
          segments={[
            { label: t("Failed units"), value: host.failed_units ?? undefined, tone: "error" },
            { label: t("Updates waiting"), value: host.pending_updates ?? undefined, tone: "warn" },
            { label: t("Security updates"), value: host.pending_security_updates ?? undefined, tone: "error" },
          ]}
        />

        <Section title={t("System")} span={7} flush>
          <Facts>
            <Fact label={t("Hostname")}><span className="hm-mono">{host.hostname}</span></Fact>
            <Fact label={t("System")}>{host.os_distribution} {host.os_version} ({host.os_family})</Fact>
            <Fact label={t("Architecture")}>{host.architecture || "—"}</Fact>
            <Fact label={t("Management address")}>
              {host.management_address
                ? <span className="hm-mono">{host.management_address} ({host.management_address_source})</span>
                : <span className="badge unknown">{t("unknown")}</span>}
            </Fact>
            <Fact label={t("Lifecycle state")}><LifecycleBadge state={host.lifecycle_state} /></Fact>
            <Fact label={t("Reboot required")}><OptionalFlag value={host.reboot_required} /></Fact>
            <Fact label={t("Failed units")}><OptionalNumber value={host.failed_units} /></Fact>
            <Fact label={t("Package database")}>
              {host.package_database_broken ? <span className="badge error">{t("needs repair")}</span> : t("healthy")}
            </Fact>
            <Fact label={t("Enrolled")}><Time value={host.enrolled_at} /></Fact>
            <Fact label={t("Machine ID")}><span className="hm-mono">{host.machine_id}</span></Fact>
            <Fact label={t("Boot ID")}><span className="hm-mono">{host.boot_id || "—"}</span></Fact>
          </Facts>
          <RenameHost host={host} reported={module.data?.payload?.hostname} />
        </Section>

        <Section title={t("Hardware")} span={5} flush>
          {hardware ? (
            <Facts>
              <Fact label={t("CPU cores")}>{hardware.cpu_cores ?? "—"}</Fact>
              <Fact label={t("Memory")}>{hardware.memory_bytes ? bytes(hardware.memory_bytes) : "—"}</Fact>
              <Fact label={t("Virtualization")}>{hardware.virtualization || "—"}</Fact>
              {/* The filesystem is the one number here that changes on its
                  own; it gets a bar, and the bar's colour says when it is
                  time to look at the storage page. */}
              <Fact label={t("Root filesystem")} wide>
                {rootUsed !== undefined && hardware.root_fs_bytes ? (
                  <Meter
                    value={rootUsed}
                    max={hardware.root_fs_bytes}
                    tone={usageTone(rootUsed, hardware.root_fs_bytes)}
                    text={t("{free} free of {total}", { free: bytes(hardware.root_fs_free_bytes), total: bytes(hardware.root_fs_bytes) })}
                  />
                ) : "—"}
              </Fact>
            </Facts>
          ) : (
            <Empty>{t("This host has not reported its hardware yet.")}</Empty>
          )}
        </Section>

        {/* The trust in the host: its state, the decision behind it, and
            the one change that cannot be undone. */}
        <Section
          title={t("Lifecycle")}
          description={t("Whether the panel trusts this host, and ending that trust.")}
          span={12}
          flush
        >
          <Lifecycle host={host} />
        </Section>

        <Section title={t("Adapters")} count={(host.capabilities ?? []).length} span={12} flush>
          <Adapters host={host} />
        </Section>

        {/* The history of the host from every record the panel keeps,
            lined up by time: what ran, what failed, who did what and when
            the host was last seen. */}
        <Section
          title={t("Recent activity")}
          description={t("Tasks, audit entries, sessions, campaigns and alerts of this host, newest first.")}
          span={12}
          flush
        >
          <RecentActivity host={host} />
        </Section>
      </Widgets>
    </ModulePage>
  );
}

/** An RFC 1123 name as the host accepts it: lower-case labels joined by dots. */
const HOSTNAME_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * Renaming the host.
 *
 * A rename changes the identity of the host towards everything that knows
 * it by name: DNS, Kerberos, the certificates of its services, the entries
 * of other hosts. The panel knows the host by identifier, so the management
 * channel survives - the rest is checked on the host before the change and
 * reported, never guessed. Critical: the operator types the name they are
 * taking away, and the order asks for fresh authentication.
 */
function RenameHost({ host, reported }: { host: Host; reported?: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [hostname, setHostname] = useState("");
  const [pretty, setPretty] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setConfirming(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const name = hostname.trim();
  const valid = HOSTNAME_PATTERN.test(name) && name.length <= 64 && name !== "localhost" && !name.endsWith(".localhost");
  const unchanged = name === host.hostname;

  return (
    <div className="hm-section-body">
      {/* The name the host reports for itself, when the panel's differs:
          the host was renamed by hand, or a rename is on its way. */}
      {reported && reported !== host.hostname && (
        <FormNote>{t("The host reports the name {name}; the panel will follow at the next inventory.", { name: reported })}</FormNote>
      )}
      {!open ? (
        <FormActions>
          <button className="secondary" onClick={() => setOpen(true)} disabled={host.connection_state !== "online"}>
            {t("Rename host")}
          </button>
        </FormActions>
      ) : (
        <Form>
          <Fields>
            <Field
              label={t("New hostname")}
              help={t("An RFC 1123 name, lower-case: a label or a fully qualified name.")}
            >
              <input value={hostname} placeholder="web02.example.internal" onChange={(e) => setHostname(e.target.value)} />
            </Field>
            <Field label={t("Pretty name")} help={t("Optional; what hostnamectl shows to people.")}>
              <input value={pretty} placeholder="Web 02" onChange={(e) => setPretty(e.target.value)} />
            </Field>
          </Fields>
          {name !== "" && !valid && (
            <Message text={t("This is not a valid hostname: lower-case letters, digits and hyphens, labels joined by dots.")} error />
          )}
          {unchanged && <Message text={t("The host already has this name.")} />}
          <FormNote>
            {t("The host checks first whether the name resolves in DNS to another machine and whether the agent's certificate is bound to the name. /etc/hosts follows the rename; DNS, Kerberos and service certificates do not.")}
          </FormNote>
          <FormActions>
            <button className="hm-danger" onClick={() => setConfirming(true)} disabled={!valid || unchanged || confirming}>
              {t("Rename host…")}
            </button>
            <button className="secondary" onClick={() => { setOpen(false); setConfirming(false); }}>{t("Cancel")}</button>
          </FormActions>
          <Message text={message} />
        </Form>
      )}

      {confirming && (
        <TargetConfirmation
          host={host}
          label={t("Rename host")}
          description={t("{host} will be renamed to {name}. Every system that knows it by the old name loses it at once; the panel keeps it by identifier.", { host: host.hostname, name })}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: "system.hostname.set",
              reason,
              target_confirmation: confirmation,
              payload: { hostname: { hostname: name, pretty: pretty.trim() } },
            })
          }
          onCancel={() => setConfirming(false)}
        />
      )}
    </div>
  );
}

/** The state of the host as a badge; the colour says which kind of "no" it is. */
function LifecycleBadge({ state }: { state: string }) {
  const t = useT();
  return <span className={`badge ${lifecycleTone(state)}`} data-testid="lifecycle-state">{t(state)}</span>;
}

/** What a state means for the operator reading the host. */
function lifecycleMeaning(t: (text: string) => string, state: string): string {
  switch (state) {
    case "active": return t("The host takes operations and secrets, and renews its certificate.");
    case "quarantined": return t("The host is cut off: no operations, no secrets, no session. Release it once the incident is assessed.");
    case "recovery": return t("An identity recovery is under way: no operations and no secrets until the new certificate opens its first session. The old certificate may still connect for a day, so the host can be read.");
    case "retiring": return t("The host is being decommissioned: the panel is waiting for it to finish its work.");
    case "retired": return t("The trust in this host has ended. It does not come back; its record and history stay.");
    default: return "";
  }
}

/**
 * The lifecycle of the host: the state with the decision behind it, and the
 * decommission.
 */
function Lifecycle({ host }: { host: Host }) {
  const t = useT();
  // The outcome lives here rather than in the form: the form goes away once
  // the host is retired, and the answer - above all an unconfirmed cleanup
  // - has to stay on screen after that.
  const [outcome, setOutcome] = useState<DecommissionOutcome | null>(null);
  return (
    <>
      <Facts>
        <Fact label={t("State")}><LifecycleBadge state={host.lifecycle_state} /></Fact>
        <Fact label={t("Since")}>{host.lifecycle_changed_at ? <Time value={host.lifecycle_changed_at} /> : "—"}</Fact>
        <Fact label={t("Reason")}>{host.lifecycle_reason || "—"}</Fact>
        <Fact label={t("Meaning")} wide>{lifecycleMeaning(t, host.lifecycle_state)}</Fact>
      </Facts>
      {outcome && <div className="hm-section-body"><DecommissionResult outcome={outcome} /></div>}
      {host.lifecycle_state !== "retired" && <DecommissionHost host={host} onDone={setOutcome} />}
    </>
  );
}

/**
 * Decommissioning the host.
 *
 * The end of trust, not the end of history: the record, the inventory and
 * the audit trail stay. A connected host is asked to finish its work, drop
 * its secret leases and wipe its identity; a host without a session is
 * retired without that, and the answer says so - a machine on a shelf must
 * not be taken for a machine that wiped itself. Critical: the operator
 * types the hostname and gives a reason, and the order asks for fresh
 * authentication.
 */
function DecommissionHost({ host, onDone }: { host: Host; onDone: (outcome: DecommissionOutcome) => void }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [wipe, setWipe] = useState(true);
  const [revokeOffline, setRevokeOffline] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<DecommissionOutcome>(`/api/v1/hosts/${host.id}/decommission`, body),
    onSuccess: (result) => {
      onDone(result);
      setMessage("");
      setConfirming(false);
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setConfirming(false);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const online = host.connection_state === "online";

  return (
    <div className="hm-section-body">
      {!open ? (
        <FormActions>
          <button className="hm-danger" onClick={() => setOpen(true)}>
            {t("Decommission host…")}
          </button>
        </FormActions>
      ) : (
        <Form>
          <Check checked={wipe} onChange={setWipe}>
            {t("Wipe the identity and the journal on the host and disable its agent service")}
          </Check>
          <Check checked={revokeOffline} onChange={setRevokeOffline}>
            {t("Revoke the certificates at once if the host is offline")}
          </Check>
          <FormNote>
            {online
              ? t("The host is connected: it will finish the operations under way, drop its secret leases and report it is ready; then its certificates are revoked and, with the wipe, its identity removed. The panel waits up to two minutes for the answer.")
              : t("The host is not connected: it is retired without its cooperation. Its certificates are revoked now, or at its first contact when the box above is cleared. What is on its disk stays unknown until somebody wipes it out of band.")}
          </FormNote>
          <FormNote>
            {t("The record, the inventory and the audit trail stay. A retired host does not come back; its machine is refused for a new-host token for 30 days.")}
          </FormNote>
          <FormActions>
            <button className="hm-danger" onClick={() => setConfirming(true)} disabled={confirming}>
              {t("Decommission host…")}
            </button>
            <button className="secondary" onClick={() => { setOpen(false); setConfirming(false); }}>{t("Cancel")}</button>
          </FormActions>
          <Message text={message} error />
        </Form>
      )}

      {confirming && (
        <TargetConfirmation
          host={host}
          danger
          label={t("Decommission host")}
          description={t("{host} leaves the fleet for good. Its certificates are revoked and nothing brings it back but a new enrollment as a new host.", { host: host.hostname })}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              reason,
              typed_confirmation: confirmation,
              local_identity_wipe: wipe,
              revoke_immediately_if_offline: revokeOffline,
            })
          }
          onCancel={() => setConfirming(false)}
        />
      )}
    </div>
  );
}

/**
 * What the decommission ended with. The unconfirmed cleanup is shown as a
 * warning and named for what it is; the confirmed one lists what the host
 * reported.
 */
function DecommissionResult({ outcome }: { outcome: DecommissionOutcome }) {
  const t = useT();
  return (
    <div className="hm-form" data-testid="decommission-result">
      {outcome.remote_cleanup_unconfirmed ? (
        <Message
          error
          text={outcome.phase === "no_session"
            ? t("The host is retired, but it had no session: nothing on the machine confirmed a wipe. Its identity files may still be there - wipe it out of band before it is handed over.")
            : t("The host is retired, but it did not answer the final task in time: nothing on the machine confirmed a wipe. Its identity files may still be there - check it out of band.")}
        />
      ) : (
        <Message text={t("The host is retired. It reported it stopped, its certificates were revoked and it was told to wipe its identity.")} />
      )}
      <Facts>
        <Fact label={t("Certificates revoked")}>{outcome.certificates_revoked}</Fact>
        <Fact label={t("Jobs cancelled")}>{outcome.jobs_canceled}</Fact>
        <Fact label={t("Secret leases dropped")}>{outcome.leases_dropped ? t("yes") : t("not confirmed")}</Fact>
        <Fact label={t("Operations cut short")}>
          {outcome.running_tasks.length === 0 ? t("none") : outcome.running_tasks.map((id) => <span key={id} className="hm-mono">{id.slice(0, 8)} </span>)}
        </Fact>
      </Facts>
    </div>
  );
}

/** How many rows one page of the timeline holds; the operator asks for more. */
const TIMELINE_PAGE = 30;

/** The mark of every kind of record, taken from the page it links to. */
const KIND_ICONS: Record<HostTimelineKind, IconName> = {
  job: "jobs", audit: "audit", session: "server", lifecycle: "hosts", alert: "monitoring", campaign: "campaigns",
};

/**
 * The host timeline. Every row is one record of one table - nothing is
 * derived here - and the row links to the page of that record. The server
 * folds in only the sources the operator may read; the ones left out are
 * named under the list rather than passed over.
 */
function RecentActivity({ host }: { host: Host }) {
  const t = useT();
  const timeline = useInfiniteQuery({
    queryKey: ["host-timeline", host.id],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams({ limit: String(TIMELINE_PAGE) });
      if (pageParam) page.set("cursor", pageParam);
      return api.get<HostTimelinePage>(`/api/v1/hosts/${host.id}/timeline?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });
  const items = loadedItems(timeline.data);
  const sources = timeline.data?.pages[0]?.sources ?? [];
  const hidden = (Object.keys(KIND_ICONS) as HostTimelineKind[]).filter((kind) => !sources.includes(kind));

  if (timeline.error) return <ErrorBox error={timeline.error} />;
  if (timeline.isPending) return <Empty>{t("Loading…")}</Empty>;
  return (
    <>
      {items.length === 0 ? (
        <Empty>{t("Nothing has been recorded for this host yet.")}</Empty>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>{t("When")}</th><th>{t("Kind")}</th><th>{t("What")}</th><th>{t("State")}</th><th>{t("Who")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.kind}:${item.id}`}>
                <td><Time value={item.at} /></td>
                <td>
                  <span className="badge" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                    <Icon name={KIND_ICONS[item.kind]} />{t(kindName(item.kind))}
                  </span>
                </td>
                <td>
                  <ActivityTitle host={host} item={item} />
                  {item.detail && <div className="source">{item.detail}</div>}
                </td>
                <td><ActivityState item={item} /></td>
                <td className="source">{item.actor || "—"}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <Foot>
        {timeline.hasNextPage && (
          <button className="secondary" onClick={() => timeline.fetchNextPage()} disabled={timeline.isFetchingNextPage}>
            {t("Load more")}
          </button>
        )}
        <span>{t("{n} shown", { n: items.length })}</span>
        {hidden.length > 0 && (
          <span>{t("Not shown, no permission: {kinds}", { kinds: hidden.map((kind) => t(kindName(kind))).join(", ") })}</span>
        )}
      </Foot>
    </>
  );
}

/** The name of a kind of record, as the row's badge says it. */
function kindName(kind: HostTimelineKind): string {
  const names: Record<HostTimelineKind, string> = {
    job: "task", audit: "audit", session: "session", lifecycle: "lifecycle", alert: "alert", campaign: "campaign",
  };
  return names[kind];
}

/**
 * The title of a row with the link to its record. A task links to the
 * host's task list and an audit entry to the host's trail, because those
 * are the pages that show the record; a campaign has a page of its own;
 * a session has none and stays text.
 */
function ActivityTitle({ host, item }: { host: Host; item: HostTimelineItem }) {
  const t = useT();
  const target = linkOf(host, item);
  const title = <span className="hm-mono">{item.title || "—"}</span>;
  return (
    <div>
      {target ? <Link to={target}>{title}</Link> : title}
      {/* The event words come from the server in a fixed set (created,
          finished, opened, ended, fired, resolved, selected, started). */}
      {item.event && <span className="source"> · {t(item.event)}</span>}
    </div>
  );
}

function linkOf(host: Host, item: HostTimelineItem): string | undefined {
  switch (item.kind) {
    case "job": return `/hosts/${host.id}/jobs`;
    case "audit":
    case "lifecycle": return `/hosts/${host.id}/audit`;
    case "alert": return `/hosts/${host.id}/monitoring`;
    case "campaign": return `/campaigns/${item.ref.id}`;
    default: return undefined;
  }
}

/**
 * The state of the record, coloured by what it means: a task or a
 * campaign target uses the shared state badge, an audit entry its outcome,
 * a lifecycle change the state the host went into, an alert whether it
 * still fires. An empty state is a dash, not a made-up "ok".
 */
function ActivityState({ item }: { item: HostTimelineItem }) {
  const t = useT();
  if (!item.state) return <>—</>;
  const errorCode = item.error_code ? <span className="source"> {item.error_code}</span> : null;
  switch (item.kind) {
    case "job":
    case "campaign":
      return <><JobState state={item.state} />{errorCode}</>;
    case "audit":
      return <span className={`badge ${item.state === "success" ? "ok" : "error"}`}>{t(item.state)}</span>;
    case "lifecycle":
      return <span className={`badge ${lifecycleTone(item.state)}`}>{t(item.state)}</span>;
    case "alert":
      return <span className={`badge ${item.state === "firing" ? "error" : "ok"}`}>{t(item.state)}</span>;
    case "session":
      return <span className={`badge ${item.state === "open" ? "ok" : ""}`}>{t(item.state)}</span>;
    default:
      return <span className="badge">{item.state}</span>;
  }
}

function lifecycleTone(state: string): string {
  switch (state) {
    case "active": return "ok";
    case "quarantined": return "warn";
    // A recovery and a retirement under way are both a host the panel is
    // waiting on: not cut off for good, not working either.
    case "recovery": return "warn";
    case "retiring": return "warn";
    case "retired": return "unknown";
    // A refused or failed attempt carries its outcome in place of a state.
    case "denied":
    case "failure": return "error";
    default: return "";
  }
}

/**
 * The host's adapter registry. The operator sees not only what is missing
 * but also why - the reason comes from the host, not from browser code.
 */
function Adapters({ host }: { host: ReturnType<typeof useHost> }) {
  const t = useT();
  const adapters = host.capabilities ?? [];
  if (adapters.length === 0) {
    return <Empty>{t("This host has not reported its adapters yet.")}</Empty>;
  }
  return (
    <Table>
      <thead><tr><th>{t("Adapter")}</th><th>{t("State")}</th><th>{t("Features")}</th><th>{t("Reason")}</th></tr></thead>
      <tbody>
        {adapters.map((adapter) => (
          <tr key={adapter.name}>
            <td className="hm-mono">{adapter.name}</td>
            <td>
              {!adapter.available ? (
                <span className="badge">{t("unavailable")}</span>
              ) : adapter.read_only ? (
                <span className="badge warn">{t("read only")}</span>
              ) : (
                <span className="badge ok">{t("available")}</span>
              )}
            </td>
            <td className="source">
              {Object.entries(adapter.features ?? {}).length === 0
                ? "—"
                : Object.entries(adapter.features ?? {})
                    .map(([name, present]) => `${name}: ${present ? t("yes") : t("no")}`)
                    .join(", ")}
            </td>
            <td className="source">{adapter.reason || "—"}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
