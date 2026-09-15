import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Time, OptionalFlag, OptionalNumber, Empty, ErrorBox, JobState } from "../../components/ui";
import { Icon, type IconName } from "../../components/icons";
import { Meter } from "../../components/widgets";
import { api, ApiError, loadedItems } from "../../lib/api";
import { bytes, relativeTime } from "../../lib/format";
import {
  RECOVERABLE_REFUSALS, refusalName,
  type DecommissionOutcome, type EnrollmentOrder, type Host, type HostTimelineItem, type HostTimelineKind, type HostTimelinePage, type Job,
  type Whoami,
} from "../../lib/types";
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
  // The owner and the address are facts recorded in the panel, edited in
  // place by whoever may write the host's tags: the same right, because
  // they are the same kind of thing - what the panel knows, not what the
  // host reports.
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canEditFacts = (whoami.data?.permissions ?? []).includes("host.tag.write");

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
            <Fact label={t("Owner")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                value={host.owner ?? ""}
                shown={host.owner ? <span>{host.owner}</span> : <span className="badge unknown">{t("nobody")}</span>}
                label={t("Owner")}
                help={t("Who answers for the host; empty hands it back to nobody.")}
                placeholder={t("platform team")}
                path="owner"
                field="owner"
                testID="owner"
              />
            </Fact>
            <Fact label={t("Management address")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                value={host.management_address_source === "manual" ? host.management_address ?? "" : ""}
                shown={host.management_address
                  ? <span className="hm-mono">{host.management_address} <span className="badge" title={t(addressSourceMeaning(host.management_address_source))}>{host.management_address_source}</span></span>
                  : <span className="badge unknown">{t("unknown")}</span>}
                label={t("Management address")}
                help={t("An IP address or a host name the panel reaches the host at. It replaces what the connection shows; empty forgets it and the observed address returns.")}
                placeholder="10.0.0.5"
                path="management-address"
                field="address"
                testID="management-address"
              />
            </Fact>
            {/* The domain is a budget key from the moment it is written:
                the next change on the host asks for a token of that domain
                next to the site's. Hence a fact set by hand, not a tag. */}
            <Fact label={t("Failure domain")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                value={host.failure_domain ?? ""}
                shown={host.failure_domain ? <span>{host.failure_domain}</span> : <span className="badge unknown">{t("not placed")}</span>}
                label={t("Failure domain")}
                help={t("What the host goes down with: a rack, a zone, a cluster. Change budgets are keyed by it, so a campaign takes at most its share of one domain at a time; empty takes the host out from under the domain budgets.")}
                placeholder={t("rack-12, zone-b")}
                path="failure-domain"
                field="failure_domain"
                testID="failure-domain"
              />
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
            {/* The release and, next to it, the commit the binary was built
                from: the version names a release, the commit names the
                sources, which matters once a package was rebuilt. An agent
                from before the report shows the version alone. */}
            <Fact label={t("Agent version")}>
              {host.agent_version || <span className="badge unknown">{t("unknown")}</span>}
              {host.agent_build_commit && (
                <>
                  {" "}
                  <span className="hm-mono" title={`${t("Commit")}: ${host.agent_build_commit}`}>
                    {host.agent_build_commit.slice(0, 12)}
                  </span>
                </>
              )}
            </Fact>
            {/* Whether the agent runs on the configuration file of the
                current schema or still on the environment file of the old
                flow, which is what "agentctl config migrate" moves it off.
                A host whose agent reported nothing is unknown, not legacy. */}
            <Fact label={t("Daemon config")}>
              {host.config_legacy === undefined
                ? <span className="badge unknown">{t("unknown")}</span>
                : host.config_legacy
                  ? <span className="badge warn">{t("Schema migration")}</span>
                  : <span className="badge ok">{t("up to date")}</span>}
            </Fact>
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
          description={t("Whether the panel trusts this host, restoring its identity, and ending that trust.")}
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

/** What each origin of the management address means, for the badge. */
function addressSourceMeaning(source: string | undefined): string {
  switch (source) {
    case "session": return "address seen by the control plane on its end of the connection";
    case "agent": return "address reported by the host itself; it connects through a relay";
    case "manual": return "address set manually by an operator";
    default: return "address source";
  }
}

/**
 * A hand-recorded fact of the host, shown with an editor in place.
 *
 * The write goes back with the entity tag of the host read when the
 * editor opened, so a correction made by somebody else in the meantime is
 * refused with a message rather than overwritten; the operator reads the
 * host again and decides with the newer value in front of them. The
 * reason is optional and kept in the trail.
 */
function HostFact({ host, editable, value, shown, label, help, placeholder, path, field, testID }: {
  host: Host;
  editable: boolean;
  /** The value the editor starts from. */
  value: string;
  /** The fact as the card shows it when nobody is editing. */
  shown: ReactNode;
  label: string;
  help: string;
  placeholder: string;
  /** The last segment of the PUT address under /api/v1/hosts/{id}/. */
  path: "owner" | "management-address" | "failure-domain";
  /** The name of the value in the request body. */
  field: "owner" | "address" | "failure_domain";
  testID: string;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [reason, setReason] = useState("");
  const [etag, setEtag] = useState("");
  const [message, setMessage] = useState("");

  const save = useMutation({
    mutationFn: () =>
      api.put<Host>(`/api/v1/hosts/${host.id}/${path}`, { [field]: draft.trim(), reason: reason.trim() },
        { headers: etag ? { "If-Match": etag } : {} }),
    onSuccess: () => {
      setEditing(false);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 412) {
        setMessage(t("Somebody changed this host since you opened the editor; close it and open it again to see the current value."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const open = async () => {
    setDraft(value);
    setReason("");
    setMessage("");
    setEditing(true);
    // The tag comes with a fresh read, not from the cached host: the cache
    // may be a heartbeat old, and the tag must name what the editor shows.
    try {
      const fresh = await api.getWithMeta<Host>(`/api/v1/hosts/${host.id}`);
      setEtag(fresh.etag);
    } catch {
      // Without a tag the write goes unconditional, as a script would;
      // the server still records who changed what.
      setEtag("");
    }
  };

  if (!editing) {
    return (
      <span data-testid={`fact-${testID}`}>
        {shown}
        {editable && (
          <>
            {" "}
            <button type="button" className="link" onClick={open}>{t("edit")}</button>
          </>
        )}
      </span>
    );
  }
  return (
    <Form>
      <Fields>
        <Field label={label} help={help}>
          <input
            value={draft}
            placeholder={placeholder}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") save.mutate();
              if (e.key === "Escape") setEditing(false);
            }}
            autoFocus
            data-testid={`edit-${testID}`}
          />
        </Field>
        <Field label={t("Reason")} help={t("Optional; kept in the audit trail.")}>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("change ticket, handover")} />
        </Field>
      </Fields>
      <FormActions>
        <button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? t("saving…") : t("Save")}</button>
        <button className="secondary" onClick={() => setEditing(false)} disabled={save.isPending}>{t("Cancel")}</button>
      </FormActions>
      <Message text={message} error />
    </Form>
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
 * The lifecycle of the host: the state with the decision behind it, the
 * refusal that keeps it out if there is one, the recovery of its identity
 * and the decommission.
 */
function Lifecycle({ host }: { host: Host }) {
  const t = useT();
  // The outcome lives here rather than in the form: the form goes away once
  // the host is retired, and the answer - above all an unconfirmed cleanup
  // - has to stay on screen after that.
  const [outcome, setOutcome] = useState<DecommissionOutcome | null>(null);
  const refusal = host.connection_state !== "online" ? host.last_connection_refusal : undefined;
  const alive = host.lifecycle_state !== "retired" && host.lifecycle_state !== "retiring";
  return (
    <>
      {refusal && <ConnectionRefusalNotice host={host} />}
      <Facts>
        <Fact label={t("State")}><LifecycleBadge state={host.lifecycle_state} /></Fact>
        <Fact label={t("Since")}>{host.lifecycle_changed_at ? <Time value={host.lifecycle_changed_at} /> : "—"}</Fact>
        <Fact label={t("Decided by")}>{lifecycleActor(host) || "—"}</Fact>
        <Fact label={t("Reason")}>{host.lifecycle_reason || "—"}</Fact>
        <Fact label={t("Meaning")} wide>{lifecycleMeaning(t, host.lifecycle_state)}</Fact>
      </Facts>
      {alive && <Quarantine host={host} />}
      {alive && <IdentityRecovery host={host} prompted={!!refusal && RECOVERABLE_REFUSALS.includes(refusal.code)} />}
      {outcome && <div className="hm-section-body"><DecommissionResult outcome={outcome} /></div>}
      {host.lifecycle_state !== "retired" && <DecommissionHost host={host} onDone={setOutcome} />}
    </>
  );
}

/**
 * Who took the lifecycle decision, when the host view carries it. The
 * field is written with every transition; a view from before it was
 * exposed has none, and that is shown as unknown rather than as nobody.
 */
function lifecycleActor(host: Host): string {
  const actor = (host as Host & { lifecycle_changed_by?: string }).lifecycle_changed_by;
  return actor ?? "";
}

/**
 * Cutting the host off and letting it back in.
 *
 * Quarantine is the first move of an incident: the host loses its session
 * and its secrets, the undelivered jobs are cancelled, and nothing runs on
 * it until somebody releases it. Revoking the certificates is a separate
 * decision, taken on a suspected key theft: a revoked certificate cannot
 * be released, only recovered. Both changes are step-up operations: the
 * operator types the hostname, gives a reason, and the order asks for
 * fresh authentication. The buttons exist only for whoever may order them.
 */
function Quarantine({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = whoami.data?.permissions ?? [];
  const quarantined = host.lifecycle_state === "quarantined";
  const mayQuarantine = permissions.includes("host.quarantine") && !quarantined;
  const mayRelease = permissions.includes("host.quarantine.release") && quarantined;
  const [open, setOpen] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [confirming, setConfirming] = useState<"quarantine" | "release" | null>(null);
  const [message, setMessage] = useState("");
  const [signInAgain, setSignInAgain] = useState(false);

  const request = useMutation({
    mutationFn: ({ path, body }: { path: string; body: Record<string, unknown> }) =>
      api.post<{ lifecycle_state: string; jobs_canceled?: number; certificates_revoked?: number }>(
        `/api/v1/hosts/${host.id}/${path}`, body,
      ),
    onSuccess: (result) => {
      setMessage(result.lifecycle_state === "quarantined"
        ? t("The host is quarantined: {jobs} job(s) cancelled, {certificates} certificate(s) revoked.", {
            jobs: result.jobs_canceled ?? 0, certificates: result.certificates_revoked ?? 0,
          })
        : t("The host is released; the agent reconnects on its own."));
      setSignInAgain(false);
      setConfirming(null);
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["host-timeline", host.id] });
    },
    onError: (error) => {
      setConfirming(null);
      // A stale authentication is a sign-in that comes back here, not a
      // failure of the order.
      if (error instanceof ApiError && error.unauthenticated) {
        setSignInAgain(true);
        setMessage(t("Fresh authentication is required: sign in again and repeat the order."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  if (!mayQuarantine && !mayRelease) return null;

  return (
    <div className="hm-section-body" data-testid="quarantine">
      {mayRelease && (
        <FormActions>
          <button onClick={() => setConfirming("release")} disabled={confirming !== null}>
            {t("Release from quarantine…")}
          </button>
        </FormActions>
      )}
      {mayQuarantine && !open && (
        <FormActions>
          <button className="hm-danger" onClick={() => setOpen(true)}>{t("Quarantine host…")}</button>
        </FormActions>
      )}
      {mayQuarantine && open && (
        <Form>
          <Check checked={revoke} onChange={setRevoke}>
            {t("Revoke the certificates as well (suspected key theft)")}
          </Check>
          <FormNote>
            {revoke
              ? t("The certificates stop working now. A host with revoked certificates is not released: its return is an identity recovery.")
              : t("The certificates stay valid; the lifecycle state alone keeps the host out, and a release lets it back in.")}
          </FormNote>
          <FormNote>
            {t("The session is closed, the undelivered jobs are cancelled, and the host takes no operations and no secrets. A task already delivered runs to its end; the panel cannot undo it.")}
          </FormNote>
          <FormActions>
            <button className="hm-danger" onClick={() => setConfirming("quarantine")} disabled={confirming !== null}>
              {t("Quarantine host…")}
            </button>
            <button className="secondary" onClick={() => { setOpen(false); setConfirming(null); }}>{t("Cancel")}</button>
          </FormActions>
        </Form>
      )}
      <Message text={message} />
      {signInAgain && (
        <FormActions>
          <button
            className="secondary"
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </button>
        </FormActions>
      )}

      {confirming === "quarantine" && (
        <TargetConfirmation
          host={host}
          danger
          label={t("Quarantine host")}
          description={t("{host} is cut off from the fleet at once: no session, no operations, no secrets, until somebody releases it.", { host: host.hostname })}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ path: "quarantine", body: { reason, revoke_certificates: revoke } })
          }
          onCancel={() => setConfirming(null)}
        />
      )}
      {confirming === "release" && (
        <TargetConfirmation
          host={host}
          label={t("Release from quarantine")}
          description={t("{host} returns to the fleet: the agent reconnects on its own and the host takes operations again. Under a duplicate identity, wipe or reinstall the other machine first, or the release produces the next duplicate.", { host: host.hostname })}
          busy={request.isPending}
          onConfirm={(reason) => request.mutate({ path: "quarantine/release", body: { reason } })}
          onCancel={() => setConfirming(null)}
        />
      )}
    </div>
  );
}

/**
 * Why the host is not connected, when the gateway is the one that said no.
 *
 * An offline host and a refused host look the same from the connection
 * badge, and the difference is the whole diagnosis: a refused host is
 * alive and knocking, and the reason names what to do about it. The
 * certificate refusals are answered by an identity recovery; a lifecycle
 * refusal is an operator's own decision and is said to be one.
 */
function ConnectionRefusalNotice({ host }: { host: Host }) {
  const t = useT();
  const refusal = host.last_connection_refusal;
  if (!refusal) return null;
  const remedy = RECOVERABLE_REFUSALS.includes(refusal.code)
    ? t("The agent on the host is alive and connecting, but the gateway will not take its certificate. Order an identity recovery below and run the recovery on the host; nothing else brings it back.")
    : refusal.code === "certificate_not_yet_valid"
      ? t("The certificate is from the future: the clock of the host or of the panel is wrong. Fix the time; the agent reconnects on its own.")
      : refusal.code.startsWith("lifecycle_")
        ? t("The host is kept out by its lifecycle state, a decision recorded above, not by a fault of its own.")
        : t("The certificate is on record for another host. Check which machine holds this identity before anything else.");
  return (
    <div className="hm-section-body" data-testid="connection-refusal">
      <Message
        error
        text={t("Connection refused: {reason} {when}.", {
          reason: t(refusalName(refusal.code)),
          when: relativeTime(refusal.at),
        })}
      />
      <FormNote>{remedy}</FormNote>
      {refusal.detail && <FormNote><span className="hm-mono">{refusal.detail}</span></FormNote>}
    </div>
  );
}

/** The recovery order as it comes back: the token exists only in this answer. */
type RecoveryOrder = EnrollmentOrder & { token?: string };

/**
 * Ordering an identity recovery.
 *
 * The host stays in the fleet with its history: the order issues a token
 * that fits this host alone, and the agent on the machine trades it for a
 * new key and certificate. Meant for a host whose certificate the gateway
 * refuses - expired, unknown, revoked - and for a suspected key theft, in
 * which case the old certificate is cut off at once rather than at the
 * first session of the new one. Critical: the operator types the hostname
 * and gives a reason, and the order asks for fresh authentication.
 */
function IdentityRecovery({ host, prompted }: { host: Host; prompted: boolean }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [revokeOld, setRevokeOld] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState("");
  const [signInAgain, setSignInAgain] = useState(false);
  const [order, setOrder] = useState<RecoveryOrder | null>(null);

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<RecoveryOrder>(`/api/v1/hosts/${host.id}/identity-recovery`, body),
    onSuccess: (result) => {
      setOrder(result);
      setMessage("");
      setSignInAgain(false);
      setConfirming(false);
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setConfirming(false);
      // A stale authentication is a sign-in that comes back here, not a
      // failure of the order.
      if (error instanceof ApiError && error.unauthenticated) {
        setSignInAgain(true);
        setMessage(t("Fresh authentication is required: sign in again and repeat the order."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <div className="hm-section-body" data-testid="identity-recovery">
      {order && <RecoveryOrderResult host={host} order={order} />}
      {!open ? (
        <FormActions>
          <button className={prompted ? undefined : "secondary"} onClick={() => setOpen(true)}>
            {t("Order identity recovery…")}
          </button>
        </FormActions>
      ) : (
        <Form>
          <Check checked={revokeOld} onChange={setRevokeOld}>
            {t("Revoke the old certificate at once (suspected key theft)")}
          </Check>
          <FormNote>
            {revokeOld
              ? t("The old certificate stops working now: the host loses its session and cannot come back until the recovery is run on it.")
              : t("The old certificate stays valid for a day, so the host can still be read; it is revoked when the new one opens its first session.")}
          </FormNote>
          <FormNote>
            {t("The host enters recovery: no operations and no secrets until the new certificate has proven it works. The token is shown once and fits this host alone.")}
          </FormNote>
          <FormActions>
            <button onClick={() => setConfirming(true)} disabled={confirming}>
              {t("Order identity recovery…")}
            </button>
            <button className="secondary" onClick={() => { setOpen(false); setConfirming(false); }}>{t("Cancel")}</button>
          </FormActions>
          <Message text={message} error />
          {signInAgain && (
            <FormActions>
              <button
                className="secondary"
                onClick={() => {
                  const target = encodeURIComponent(window.location.pathname);
                  window.location.href = `/auth/login?step_up=1&redirect=${target}`;
                }}
              >
                {t("Sign in again")}
              </button>
            </FormActions>
          )}
        </Form>
      )}

      {confirming && (
        <TargetConfirmation
          host={host}
          label={t("Order identity recovery")}
          description={t("{host} gets a one-time token for a new key and certificate; its record and history stay. Until the new certificate connects, the host takes no operations.", { host: host.hostname })}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              reason,
              description: reason,
              revoke_old_immediately: revokeOld,
            })
          }
          onCancel={() => setConfirming(false)}
        />
      )}
    </div>
  );
}

/**
 * The recovery order and what to do with it on the host. The token is
 * shown here and never again: it is not stored in the browser and cannot
 * be read back from the panel.
 */
function RecoveryOrderResult({ host, order }: { host: Host; order: RecoveryOrder }) {
  const t = useT();
  return (
    <div className="hm-form" data-testid="recovery-order">
      <Message text={order.token
        ? t("The recovery order is placed. Run the command below on the host as root and paste the token when asked.")
        : t("A recovery order for this host is already open; its token was shown when it was placed.")} />
      <Facts>
        <Fact label={t("On the host")} wide>
          <span className="hm-mono">flotestro-agentctl identity reset --confirm {host.hostname}</span>
        </Fact>
        {order.token && (
          <Fact label={t("Token (shown once)")} wide>
            <span className="hm-mono" data-testid="recovery-token">{order.token}</span>
          </Fact>
        )}
        <Fact label={t("Expires")}><Time value={order.expires_at} /></Fact>
        <Fact label={t("Order")}><Link to="/hosts/new">{order.id.slice(0, 8)}</Link></Fact>
      </Facts>
    </div>
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
