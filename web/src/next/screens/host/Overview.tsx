import { useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, loadedItems, type Collection } from "../../../lib/api";
import { bytes, relativeTime, absoluteTime } from "../../../lib/format";
import { REFRESH_INTERVAL } from "../../../lib/stream";
import {
  RECOVERABLE_REFUSALS, refusalName,
  type DecommissionOutcome, type EnrollmentOrder, type FleetActivity, type Host,
  type HostTimelineItem, type HostTimelineKind, type HostTimelinePage,
  type InventoryFragment, type Job, type Whoami,
} from "../../../lib/types";
import { stateName } from "../../../lib/states";
import { useT, type Translate } from "../../../i18n";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Button, C, Card, Check, Empty, Fact, Facts, Field, Fields, Grid, Kpi,
  Meter, Needs, Note, Pill, Readout, Reasons, Table, Tabs, Tag, Tags, type Segment, type Tone, Row} from "../../kit";
import {
  Confirm, Guard, JobLine, ReadOnlyNotice, orderReady, refusalOf, registryOrder, useOrder,
  type Intent, type RegistryOrder,
} from "./Power";

/**
 * What this machine is: what it is made of, what it is carrying, what has
 * lately been done to it - and what may be done to it.
 *
 * A figure the host never reported is an em dash and says so - the one
 * place that matters most, because a nought on a disk reads as "plenty of
 * room" about a machine nobody has asked.
 *
 * Every change here is a decision about one machine, so every one of them
 * goes through the same dialog the Power module confirms a reboot with: a
 * reason that goes into the trail and the hostname typed out. The dialog
 * itself is drawn by the screen rather than by the card that asked for it,
 * because a card lifts under the pointer and a fixed backdrop drawn inside
 * one would be measured against the card instead of the window.
 */

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

/** What the panel records by hand is corrected by whoever may write tags. */
const FACT_PERMISSION = "host.tag.write";

/**
 * Moving a host between teams is not editing a fact about it: it hands the
 * machine to other people, so it takes its own permission.
 */
const TEAM_PERMISSION = "host.scope.write";

/** The changes this screen offers; when every one is refused, it says so once. */
const OVERVIEW_CHANGES = ["system.hostname.set", "host.quarantine", "host.quarantine.release", "host.decommission"];

/** The longest note the API takes; the field says so before the request leaves. */
export const MAX_NOTES_LENGTH = 4000;

/** How many rows one page of the timeline holds; the operator asks for more. */
const TIMELINE_PAGE = 30;

/** What a card hands the screen when it wants a decision confirmed. */
export type Send = (reason: string, confirmation: string) => void;

/**
 * How every card on this screen asks: it describes the order and says what
 * to send, and the screen draws the one dialog and closes it again.
 */
export type Decide = {
  ask: (intent: Intent, send: Send) => void;
  close: () => void;
};

/** The permissions of the signed-in operator, for the gates of this screen. */
function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/** A refusal of a write in the operator's words rather than the server's. */
export function writeRefusal(t: Translate, error: unknown): string {
  if (error instanceof ApiError && error.status === 412) {
    return t("Somebody changed this host since you opened the editor; close it and open it again to see the current value.");
  }
  if (error instanceof ApiError && error.unauthenticated) {
    return t("Fresh authentication is required: sign in again and repeat the order.");
  }
  return error instanceof Error ? error.message : String(error);
}

/**
 * How full the root filesystem is, and whether that is a condition.
 *
 * Three answers rather than two: a host that has not reported its disk is
 * unknown, not empty. The thresholds are the ones an operator acts on -
 * past ninety per cent a full disk is a matter of hours, past eighty it is
 * a matter of planning.
 */
export function diskPressure(total?: number, free?: number): { used?: number; share?: number; tone?: Tone } {
  if (total === undefined || free === undefined || total <= 0) return {};
  const used = total - free;
  const share = used / total;
  return { used, share, tone: share > 0.9 ? "error" : share > 0.8 ? "warn" : "ok" };
}

export function Overview({ host }: { host: Host }) {
  const t = useT();
  const permissions = usePermissions();
  const canEditFacts = permissions.has(FACT_PERMISSION);
  const canMoveTeam = permissions.has(TEAM_PERMISSION);

  // The one dialog of the screen: what is being decided and what it sends.
  const [pending, setPending] = useState<{ intent: Intent; send: Send } | null>(null);
  const [busy, setBusy] = useState(false);
  const decide: Decide = {
    ask: (intent, send) => { setBusy(false); setPending({ intent, send }); },
    close: () => { setBusy(false); setPending(null); },
  };

  const system = useQuery({
    queryKey: ["inventory", host.id, "system"],
    queryFn: () => api.get<InventoryFragment<SystemState>>(`/api/v1/hosts/${host.id}/inventory/system`),
    retry: false,
  });
  const jobs = useQuery({
    queryKey: ["jobs", host.id, "recent"],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=8`),
    refetchInterval: REFRESH_INTERVAL,
  });

  const hardware = system.data?.payload?.hardware;
  const root = diskPressure(hardware?.root_fs_bytes, hardware?.root_fs_free_bytes);
  // A host that has not reported its adapters has an unknown registry, not
  // an empty one.
  const adapters = host.capabilities?.length ? host.capabilities : undefined;
  const available = adapters?.filter((one) => one.available).length;
  const unavailable = adapters === undefined ? undefined : adapters.length - (available ?? 0);
  const readOnly = adapters?.filter((one) => one.available && one.read_only).length;
  // The ones the panel cannot use here, in the order the host listed them.
  const missing = adapters?.filter((one) => !one.available) ?? [];
  // The gateway's own refusal is only news while the host is away.
  const refusal = host.connection_state !== "online" ? host.last_connection_refusal : undefined;

  const registry: Segment[] = [
    { label: t("available"), value: available, tone: "ok" },
    { label: t("unavailable"), value: unavailable, tone: "neutral" },
  ];

  /* What is wrong with this machine right now, counted apart from what it
     is made of: a reader asks "is it well" before "what is it". */
  const attention: { label: string; value?: number | boolean | null; tone: Tone; to?: string }[] = [
    { label: t("Failed units"), value: host.failed_units, tone: "error", to: `/hosts/${host.id}/services` },
    { label: t("Reboot required"), value: host.reboot_required, tone: "warn" },
    { label: t("Package database broken"), value: host.package_database_broken, tone: "error" },
    { label: t("Security updates"), value: host.pending_security_updates, tone: "warn", to: `/hosts/${host.id}/packages` },
    { label: t("Updates waiting"), value: host.pending_updates, tone: "neutral", to: `/hosts/${host.id}/packages` },
  ];

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={OVERVIEW_CHANGES} />
      {refusal && <ConnectionRefusal host={host} />}

      <Readings panels={{
      disk: (
        <Kpi
          icon="storage"
          label={t("Disk used")}
          value={root.share === undefined ? null : Math.round(root.share * 100)}
          unit="%"
          tone={root.tone}
          note={root.used === undefined || hardware?.root_fs_bytes === undefined
            ? undefined
            : t("{used} of {total}", { used: bytes(root.used), total: bytes(hardware.root_fs_bytes) })}
        />
      ),
      memory: (
        <Kpi
          icon="server"
          label={t("Memory")}
          value={hardware?.memory_bytes === undefined ? null : bytes(hardware.memory_bytes)}
          note={hardware?.virtualization ? t("on {what}", { what: hardware.virtualization }) : undefined}
        />
      ),
      cores: (
        <Kpi icon="overview" label={t("CPU cores")} value={hardware?.cpu_cores ?? null} />
      ),
      adapters: (
        <Card
          title={t("What the panel can do here")}
          note={t("The adapters this host reported, and what each of them allows.")}
          foot={readOnly !== undefined && readOnly > 0 ? t("{n} of them read only.", { n: readOnly }) : undefined}
        >
          {adapters === undefined
            ? <Empty>{t("This host has not reported its adapters yet.")}</Empty>
            : (
              <>
                <Band segments={registry} testId="adapters" />
                {/* Which of them are missing, and the host's own sentence
                    for why. A reader who is told only that six are
                    unavailable has to open the registry to learn whether
                    any of them is one he wanted; the reason is also the
                    remedy - "this host has no Docker socket" says what to
                    install. */}
                {missing.length > 0 && (
                  <Reasons
                    testId="adapters-missing"
                    items={missing.map((one) => ({
                      name: one.name,
                      reason: one.reason,
                      to: adapterSegment(one.name) ? `/hosts/${host.id}/${adapterSegment(one.name)}` : undefined,
                    }))}
                  />
                )}
              </>
            )}
        </Card>
      ),
      attention: (
        <Card title={t("Needs attention")} note={t("Counted by the agent on its last report.")}>
          <Needs items={attention.map((one) => ({
            label: one.label,
            value: one.value ?? undefined,
            tone: one.tone,
            quiet: one.value === false || one.value === 0,
            to: one.to && one.value !== false && one.value !== 0 && one.value !== null && one.value !== undefined
              ? one.to
              : undefined,
          }))} />
        </Card>
      ),
      system: (
        <Card
          title={t("System")}
          foot={system.data
            ? t("Source: {source}, revision {revision}, observed {when}", {
                source: system.data.source,
                revision: system.data.revision.slice(0, 12),
                when: relativeTime(system.data.observed_at),
              })
            : undefined}
        >
          <Facts>
            <Fact label={t("Hostname")}>{host.hostname}</Fact>
            <Fact label={t("System")}>
              {host.os_distribution || host.os_family || <Pill tone="unknown">{t("unknown")}</Pill>}
              {host.os_version ? ` ${host.os_version}` : ""}
            </Fact>
            <Fact label={t("Architecture")}>{host.architecture || <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
            <Fact label={t("Agent")}>
              {host.agent_version || <Pill tone="unknown">{t("unknown")}</Pill>}
              {/* The release and, beside it, the commit the binary was built
                  from: the version names a release, the commit names the
                  sources, which matters once a package was rebuilt. */}
              {host.agent_build_commit && (
                <>
                  {" "}
                  <Tag title={t("Commit {commit}", { commit: host.agent_build_commit })}>
                    {host.agent_build_commit.slice(0, 12)}
                  </Tag>
                </>
              )}
            </Fact>
            {/* Whether the agent runs on the configuration file of the
                current schema or still on the environment file of the old
                flow. A host whose agent reported nothing is unknown, not
                legacy. */}
            <Fact label={t("Daemon config")}>
              {host.config_legacy === undefined
                ? <Pill tone="unknown">{t("unknown")}</Pill>
                : host.config_legacy
                  ? <Pill tone="warn">{t("Schema migration")}</Pill>
                  : <Pill tone="ok">{t("up to date")}</Pill>}
            </Fact>
            <Fact label={t("Machine ID")} mono>{host.machine_id}</Fact>
            <Fact label={t("Boot ID")} mono>{host.boot_id || "—"}</Fact>
            <Fact label={t("Package database")}>
              {host.package_database_broken
                ? <Pill tone="error">{t("needs repair")}</Pill>
                : <Pill tone="ok">{t("healthy")}</Pill>}
            </Fact>
            {/* The placement is edited here like the owner, but it is not a
                label: budgets, role scopes and group selectors key on it and
                none of them is re-evaluated by the move. */}
            <Fact label={t("Site / environment")}>
              <Placement host={host} editable={canEditFacts} decide={decide} />
            </Fact>
            {/* The team stands beside the placement because both answer
                "where does this host belong", and apart from the owner
                because it is the one that decides who may act on it. */}
            <Fact label={t("Team")}>
              <HostTeam host={host} editable={canMoveTeam} decide={decide} />
            </Fact>
            <Fact label={t("Owner")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                decide={decide}
                value={host.owner ?? ""}
                shown={host.owner ? <span>{host.owner}</span> : <Pill tone="unknown">{t("nobody")}</Pill>}
                label={t("Owner")}
                hint={t("Who answers for the host; empty hands it back to nobody.")}
                placeholder={t("platform team")}
                path="owner"
                field="owner"
                testId="owner"
              />
            </Fact>
            <Fact label={t("Management address")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                decide={decide}
                value={host.management_address_source === "manual" ? host.management_address ?? "" : ""}
                shown={host.management_address
                  ? (
                    <>
                      <span>{host.management_address}</span>
                      {" "}
                      <Tag title={t(addressSourceMeaning(host.management_address_source))}>
                        {host.management_address_source}
                      </Tag>
                    </>
                  )
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
                label={t("Management address")}
                hint={t("An IP address or a host name the panel reaches the host at. It replaces what the connection shows; empty forgets it and the observed address returns.")}
                placeholder="10.0.0.5"
                path="management-address"
                field="address"
                testId="management-address"
              />
            </Fact>
            {/* The domain is a budget key from the moment it is written: the
                next change on the host asks for a token of that domain next
                to the site's. Hence a fact set by hand, not a tag. */}
            <Fact label={t("Failure domain")}>
              <HostFact
                host={host}
                editable={canEditFacts}
                decide={decide}
                value={host.failure_domain ?? ""}
                shown={host.failure_domain ? <span>{host.failure_domain}</span> : <Pill tone="unknown">{t("not placed")}</Pill>}
                label={t("Failure domain")}
                hint={t("What the host goes down with: a rack, a zone, a cluster. Change budgets are keyed by it, so a campaign takes at most its share of one domain at a time; empty takes the host out from under the domain budgets.")}
                placeholder={t("rack-12, zone-b")}
                path="failure-domain"
                field="failure_domain"
                testId="failure-domain"
              />
            </Fact>
          </Facts>
          <RenameHost host={host} reported={system.data?.payload?.hostname} decide={decide} />
        </Card>
      ),
      hardware: (
        <Card title={t("Hardware")}>
          <Facts>
            <Fact label={t("CPU cores")}>{hardware?.cpu_cores ?? "—"}</Fact>
            <Fact label={t("Memory")}>
              {hardware?.memory_bytes === undefined ? "—" : bytes(hardware.memory_bytes)}
            </Fact>
            <Fact label={t("Virtualization")}>
              {hardware?.virtualization || <Pill tone="unknown">{t("unknown")}</Pill>}
            </Fact>
            <Fact label={t("Root filesystem")}>
              {root.share === undefined
                ? "—"
                : (
                  <Meter
                    share={root.share}
                    tone={root.tone}
                    text={t("{free} free of {total}", {
                      free: bytes((hardware?.root_fs_free_bytes ?? 0)),
                      total: bytes((hardware?.root_fs_bytes ?? 0)),
                    })}
                  />
                )}
            </Fact>
          </Facts>
        </Card>
      ),
      notes: (
        <Card
          title={t("Notes")}
          note={t("What an operator wrote about this host that fits no other field. Free text; every change goes to the audit trail with the previous text.")}
        >
          <HostNotes host={host} editable={canEditFacts} decide={decide} />
        </Card>
      ),
      lifecycle: (
        <Card
          title={t("Lifecycle")}
          note={t("Whether the panel trusts this host, restoring its identity, and ending that trust.")}
        >
          <Lifecycle host={host} decide={decide} />
        </Card>
      ),
      registry: (
        <Card
          title={t("Adapters")}
          note={t("What the panel can read and change on this host, and why it cannot where it cannot.")}
          flush
        >
          <Adapters host={host} />
        </Card>
      ),
      recent: (
        <Card
          title={t("Recent activity")}
          tools={<Link to={`/hosts/${host.id}/jobs`}>{t("All jobs")}</Link>}
          flush
        >
          <Table
            rows={jobs.data?.items ?? []}
            keyOf={(one) => one.id}
            loading={jobs.isLoading} empty={t("Nothing has been done to this host yet.")}
            columns={[
              { key: "when", head: t("Time"), cell: (one) => (
                <Link to={`/jobs/${one.id}`} title={absoluteTime(one.created_at)}>
                  {relativeTime(one.finished_at ?? one.created_at)}
                </Link>
              ) },
              { key: "what", head: t("Operation"), tight: true, cell: (one) => <code title={one.action_type}>{one.action_type}</code> },
              { key: "state", head: t("Outcome"), cell: (one) => (
                <Pill tone={jobTone(one.state)}>{t(stateName(one.state))}</Pill>
              ) },
              { key: "error", head: t("Error"), minor: true, tight: true, cell: (one) => (
                one.result_error_code
                  ? <code title={one.result_error_code}>{one.result_error_code}</code>
                  : "—"
              ) },
            ]}
          />
        </Card>
      ),
      timeline: (
        <Card
          title={t("History")}
          note={t("Tasks, audit entries, sessions, campaigns and alerts of this host, newest first.")}
          flush
        >
          <Timeline host={host} />
        </Card>
      ),
      }} />

      {pending && (
        <Confirm
          key={pending.intent.action}
          host={host}
          intent={pending.intent}
          busy={busy}
          onConfirm={(reason, confirmation) => { setBusy(true); pending.send(reason, confirmation); }}
          onCancel={decide.close}
        />
      )}
    </>
  );
}

/* ------------------------------------------------------------------ */

/** The sub-tabs of this screen, in the order a reader wants them. */
const OVERVIEW_TABS = ["summary", "system", "adapters", "lifecycle", "activity"] as const;
type OverviewTab = typeof OVERVIEW_TABS[number];

/**
 * One machine, in five readings rather than twelve containers.
 *
 * It was a board until 17.10, and the owner's words for the result were
 * that the things on it looked like blocks somebody had scattered round a
 * room. He was right, and the reason is worth keeping: a board arranges
 * containers of one shape well - a dashboard of tiles, a wall of charts -
 * and this screen has four shapes on it. A list of facts, a form, a band
 * and a table have nothing in common to line up, so the grid lines up
 * their corners and leaves the rest to chance.
 *
 * Sub-tabs instead. One reading at a time, the width of the page, each
 * section as tall as what is in it - no cell to fill and none to overrun,
 * which also ends the whole class of fault a fixed cell carries: measured
 * at one window width, 65 of the panel's containers changed height by
 * more than a line when the window changed.
 *
 * The three measurements stay above the tabs: they are one shape, they
 * are what a reader looks at first, and they are the same on every tab.
 */
function Readings({ panels }: { panels: Record<string, ReactNode> }) {
  const t = useT();
  const [address, setAddress] = useSearchParams();
  const asked = address.get("tab") ?? "";
  const tab: OverviewTab = (OVERVIEW_TABS as readonly string[]).includes(asked)
    ? asked as OverviewTab
    : "summary";
  const go = (next: OverviewTab) => {
    const after = new URLSearchParams(address);
    if (next === "summary") after.delete("tab"); else after.set("tab", next);
    setAddress(after, { replace: true });
  };
  return (
    <>
      <Grid>
        <C span={4}>{panels.disk}</C>
        <C span={4}>{panels.memory}</C>
        <C span={4}>{panels.cores}</C>
      </Grid>

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "summary", label: t("Summary") },
          { value: "system", label: t("System") },
          { value: "adapters", label: t("Adapters") },
          { value: "lifecycle", label: t("Lifecycle") },
          { value: "activity", label: t("Activity") },
        ]}
      />

      {tab === "summary" && (
        <Grid>
          <C span={7}>{panels.attention}</C>
          <C span={5}>{panels.notes}</C>
          <C span={12}>{panels.adapters}</C>
        </Grid>
      )}
      {/* Both take the width rather than standing side by side. One holds
          twelve facts and the other four, so a row would stretch the short
          one to the tall one's height and leave a third of it empty - the
          fault the owner kept pointing at. Full width, they flow into four
          columns and three rows, and each ends where its facts end. */}
      {tab === "system" && (
        <Grid>
          <C span={12}>{panels.system}</C>
          <C span={12}>{panels.hardware}</C>
        </Grid>
      )}
      {tab === "adapters" && <Grid><C span={12}>{panels.registry}</C></Grid>}
      {tab === "lifecycle" && <Grid><C span={12}>{panels.lifecycle}</C></Grid>}
      {tab === "activity" && (
        <Grid>
          <C span={12}>{panels.recent}</C>
          <C span={12}>{panels.timeline}</C>
        </Grid>
      )}
    </>
  );
}

/** What each origin of the management address means, for the chip. */
export function addressSourceMeaning(source: string | undefined): string {
  switch (source) {
    case "session": return "address seen by the control plane on its end of the connection";
    case "agent": return "address reported by the host itself; it connects through a relay";
    case "manual": return "address set manually by an operator";
    default: return "address source";
  }
}

/* ------------------------------------------------------- what is written */

/**
 * One write of what the panel records about a host.
 *
 * The entity tag comes from a fresh read rather than from the cached host:
 * the cache may be a heartbeat old, and the tag has to name the version the
 * editor is showing. Without a tag the write goes out unconditional, as a
 * script would; the server still records who changed what.
 */
function useFactWrite(host: Host, path: string) {
  const t = useT();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");
  const [etag, setEtag] = useState("");

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.put<Host>(`/api/v1/hosts/${host.id}/${path}`, body, { headers: etag ? { "If-Match": etag } : {} }),
    onSuccess: () => {
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["fleet-activity"] });
    },
    onError: (error) => setMessage(writeRefusal(t, error)),
  });

  const readTag = async () => {
    try {
      setEtag((await api.getWithMeta<Host>(`/api/v1/hosts/${host.id}`)).etag);
    } catch {
      setEtag("");
    }
  };

  return { save, message, setMessage, readTag };
}

/**
 * A hand-recorded fact of the host, shown with an editor in place and
 * written only once the decision has been confirmed.
 */
function HostFact({ host, editable, decide, value, shown, label, hint, placeholder, path, field, testId }: {
  host: Host;
  editable: boolean;
  decide: Decide;
  /** The value the editor starts from. */
  value: string;
  /** The fact as the card shows it when nobody is editing. */
  shown: ReactNode;
  label: string;
  hint: string;
  placeholder: string;
  /** The last segment of the PUT address under /api/v1/hosts/{id}/. */
  path: "owner" | "management-address" | "failure-domain";
  /** The name of the value in the request body. */
  field: "owner" | "address" | "failure_domain";
  testId: string;
}) {
  const t = useT();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const write = useFactWrite(host, path);

  const open = () => {
    setDraft(value);
    write.setMessage("");
    setEditing(true);
    void write.readTag();
  };

  const confirm = () => decide.ask(
    {
      action: `host.${field}`,
      label: t("Save {label}", { label }),
      payload: {},
      description: draft.trim() === ""
        ? t("{label} is cleared on {host}. The previous value is kept in the audit trail.", { label, host: host.hostname })
        : t("{label} of {host} becomes {value}. The previous value is kept in the audit trail.", { label, host: host.hostname, value: draft.trim() }),
    },
    (reason) => write.save.mutate(
      { [field]: draft.trim(), reason },
      {
        onSuccess: () => { decide.close(); setEditing(false); },
        onError: () => decide.close(),
      },
    ),
  );

  if (!editing) {
    return (
      <span data-testid={`fact-${testId}`}>
        {shown}
        {editable && (
          <>
            {" "}
            <Button kind="word" testId={`edit-${testId}`} onClick={open}>{t("edit")}</Button>
          </>
        )}
        {write.message && <Note>{write.message}</Note>}
      </span>
    );
  }
  return (
    <span data-testid={`fact-${testId}`}>
      <Fields>
        <Field label={label} hint={hint} wide>
          <input
            value={draft}
            placeholder={placeholder}
            onChange={(event) => setDraft(event.target.value)}
            data-testid={`input-${testId}`}
          />
        </Field>
      </Fields>
      <Actions>
        <Button testId={`save-${testId}`} onClick={confirm} disabled={draft.trim() === value.trim()}>{t("Save…")}</Button>
        <Button kind="quiet" onClick={() => setEditing(false)}>{t("Cancel")}</Button>
      </Actions>
      {write.message && <Note>{write.message}</Note>}
    </span>
  );
}

/**
 * The notes of the host, shown whole and edited in place.
 */
function HostNotes({ host, editable, decide }: { host: Host; editable: boolean; decide: Decide }) {
  const t = useT();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const write = useFactWrite(host, "notes");
  // The notes ride on the host view; a host nobody wrote about has none.
  const notes = (host as Host & { notes?: string }).notes ?? "";

  const open = () => {
    setDraft(notes);
    write.setMessage("");
    setEditing(true);
    void write.readTag();
  };

  const tooLong = draft.length > MAX_NOTES_LENGTH;
  const changed = draft.trim() !== notes;

  const confirm = () => decide.ask(
    {
      action: "host.notes",
      label: t("Save the note"),
      payload: {},
      description: draft.trim() === ""
        ? t("The note on {host} is cleared. The text it had is kept in the audit trail.", { host: host.hostname })
        : t("The note on {host} is replaced. The text it had is kept in the audit trail.", { host: host.hostname }),
    },
    (reason) => write.save.mutate(
      { notes: draft, reason },
      {
        onSuccess: () => { decide.close(); setEditing(false); },
        onError: () => decide.close(),
      },
    ),
  );

  if (!editing) {
    return (
      <div data-testid="fact-notes">
        {notes ? <p>{notes}</p> : <Empty icon="audit">{t("Nobody has written anything about this host.")}</Empty>}
        {editable && (
          <Actions>
            <Button kind="word" testId="edit-notes" onClick={open}>
              {notes ? t("edit") : t("write a note")}
            </Button>
          </Actions>
        )}
        {write.message && <Note>{write.message}</Note>}
      </div>
    );
  }
  return (
    <div data-testid="fact-notes">
      <Fields>
        <Field
          label={t("Notes")}
          hint={tooLong
            ? t("At most {max} characters; {n} typed.", { max: MAX_NOTES_LENGTH, n: draft.length })
            : t("Free text, at most {max} characters; empty clears the notes.", { max: MAX_NOTES_LENGTH })}
          wide
        >
          <textarea
            rows={6}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            aria-invalid={tooLong}
            data-testid="input-notes"
          />
        </Field>
      </Fields>
      <Actions>
        <Button testId="save-notes" onClick={confirm} disabled={tooLong || !changed}>{t("Save…")}</Button>
        <Button kind="quiet" onClick={() => setEditing(false)}>{t("Cancel")}</Button>
      </Actions>
      {write.message && <Note>{write.message}</Note>}
    </div>
  );
}

/**
 * The placement of the host - its site and its environment - edited in
 * place. It is where the host stands, and the budgets, the role scopes and
 * the group selectors all key on it.
 */
function Placement({ host, editable, decide }: { host: Host; editable: boolean; decide: Decide }) {
  const t = useT();
  const [editing, setEditing] = useState(false);
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const write = useFactWrite(host, "placement");
  // The facets are the fleet's own values: a hint under the field, not a
  // boundary - a site with no host yet is a placement like any other.
  const facets = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    staleTime: 60_000,
    enabled: editing,
  });
  const movedAt = host.placement_changed_at;

  const open = () => {
    setSite(host.site);
    setEnvironment(host.environment);
    write.setMessage("");
    setEditing(true);
    void write.readTag();
  };

  const moves = site.trim() !== "" && environment.trim() !== ""
    && (site.trim() !== host.site || environment.trim() !== host.environment);

  const confirm = () => decide.ask(
    {
      action: "host.placement",
      label: t("Move host"),
      payload: {},
      description: t("{host} is recorded as standing in {site} / {environment}. Groups that select on the site or the environment take the host in or let it go at their next read; nothing already planned is re-evaluated.", {
        host: host.hostname, site: site.trim(), environment: environment.trim(),
      }),
    },
    (reason) => write.save.mutate(
      { site: site.trim(), environment: environment.trim(), reason },
      {
        onSuccess: () => { decide.close(); setEditing(false); },
        onError: () => decide.close(),
      },
    ),
  );

  if (!editing) {
    return (
      <span data-testid="fact-placement">
        <span>{host.site} / {host.environment}</span>
        {movedAt && (
          <>
            {" "}
            <Tag title={t("When an operator last moved the host to another site or environment.")}>
              {t("moved {when}", { when: relativeTime(movedAt) })}
            </Tag>
          </>
        )}
        {editable && (
          <>
            {" "}
            <Button kind="word" testId="edit-placement" onClick={open}>{t("edit")}</Button>
          </>
        )}
        {write.message && <Note>{write.message}</Note>}
      </span>
    );
  }
  return (
    <span data-testid="fact-placement">
      <Fields>
        <Field
          label={t("Site")}
          hint={t("Where the host stands. The site keys the site budgets and the scope of every role; a running campaign keeps the capacity it was planned with.")}
          wide
        >
          <input
            value={site}
            list="next-placement-sites"
            onChange={(event) => setSite(event.target.value)}
            data-testid="input-site"
          />
          <datalist id="next-placement-sites">
            {(facets.data?.by_site ?? []).map((one) => <option key={one.key} value={one.key} />)}
          </datalist>
        </Field>
        <Field
          label={t("Environment")}
          hint={t("What the host serves. The environment decides who may change the host and whether a change needs a second person, from the next order on.")}
          wide
        >
          <input
            value={environment}
            list="next-placement-environments"
            onChange={(event) => setEnvironment(event.target.value)}
            data-testid="input-environment"
          />
          <datalist id="next-placement-environments">
            {(facets.data?.by_environment ?? []).map((one) => <option key={one.key} value={one.key} />)}
          </datalist>
        </Field>
      </Fields>
      <Actions>
        <Button testId="save-placement" onClick={confirm} disabled={!moves}>{t("Move…")}</Button>
        <Button kind="quiet" onClick={() => setEditing(false)}>{t("Cancel")}</Button>
      </Actions>
      {write.message && <Note>{write.message}</Note>}
    </span>
  );
}

/** The team of the host, and the move between teams. */
function HostTeam({ host, editable, decide }: { host: Host; editable: boolean; decide: Decide }) {
  const t = useT();
  const [editing, setEditing] = useState(false);
  const [team, setTeam] = useState("");
  const write = useFactWrite(host, "team");
  const placement = host as Host & { team_id?: string; team_name?: string };
  const teams = useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<{ id: string; name: string }>>("/api/v1/teams"),
    staleTime: 60 * 1000,
    retry: false,
    enabled: editing,
  });

  const open = () => {
    setTeam(placement.team_id ?? "");
    write.setMessage("");
    setEditing(true);
  };

  // Nothing moves when the team is the one the host is already in, so the
  // button stays shut rather than placing a write the server would answer
  // with the host unchanged.
  const changed = team !== (placement.team_id ?? "");
  const named = (teams.data?.items ?? []).find((one) => one.id === team)?.name ?? t("no team");

  const confirm = () => decide.ask(
    {
      action: "host.team",
      label: t("Move host to another team"),
      payload: {},
      description: t("{host} is handed to {team}. From the next request, the operators of the new team may see and change it, and the operators of the old team may not. Work already under way keeps the targets it was planned with.", {
        host: host.hostname, team: named,
      }),
    },
    (reason) => write.save.mutate(
      { team, reason },
      {
        onSuccess: () => { decide.close(); setEditing(false); },
        onError: () => decide.close(),
      },
    ),
  );

  if (!editing) {
    return (
      <span data-testid="fact-team">
        {placement.team_name
          ? <span>{placement.team_name}</span>
          : (
            <Pill tone="unknown" title={t("Nobody has placed this host in a team; it is reachable through its site alone.")}>
              {t("no team")}
            </Pill>
          )}
        {editable && (
          <>
            {" "}
            <Button kind="word" testId="edit-team" onClick={open}>{t("move")}</Button>
          </>
        )}
        {write.message && <Note>{write.message}</Note>}
      </span>
    );
  }
  return (
    <span data-testid="fact-team">
      <Fields>
        <Field
          label={t("Team")}
          hint={t("The group of people this host belongs to. A team is a boundary of authority, not a label: the hosts of a team are named by the role bindings that name the team.")}
          wide
        >
          <select value={team} onChange={(event) => setTeam(event.target.value)} data-testid="input-team">
            <option value="">{t("no team")}</option>
            {(teams.data?.items ?? []).map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
          </select>
        </Field>
      </Fields>
      <Actions>
        <Button testId="save-team" onClick={confirm} disabled={!changed}>{t("Move…")}</Button>
        <Button kind="quiet" onClick={() => setEditing(false)}>{t("Cancel")}</Button>
      </Actions>
      {write.message && <Note>{write.message}</Note>}
    </span>
  );
}

/**
 * A rename as an order, composed by the operation registry: this screen and
 * the Bulk workspace then send one payload and refuse one set of names.
 */
export function renameOrder(hostname: string, pretty: string): RegistryOrder {
  return registryOrder("system.hostname.set", { hostname, pretty });
}

/** Renaming the host. */
function RenameHost({ host, reported, decide }: { host: Host; reported?: string; decide: Decide }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [hostname, setHostname] = useState("");
  const [pretty, setPretty] = useState("");
  const order = useOrder(host, () => { decide.close(); setOpen(false); });

  const name = hostname.trim();
  const composed = renameOrder(hostname, pretty);
  const refusal = refusalOf(t, composed);
  // The host already carrying the name is this screen's own refusal: the
  // registry compares the form with itself, not with the host.
  const unchanged = name === host.hostname;

  const confirm = () => decide.ask(
    {
      action: "system.hostname.set",
      label: t("Rename host"),
      danger: true,
      description: t("{host} will be renamed to {name}. Every system that knows it by the old name loses it at once; the panel keeps it by identifier.", { host: host.hostname, name }),
      payload: composed.payload,
    },
    (reason, confirmation) => order.request.mutate(
      { action: "system.hostname.set", reason, target_confirmation: confirmation, payload: composed.payload },
      { onError: () => decide.close() },
    ),
  );

  return (
    <>
      {/* The name the host reports for itself, when the panel's differs: the
          host was renamed by hand, or a rename is on its way. */}
      {reported && reported !== host.hostname && (
        <Note>{t("The host reports the name {name}; the panel will follow at the next inventory.", { name: reported })}</Note>
      )}
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {order.job && <JobLine job={order.job} hostID={host.id} />}
      {/* The trigger and the form stand behind the preview together: a
          rename nobody may order has no form to fill in either. */}
      <Guard action="system.hostname.set" host={host.id} explain>
        {!open ? (
          <Actions>
            <Button
              kind="quiet"
              testId="rename-open"
              onClick={() => setOpen(true)}
              disabled={host.connection_state !== "online"}
              title={host.connection_state !== "online" ? t("the host is not connected") : undefined}
            >
              {t("Rename host")}
            </Button>
          </Actions>
        ) : (
          <>
            <Fields>
              <Field label={t("New hostname")} hint={t("An RFC 1123 name, lower-case: a label or a fully qualified name.")} wide>
                <input
                  value={hostname}
                  placeholder="web02.example.internal"
                  onChange={(event) => setHostname(event.target.value)}
                  data-testid="rename-hostname"
                />
              </Field>
              <Field label={t("Pretty name")} hint={t("Optional; what hostnamectl shows to people.")} wide>
                <input value={pretty} placeholder="Web 02" onChange={(event) => setPretty(event.target.value)} />
              </Field>
            </Fields>
            {name !== "" && refusal !== "" && <Note>{refusal}</Note>}
            {unchanged && name !== "" && <Note>{t("The host already has this name.")}</Note>}
            <Note>
              {t("The host checks first whether the name resolves in DNS to another machine and whether the agent's certificate is bound to the name. /etc/hosts follows the rename; DNS, Kerberos and service certificates do not.")}
            </Note>
            <Actions>
              <Button kind="danger" testId="rename" onClick={confirm} disabled={!orderReady(composed) || unchanged}>
                {t("Rename host…")}
              </Button>
              <Button kind="quiet" onClick={() => setOpen(false)}>{t("Cancel")}</Button>
            </Actions>
          </>
        )}
      </Guard>
    </>
  );
}

/* ----------------------------------------------------------- lifecycle */

/** What a state means for the operator reading the host. */
export function lifecycleMeaning(t: Translate, state: string): string {
  switch (state) {
    case "active": return t("The host takes operations and secrets, and renews its certificate.");
    case "quarantined": return t("The host is cut off: no operations, no secrets, no session. Release it once the incident is assessed.");
    case "recovery": return t("An identity recovery is under way: no operations and no secrets until the new certificate opens its first session. The old certificate may still connect for a day, so the host can be read.");
    case "retiring": return t("The host is being decommissioned: the panel is waiting for it to finish its work.");
    case "retired": return t("The trust in this host has ended. It does not come back; its record and history stay.");
    default: return "";
  }
}

/** The state of the host as a colour: which kind of "no" it is. */
export function lifecycleTone(state: string): Tone {
  switch (state) {
    case "active": return "ok";
    case "quarantined": return "warn";
    // A recovery and a retirement under way are both a host the panel is
    // waiting on: not cut off for good, not working either.
    case "recovery":
    case "retiring": return "warn";
    case "retired": return "unknown";
    // A refused or failed attempt carries its outcome in place of a state.
    case "denied":
    case "failure": return "error";
    default: return "neutral";
  }
}

/**
 * The lifecycle of the host: the state with the decision behind it, the
 * recovery of its identity, and the one change that cannot be undone.
 */
function Lifecycle({ host, decide }: { host: Host; decide: Decide }) {
  const t = useT();
  // The outcome lives here rather than in the form: the form goes away once
  // the host is retired, and the answer - above all an unconfirmed cleanup -
  // has to stay on screen after that.
  const [outcome, setOutcome] = useState<DecommissionOutcome | null>(null);
  const refusal = host.connection_state !== "online" ? host.last_connection_refusal : undefined;
  const alive = host.lifecycle_state !== "retired" && host.lifecycle_state !== "retiring";
  return (
    <>
      <Facts>
        <Fact label={t("State")}>
          <Pill tone={lifecycleTone(host.lifecycle_state)}>{t(host.lifecycle_state)}</Pill>
        </Fact>
        {/* A host whose state never changed has been in it since it was
            enrolled; a dash there would read as "nobody knows". */}
        <Fact label={t("Since")}>
          {host.lifecycle_changed_at
            ? <span title={absoluteTime(host.lifecycle_changed_at)}>{relativeTime(host.lifecycle_changed_at)}</span>
            : (
              <span title={absoluteTime(host.enrolled_at)}>
                {t("{when} · since enrollment", { when: relativeTime(host.enrolled_at) })}
              </span>
            )}
        </Fact>
        <Fact label={t("Decided by")}>{host.lifecycle_changed_by || "—"}</Fact>
        <Fact label={t("Reason")}>{host.lifecycle_reason || "—"}</Fact>
        <Fact label={t("Enrolled")}>
          <span title={absoluteTime(host.enrolled_at)}>{relativeTime(host.enrolled_at)}</span>
        </Fact>
        <Fact label={t("Last seen")}>
          {host.last_seen_at
            ? <span title={absoluteTime(host.last_seen_at)}>{relativeTime(host.last_seen_at)}</span>
            : t("never")}
        </Fact>
        <Fact label={t("Release channel")}>{host.release_channel}</Fact>
        {host.maintenance && (
          <Fact label={t("Maintenance until")}>
            <span title={absoluteTime(host.maintenance.until)}>{relativeTime(host.maintenance.until)}</span>
          </Fact>
        )}
        <Fact label={t("Meaning")}>{lifecycleMeaning(t, host.lifecycle_state)}</Fact>
      </Facts>
      {/* The three decisions stand side by side. Each used to be a block
          of its own, so their buttons came out one under another with
          half a 4K screen free beside them - a column of three buttons
          reads as a list of steps, which these are not. */}
      <Row>
        {alive && <Quarantine host={host} decide={decide} />}
        {alive && (
          <IdentityRecovery
            host={host}
            prompted={Boolean(refusal) && RECOVERABLE_REFUSALS.includes(refusal?.code ?? "")}
            decide={decide}
          />
        )}
        {host.lifecycle_state !== "retired" && <Decommission host={host} decide={decide} onDone={setOutcome} />}
      </Row>
      {outcome && <DecommissionResult outcome={outcome} />}
    </>
  );
}

/** Why the host is not connected, when the gateway is the one that said no. */
function ConnectionRefusal({ host }: { host: Host }) {
  const t = useT();
  const refusal = host.last_connection_refusal;
  if (!refusal) return null;
  const remedy = RECOVERABLE_REFUSALS.includes(refusal.code)
    ? t("The agent on the host is alive and connecting, but the gateway will not take its certificate. Order an identity recovery and run the recovery on the host; nothing else brings it back.")
    : refusal.code === "certificate_not_yet_valid"
      ? t("The certificate is from the future: the clock of the host or of the panel is wrong. Fix the time; the agent reconnects on its own.")
      : refusal.code.startsWith("lifecycle_")
        ? t("The host is kept out by its lifecycle state, a decision recorded on this screen, not by a fault of its own.")
        : t("The certificate is on record for another host. Check which machine holds this identity before anything else.");
  return (
    <Banner tone="error">
      <span data-testid="connection-refusal">
        {t("Connection refused: {reason} {when}.", {
          reason: t(refusalName(refusal.code)),
          when: relativeTime(refusal.at),
        })}
        {" "}
        {remedy}
        {refusal.detail ? ` ${refusal.detail}` : ""}
      </span>
    </Banner>
  );
}

/** What a lifecycle order answered with. */
type LifecycleResult = { lifecycle_state: string; jobs_canceled?: number; certificates_revoked?: number };

/** Cutting the host off and letting it back in. */
function Quarantine({ host, decide }: { host: Host; decide: Decide }) {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const quarantined = host.lifecycle_state === "quarantined";
  const mayQuarantine = permissions.has("host.quarantine") && !quarantined;
  const mayRelease = permissions.has("host.quarantine.release") && quarantined;
  const [open, setOpen] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [message, setMessage] = useState("");
  const [signInAgain, setSignInAgain] = useState(false);

  const request = useMutation({
    mutationFn: ({ path, body }: { path: string; body: Record<string, unknown> }) =>
      api.post<LifecycleResult>(`/api/v1/hosts/${host.id}/${path}`, body),
    onSuccess: (result) => {
      setMessage(result.lifecycle_state === "quarantined"
        ? t("The host is quarantined: {jobs} job(s) cancelled, {certificates} certificate(s) revoked.", {
            jobs: result.jobs_canceled ?? 0, certificates: result.certificates_revoked ?? 0,
          })
        : t("The host is released; the agent reconnects on its own."));
      setSignInAgain(false);
      setOpen(false);
      decide.close();
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["host-timeline", host.id] });
    },
    onError: (error) => {
      decide.close();
      // A stale authentication is a sign-in that comes back here, not a
      // failure of the order.
      setSignInAgain(error instanceof ApiError && error.unauthenticated);
      setMessage(writeRefusal(t, error));
    },
  });

  if (!mayQuarantine && !mayRelease) return null;

  const askQuarantine = () => decide.ask(
    {
      action: "host.quarantine",
      label: t("Quarantine host"),
      payload: {},
      danger: true,
      description: t("{host} is cut off from the fleet at once: no session, no operations, no secrets, until somebody releases it.", { host: host.hostname }),
    },
    (reason, confirmation) => request.mutate({
      path: "quarantine",
      body: { reason, revoke_certificates: revoke, typed_confirmation: confirmation },
    }),
  );

  const askRelease = () => decide.ask(
    {
      action: "host.quarantine.release",
      label: t("Release from quarantine"),
      payload: {},
      description: t("{host} returns to the fleet: the agent reconnects on its own and the host takes operations again. Under a duplicate identity, wipe or reinstall the other machine first, or the release produces the next duplicate.", { host: host.hostname }),
    },
    (reason, confirmation) => request.mutate({
      path: "quarantine/release",
      body: { reason, typed_confirmation: confirmation },
    }),
  );

  return (
    <div data-testid="quarantine-controls">
      {/* The permission list of the session, checked above, is the first
          gate; the preview of the host's actions judges in the scope of the
          host and in its lifecycle state, and is the second. */}
      {mayRelease && (
        <Guard action="host.quarantine.release" host={host.id} explain>
          <Actions>
            <Button testId="release" onClick={askRelease}>{t("Release from quarantine…")}</Button>
          </Actions>
        </Guard>
      )}
      {mayQuarantine && !open && (
        <Guard action="host.quarantine" host={host.id} explain>
          <Actions>
            <Button kind="danger" testId="quarantine-open" onClick={() => setOpen(true)}>{t("Quarantine host…")}</Button>
          </Actions>
        </Guard>
      )}
      {mayQuarantine && open && (
        <Guard action="host.quarantine" host={host.id} explain>
          <Check checked={revoke} onChange={setRevoke}>
            {t("Revoke the certificates as well (suspected key theft)")}
          </Check>
          <Note>
            {revoke
              ? t("The certificates stop working now. A host with revoked certificates is not released: its return is an identity recovery.")
              : t("The certificates stay valid; the lifecycle state alone keeps the host out, and a release lets it back in.")}
          </Note>
          <Note>
            {t("The session is closed, the undelivered jobs are cancelled, and the host takes no operations and no secrets. A task already delivered runs to its end; the panel cannot undo it.")}
          </Note>
          <Actions>
            <Button kind="danger" testId="quarantine" onClick={askQuarantine}>{t("Quarantine host…")}</Button>
            <Button kind="quiet" onClick={() => setOpen(false)}>{t("Cancel")}</Button>
          </Actions>
        </Guard>
      )}
      {message && <Note>{message}</Note>}
      {signInAgain && (
        <Actions>
          <Button
            kind="quiet"
            testId="sign-in-again"
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </Button>
        </Actions>
      )}
    </div>
  );
}

/** The recovery order as it comes back: the token exists only in this answer. */
type RecoveryOrder = EnrollmentOrder & { token?: string };

/** Ordering an identity recovery. */
function IdentityRecovery({ host, prompted, decide }: { host: Host; prompted: boolean; decide: Decide }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [revokeOld, setRevokeOld] = useState(false);
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
      setOpen(false);
      decide.close();
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      decide.close();
      setSignInAgain(error instanceof ApiError && error.unauthenticated);
      setMessage(writeRefusal(t, error));
    },
  });

  const confirm = () => decide.ask(
    {
      action: "host.identity-recovery",
      label: t("Order identity recovery"),
      payload: {},
      description: t("{host} gets a one-time token for a new key and certificate; its record and history stay. Until the new certificate connects, the host takes no operations.", { host: host.hostname }),
    },
    (reason) => request.mutate({ reason, description: reason, revoke_old_immediately: revokeOld }),
  );

  return (
    <div data-testid="identity-recovery">
      {order && <RecoveryResult host={host} order={order} />}
      {!open ? (
        <Actions>
          <Button
            kind={prompted ? "do" : "quiet"}
            testId="recovery-open"
            onClick={() => setOpen(true)}
          >
            {t("Order identity recovery…")}
          </Button>
        </Actions>
      ) : (
        <>
          <Check checked={revokeOld} onChange={setRevokeOld}>
            {t("Revoke the old certificate at once (suspected key theft)")}
          </Check>
          <Note>
            {revokeOld
              ? t("The old certificate stops working now: the host loses its session and cannot come back until the recovery is run on it.")
              : t("The old certificate stays valid for a day, so the host can still be read; it is revoked when the new one opens its first session.")}
          </Note>
          <Note>
            {t("The host enters recovery: no operations and no secrets until the new certificate has proven it works. The token is shown once and fits this host alone.")}
          </Note>
          <Actions>
            <Button testId="recovery" onClick={confirm}>{t("Order identity recovery…")}</Button>
            <Button kind="quiet" onClick={() => setOpen(false)}>{t("Cancel")}</Button>
          </Actions>
        </>
      )}
      {message && <Note>{message}</Note>}
      {signInAgain && (
        <Actions>
          <Button
            kind="quiet"
            testId="recovery-sign-in-again"
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </Button>
        </Actions>
      )}
    </div>
  );
}

/** The recovery order and what to do with it on the host. */
function RecoveryResult({ host, order }: { host: Host; order: RecoveryOrder }) {
  const t = useT();
  return (
    <div data-testid="recovery-order">
      <Banner tone={order.token ? "ok" : "info"}>
        {order.token
          ? t("The recovery order is placed. Run the command below on the host as root and paste the token when asked.")
          : t("A recovery order for this host is already open; its token was shown when it was placed.")}
      </Banner>
      <Readout
        label={t("On the host")}
        value={`flotestro-agentctl identity reset --confirm ${host.hostname}`}
        testId="recovery-command"
      />
      {order.token && (
        <Readout label={t("Token (shown once)")} value={order.token} testId="recovery-token" />
      )}
      <Facts>
        <Fact label={t("Expires")}>
          <span title={absoluteTime(order.expires_at)}>{relativeTime(order.expires_at)}</span>
        </Fact>
        <Fact label={t("Order")}><Link to="/hosts/new">{order.id.slice(0, 8)}</Link></Fact>
      </Facts>
    </div>
  );
}

/**
 * Decommissioning the host. The end of trust, not the end of history: the
 * record, the inventory and the audit trail stay.
 */
function Decommission({ host, decide, onDone }: {
  host: Host;
  decide: Decide;
  onDone: (outcome: DecommissionOutcome) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [wipe, setWipe] = useState(true);
  const [revokeOffline, setRevokeOffline] = useState(true);
  const [message, setMessage] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<DecommissionOutcome>(`/api/v1/hosts/${host.id}/decommission`, body),
    onSuccess: (result) => {
      onDone(result);
      setMessage("");
      setOpen(false);
      decide.close();
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      decide.close();
      setMessage(writeRefusal(t, error));
    },
  });

  const online = host.connection_state === "online";

  const confirm = () => decide.ask(
    {
      action: "host.decommission",
      label: t("Decommission host"),
      payload: {},
      danger: true,
      description: t("{host} leaves the fleet for good. Its certificates are revoked and nothing brings it back but a new enrollment as a new host.", { host: host.hostname }),
    },
    (reason, confirmation) => request.mutate({
      reason,
      typed_confirmation: confirmation,
      local_identity_wipe: wipe,
      revoke_immediately_if_offline: revokeOffline,
    }),
  );

  return (
    <div data-testid="decommission-controls">
      {/* The trigger and the form stand behind the preview together: the
          server judges the permission in the host's scope and the state the
          host is in. */}
      <Guard action="host.decommission" host={host.id} explain>
        {!open ? (
          <Actions>
            <Button kind="danger" testId="decommission-open" onClick={() => setOpen(true)}>
              {t("Decommission host…")}
            </Button>
          </Actions>
        ) : (
          <>
            <Check checked={wipe} onChange={setWipe}>
              {t("Wipe the identity and the journal on the host and disable its agent service")}
            </Check>
            <Check checked={revokeOffline} onChange={setRevokeOffline}>
              {t("Revoke the certificates at once if the host is offline")}
            </Check>
            <Note>
              {online
                ? t("The host is connected: it will finish the operations under way, drop its secret leases and report it is ready; then its certificates are revoked and, with the wipe, its identity removed. The panel waits up to two minutes for the answer.")
                : t("The host is not connected: it is retired without its cooperation. Its certificates are revoked now, or at its first contact when the box above is cleared. What is on its disk stays unknown until somebody wipes it out of band.")}
            </Note>
            <Note>
              {t("The record, the inventory and the audit trail stay. A retired host does not come back; its machine is refused for a new-host token for 30 days.")}
            </Note>
            <Actions>
              <Button kind="danger" testId="decommission" onClick={confirm}>{t("Decommission host…")}</Button>
              <Button kind="quiet" onClick={() => setOpen(false)}>{t("Cancel")}</Button>
            </Actions>
          </>
        )}
      </Guard>
      {message && <Note>{message}</Note>}
    </div>
  );
}

/** What the decommission ended with. */
function DecommissionResult({ outcome }: { outcome: DecommissionOutcome }) {
  const t = useT();
  return (
    <div data-testid="decommission-result">
      <Banner tone={outcome.remote_cleanup_unconfirmed ? "error" : "ok"}>
        {outcome.remote_cleanup_unconfirmed
          ? outcome.phase === "no_session"
            ? t("The host is retired, but it had no session: nothing on the machine confirmed a wipe. Its identity files may still be there - wipe it out of band before it is handed over.")
            : t("The host is retired, but it did not answer the final task in time: nothing on the machine confirmed a wipe. Its identity files may still be there - check it out of band.")
          : t("The host is retired. It reported it stopped, its certificates were revoked and it was told to wipe its identity.")}
      </Banner>
      <Facts>
        <Fact label={t("Certificates revoked")}>{outcome.certificates_revoked}</Fact>
        <Fact label={t("Jobs cancelled")}>{outcome.jobs_canceled}</Fact>
        <Fact label={t("Secret leases dropped")}>{outcome.leases_dropped ? t("yes") : t("not confirmed")}</Fact>
        <Fact label={t("Operations cut short")}>
          {outcome.running_tasks.length === 0
            ? t("none")
            : <Tags>{outcome.running_tasks.map((id) => <Tag key={id}>{id.slice(0, 8)}</Tag>)}</Tags>}
        </Fact>
      </Facts>
    </div>
  );
}

/* --------------------------------------------------------- what is read */

/**
 * The page an adapter serves, by the adapter's name: the row of the
 * registry leads there.
 */
export function adapterSegment(name: string): string | undefined {
  const bySegment: Record<string, string> = {
    backup: "backups", certificates: "certificates", "certificates.renew": "certificates",
    dns: "dns", docker: "containers", "docker.compose": "compose", "files.managed": "files",
    firewall: "firewall", journald: "logs", kernel: "kernel", monitoring: "monitoring",
    network: "network", schedules: "schedules", security: "security", sshd: "ssh",
    storage: "storage", systemd: "services", time: "time",
  };
  if (bySegment[name]) return bySegment[name];
  if (name.startsWith("packages.")) return "packages";
  return undefined;
}

/**
 * The host's adapter registry. The operator sees not only what is missing
 * but also why - the reason comes from the host, not from browser code.
 */
function Adapters({ host }: { host: Host }) {
  const t = useT();
  const adapters = host.capabilities ?? [];
  return (
    <Table
      rows={adapters}
      keyOf={(one) => one.name}
      testId="adapter-registry"
      empty={t("This host has not reported its adapters yet.")}
      columns={[
        { key: "name", head: t("Adapter"), tight: true, cell: (one) => {
          const segment = adapterSegment(one.name);
          return segment
            ? <Link to={`/hosts/${host.id}/${segment}`}>{one.name}</Link>
            : one.name;
        } },
        { key: "state", head: t("State"), cell: (one) => (
          !one.available
            ? <Pill tone="neutral">{t("unavailable")}</Pill>
            : one.read_only
              ? <Pill tone="warn">{t("read only")}</Pill>
              : <Pill tone="ok">{t("available")}</Pill>
        ) },
        { key: "features", head: t("Features"), minor: true, cell: (one) => {
          const features = Object.entries(one.features ?? {});
          return features.length === 0
            ? "—"
            : features.map(([name, present]) => `${name}: ${present ? t("yes") : t("no")}`).join(", ");
        } },
        { key: "reason", head: t("Reason"), minor: true, cell: (one) => one.reason || "—" },
      ]}
    />
  );
}

/** The name of a kind of record, as the row says it. */
export function kindName(kind: HostTimelineKind): string {
  const names: Record<HostTimelineKind, string> = {
    job: "task", audit: "audit", session: "session", lifecycle: "lifecycle", alert: "alert", campaign: "campaign",
  };
  return names[kind];
}

/** Where a row of the timeline leads, inside the new panel. */
export function timelineLink(host: Host, item: HostTimelineItem): string | undefined {
  switch (item.kind) {
    // The task has a screen of its own with its attempts and its result.
    case "job": return item.ref.type === "job" && item.ref.id
      ? `/jobs/${item.ref.id}`
      : `/hosts/${host.id}/jobs`;
    case "audit":
    case "lifecycle": return `/hosts/${host.id}/audit`;
    case "alert": return `/hosts/${host.id}/monitoring`;
    case "campaign": return `/campaigns/${item.ref.id}`;
    default: return undefined;
  }
}

/** The colour of one record's state, by what the state means there. */
function timelineTone(item: HostTimelineItem): Tone {
  switch (item.kind) {
    case "job":
    case "campaign": return jobTone(item.state ?? "");
    case "audit": return item.state === "success" ? "ok" : "error";
    case "lifecycle": return lifecycleTone(item.state ?? "");
    case "alert": return item.state === "firing" ? "error" : "ok";
    case "session": return item.state === "open" ? "ok" : "neutral";
    default: return "neutral";
  }
}

/**
 * The history of the host from every record the panel keeps, lined up by
 * time. Every row is one record of one table - nothing is derived here -
 * and the row leads to the screen of that record.
 */
function Timeline({ host }: { host: Host }) {
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
  const kinds: HostTimelineKind[] = ["job", "audit", "session", "lifecycle", "alert", "campaign"];
  const hidden = timeline.data ? kinds.filter((kind) => !sources.includes(kind)) : [];

  if (timeline.error) return <Note>{String(timeline.error)}</Note>;
  return (
    <>
      <Table
        rows={items}
        keyOf={(one) => `${one.kind}:${one.id}`}
        testId="host-timeline"
        loading={timeline.isPending}
        empty={t("Nothing has been recorded for this host yet.")}
        columns={[
          { key: "when", head: t("When"), cell: (one) => (
            <span title={absoluteTime(one.at)}>{relativeTime(one.at)}</span>
          ) },
          { key: "kind", head: t("Kind"), cell: (one) => <Pill tone="neutral">{t(kindName(one.kind))}</Pill> },
          { key: "what", head: t("What"), cell: (one) => {
            const to = timelineLink(host, one);
            // A session row carries the agent version as its title; on its
            // own the version reads as a nonsense name, so the row says
            // what it is.
            const title = one.kind === "session"
              ? t("Agent session{version}", { version: one.title ? ` · ${one.title}` : "" })
              : one.title || "—";
            return (
              <>
                {to ? <Link to={to}>{title}</Link> : title}
                {/* The event words come from the server in a fixed set. */}
                {one.event && <Note>{t(one.event)}</Note>}
                {one.detail && <Note>{one.detail}</Note>}
              </>
            );
          } },
          { key: "state", head: t("State"), cell: (one) => (
            one.state
              ? (
                <>
                  <Pill tone={timelineTone(one)}>{t(one.state)}</Pill>
                  {one.error_code && <> <code title={one.error_code}>{one.error_code}</code></>}
                </>
              )
              : "—"
          ) },
          { key: "who", head: t("Who"), minor: true, cell: (one) => (
            !one.actor
              ? "—"
              : one.actor === host.id
                ? <span title={one.actor}>{t("{host} (agent)", { host: host.hostname })}</span>
                : one.actor
          ) },
        ]}
      />
      <Actions>
        {timeline.hasNextPage && (
          <Button
            kind="quiet"
            testId="timeline-more"
            onClick={() => void timeline.fetchNextPage()}
            disabled={timeline.isFetchingNextPage}
          >
            {t("Load more")}
          </Button>
        )}
        {items.length > 0 && <Note>{t("{n} shown", { n: items.length })}</Note>}
        {hidden.length > 0 && (
          <Note>
            {t("Not shown, no permission: {kinds}", { kinds: hidden.map((kind) => t(kindName(kind))).join(", ") })}
          </Note>
        )}
      </Actions>
    </>
  );
}

/** The outcome of a job as a state: waiting is a person, failed is a fault. */
function jobTone(state: string): Tone {
  if (["succeeded", "completed", "no_change", "active"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired", "partially_applied", "plan_failed"].includes(state)) return "error";
  if (["ineligible", "skipped", "superseded_by_result", "unknown"].includes(state)) return "unknown";
  return "warn";
}

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_OVERVIEW: BoardEntry[] = [
  { key: "disk", title: "Disk used", width: 4, height: 2 },
  { key: "memory", title: "Memory", width: 4, height: 2 },
  { key: "cores", title: "CPU cores", width: 4, height: 2 },
  { key: "adapters", title: "What the panel can do here", width: 7, height: 4 },
  { key: "attention", title: "Needs attention", width: 5, height: 4 },
  { key: "system", title: "System", width: 7, height: 7 },
  { key: "hardware", title: "Hardware", width: 5, height: 4 },
  { key: "notes", title: "Notes", width: 5, height: 4 },
  { key: "lifecycle", title: "Lifecycle", width: 12, height: 7 },
  { key: "registry", title: "Adapters", width: 12, height: 5 },
  { key: "recent", title: "Recent activity", width: 7, height: 5 },
  { key: "timeline", title: "History", width: 12, height: 7 },
];

/** The name this screen's arrangement is stored under. */
export const HOST_OVERVIEW_SCREEN = "next_host_overview";
