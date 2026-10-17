import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import {
  body, count, flag, payloadTextOf, readPayloadText, text,
  type FieldSuggestions, type FieldValue, type FormValue,
  type OperationEntry, type OperationField,
} from "../../../lib/operations";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Banner, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Modal, Note, Pill,
  Table, Tag, Tags, type Segment,
} from "../../kit";
import {
  orderReady, refusalOf, registryOrder, type RegistryOrder,
} from "../../../lib/host/module";

/**
 * Power, boot and the maintenance window.
 *
 * A reboot is not over when the command is sent: it is over when the host
 * comes back with a new boot ID. A shutdown is never over here at all,
 * because nothing in this panel can turn the machine back on - which is
 * why it is the one action that asks for its reason before the dialog is
 * even offered.
 *
 * The pieces every host module acts through - the guard on one action, the
 * line a read-only module shows, the confirmation that carries a reason -
 * live in this file. They were written for this module, which is the one
 * the panel's confirmation rule exists for, and the other modules take
 * them from here rather than each keeping its own idea of what confirming
 * means.
 */

/* ------------------------------------------------------- what to act with */

/** The shortest reason the API takes for a critical operation. */
export const MIN_REASON = 8;

/** One order waiting to be confirmed: what it does, and what it would send. */
export type Intent = {
  action: string;
  label: string;
  description: ReactNode;
  payload: Record<string, unknown>;
  /** The one that cannot be undone wears the danger button. */
  danger?: boolean;
  /**
   * Ask for the reason and nothing else. An order that takes data away is
   * confirmed by typing the name of what goes away; one that is merely of
   * the highest risk needs the reason, and asking for a name there teaches
   * the operator to type names without reading them.
   */
  reasonOnly?: boolean;
  /** What is typed to confirm, when it is narrower than the whole host. */
  target?: string;
};

/**
 * A control that exists only where the order it places would be taken.
 *
 * Without `explain` a refused action simply is not offered; with it, the
 * refusal stands where the control would have been, so a reader learns
 * that the thing exists and what it would take.
 */
export function Guard({ action, host, explain = false, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  return <Pill tone="unknown" title={verdict.reason || undefined}>{verdict.reason || action}</Pill>;
}

/**
 * The one line a module shows when every change it offers is refused: the
 * reader can still read the module and learns what changing it would take,
 * instead of meeting a screen with its buttons quietly gone.
 */
export function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

/**
 * The confirmation of an order: what it does, which machine it is aimed
 * at, the reason that goes into the trail, and - where something goes away
 * - the name of the thing typed out.
 */
export function Confirm({ host, intent, busy, onConfirm, onCancel }: {
  host: Host;
  intent: Intent;
  busy: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const expected = intent.target ?? host.hostname;
  const ready = reason.trim().length >= MIN_REASON && (intent.reasonOnly === true || typed === expected);
  return (
    <Modal
      title={intent.label}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy} testId="confirm-cancel">{t("Cancel")}</Button>
          <Button
            kind={intent.danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason.trim(), typed)}
            testId="confirm-order"
          >
            {busy ? t("Requesting…") : intent.label}
          </Button>
        </>
      }
    >
      <Note>{intent.description}</Note>
      {/* The target repeated in the dialog: the operator approves a
          specific machine, not "the host I think I have open". */}
      <Tags>
        <Tag>{t("Target: {host}", { host: host.hostname })}</Tag>
        <Tag>{host.management_address || t("address unknown")}</Tag>
        <Tag>{host.site} / {host.environment}</Tag>
      </Tags>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
        </Field>
        {!intent.reasonOnly && (
          <Field
            label={intent.target === undefined ? t("Type the hostname to confirm:") : t("Type the name to confirm:")}
            hint={expected}
            wide
          >
            <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
          </Field>
        )}
      </Fields>
    </Modal>
  );
}

/**
 * Placing an order on one host: the request, what it answered with, and
 * the refusal when the panel would not take it.
 */
export function useOrder(host: Host, onDone?: (job: Job, body: Record<string, unknown>) => void) {
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created, body) => {
      setJob(created);
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      onDone?.(created, body);
    },
    onError: (error) => {
      setJob(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });
  return {
    request,
    job,
    message,
    setMessage,
    clear: () => { setJob(null); setMessage(""); },
  };
}

/**
 * What an order answered with, as a sentence that leads to the job: an
 * order waiting for approval is something somebody has to go and do.
 */
export function JobLine({ job, hostID }: { job: Job; hostID: string }) {
  const t = useT();
  return (
    <Note>
      <span data-testid="job-notice">
        {job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) })}
      </span>
      {" "}
      <Link to={`/jobs/${job.id}`}>{t("Open the job")}</Link>
      {" "}
      <Link to={`/hosts/${hostID}/jobs`}>{t("See all jobs")}</Link>
    </Note>
  );
}

/**
 * The form of one operation, drawn from the registry, with the
 * hand-written payload behind a switch for what the fields cannot show.
 *
 * It is the registry's own form rather than a form each module writes,
 * so a host module and the Bulk workspace ask for the same things and
 * refuse the same values. The old panel's component draws the same
 * fields in the appearance this panel replaces, which is why this is
 * written out of the kit instead of imported.
 */
export function OperationFields({ entry, value, onChange, json, onJson, suggestions }: {
  entry: OperationEntry;
  value: FormValue;
  onChange: (value: FormValue) => void;
  /** The payload as hand-written JSON; empty means the fields are the order. */
  json: string;
  onJson: (json: string) => void;
  /** What this host really carries, by field name. */
  suggestions?: FieldSuggestions;
}) {
  const t = useT();
  const [advanced, setAdvanced] = useState(json !== "");
  // The text of the advanced view lives here rather than in the order: a
  // value that reformats itself on every keystroke cannot be typed into.
  const [draft, setDraft] = useState(() => json || payloadTextOf(entry, value));
  const problems = entry.validate(value);
  const problemOf = (name: string) => problems.find((problem) => problem.field === name);
  const set = (field: OperationField, next: FieldValue) => onChange({ ...value, [field.name]: next });

  const editJson = (next: string) => {
    setDraft(next);
    const read = readPayloadText(entry, next);
    if (read) {
      // The fields can carry this payload, so they take it back.
      onChange(read);
      onJson("");
      return;
    }
    onJson(next);
  };

  return (
    <>
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
            // Not a problem box: a form nobody has filled in yet is not a
            // page that broke.
            <Note>{problems.map((problem) => t(problem.message, problem.params)).join(" ")}</Note>
          )}
        </>
      )}
    </>
  );
}

/** What the advanced view is holding right now. */
function advancedWords(t: Translate, entry: OperationEntry, draft: string): string {
  if (readPayloadText(entry, draft)) {
    return t("The fields can show this payload, so they are what the order carries; close the advanced view and they are filled in with it.");
  }
  try {
    const parsed: unknown = JSON.parse(draft);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return t("The fields cannot show this payload, so it travels exactly as typed. The server checks it and names what is wrong.");
    }
  } catch {
    // Not JSON at all; said below.
  }
  return t("This is not valid JSON.");
}

/** One field of an operation's form. */
function OneField({ field, value, problem, set, suggestions }: {
  field: OperationField;
  value: FormValue;
  problem?: { message: string; params?: Record<string, string | number> };
  set: (field: OperationField, next: FieldValue) => void;
  suggestions?: string[];
}) {
  const t = useT();
  // A field that is wrong says so where its explanation stood: one place
  // to look, and the explanation is no use until the value is right.
  const hint = problem ? t(problem.message, problem.params) : field.hint ? t(field.hint) : undefined;
  const listID = suggestions && suggestions.length > 0 ? `field-${field.name}` : undefined;

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
        <select value={text(value, field.name)} onChange={(event) => set(field, event.target.value)}>
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>{t(option.label)}</option>
          ))}
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
          {suggestions!.map((one) => <option key={one} value={one} />)}
        </datalist>
      )}
    </Field>
  );
}

/* ------------------------------------------------- the registry's orders */

/* The registry's order model is lib/host/module's: every module of a host
   page composes its order the same way, through the registry entry, so
   there is one copy of what "ready" and "refused" mean. */
export { orderReady, refusalOf, registryOrder, type RegistryOrder };

/**
 * The one line that says where a module's reading came from and how old
 * it is. It is a sentence rather than a component, so a card with
 * nothing to say draws no empty foot under itself.
 */
export function freshnessOf(t: Translate, fragment?: InventoryFragment<unknown>): string | undefined {
  if (!fragment) return undefined;
  return t("Source: {source}, revision {revision}, observed {when}", {
    source: fragment.source,
    revision: fragment.revision.slice(0, 12),
    when: relativeTime(fragment.observed_at),
  });
}

/* ------------------------------------------------------------- this module */

type Inhibitor = { who: string; user?: string; pid?: number; what?: string; why?: string; mode?: string };

type Boot = { index: number; boot_id: string; first_entry: string; last_entry: string };

type Snapshot = {
  boot_id?: string;
  booted_at?: string;
  uptime_seconds?: number | null;
  running_kernel?: string;
  reboot_required?: boolean | null;
  reboot_reasons?: string[];
  inhibitors?: Inhibitor[];
  inhibitors_known?: boolean;
  last_boots?: Boot[];
  scheduled_shutdown?: { mode: string; at: string };
  observed_at?: string;
  unavailable_reason?: string;
};

/** A boot identifier in the dashed form the kernel prints. */
export function dashedBootID(id: string): string {
  const bare = id.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(bare)) return id;
  return `${bare.slice(0, 8)}-${bare.slice(8, 12)}-${bare.slice(12, 16)}-${bare.slice(16, 20)}-${bare.slice(20)}`;
}

/** The Logs module of this host, narrowed to one boot. */
export function bootLogsPath(hostID: string, bootID: string): string {
  const bare = bootID.replace(/-/g, "").toLowerCase();
  return `/hosts/${encodeURIComponent(hostID)}/logs?boot=${encodeURIComponent(bare)}`;
}

/** The uptime in a form that reads without arithmetic in one's head. */
export function uptimeWords(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/** The changes this module offers; when every one is refused, it says so once. */
const POWER_CHANGES = ["system.reboot", "system.shutdown"];

/** The shortest reason a shutdown is accepted with, before the dialog opens. */
const SHUTDOWN_REASON = 10;

export function Power({ host }: { host: Host }) {
  const t = useT();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [shutdownReason, setShutdownReason] = useState("");
  const [ignoreInhibitors, setIgnoreInhibitors] = useState(false);

  const module = useQuery({
    queryKey: ["inventory", host.id, "power"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/power`),
    retry: false,
  });
  const order = useOrder(host, () => setIntent(null));

  const snapshot = module.data?.payload;
  const blocking = (snapshot?.inhibitors ?? []).filter((one) => one.mode === "block");
  // Unreported inhibitors are not zero inhibitors; the band shows a dash.
  const inhibitors = snapshot?.inhibitors_known ? snapshot.inhibitors ?? [] : undefined;
  const known = snapshot?.unavailable_reason ? undefined : snapshot;
  const uptime = snapshot?.uptime_seconds;
  const boots = [...(snapshot?.last_boots ?? [])].reverse();

  const holds: Segment[] = [
    { label: t("blocking"), value: inhibitors?.filter((one) => one.mode === "block").length, tone: "warn" },
    { label: t("delaying"), value: inhibitors?.filter((one) => one.mode !== "block").length, tone: "info" },
    {
      label: t("reboot reasons"),
      value: known ? (known.reboot_reasons ?? []).length : undefined,
      tone: known?.reboot_required ? "error" : "neutral",
    },
  ];

  if (!module.data && !module.isLoading) {
    return <Empty>{t("This host has not reported its boot state yet.")}</Empty>;
  }

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={POWER_CHANGES} />
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">
          {t("Boot state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
        </Banner>
      )}
      {/* A shutdown scheduled outside the panel is a fact the operator is
          to see before asking for anything here. */}
      {snapshot?.scheduled_shutdown && (
        <Banner tone="warn">
          {t("A {mode} is already scheduled on this host for {when}.", {
            mode: snapshot.scheduled_shutdown.mode,
            when: absoluteTime(snapshot.scheduled_shutdown.at),
          })}
        </Banner>
      )}
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {order.job && <JobLine job={order.job} hostID={host.id} />}

      <Board screen={POWER_SCREEN} catalogue={HOST_POWER} drawn={{
        uptime: (
          <Kpi
            icon="power"
            label={t("Uptime")}
            value={uptime === undefined || uptime === null ? null : uptimeWords(uptime)}
            note={snapshot?.observed_at ? t("as of {when}", { when: relativeTime(snapshot.observed_at) }) : undefined}
          />
        ),
        reboot: (
          <Kpi
            icon="power"
            label={t("Reboot required")}
            value={snapshot?.reboot_required === undefined || snapshot?.reboot_required === null
              ? null
              : snapshot.reboot_required ? t("yes") : t("no")}
            tone={snapshot?.reboot_required ? "warn" : "ok"}
            note={(snapshot?.reboot_reasons ?? []).length > 0 ? snapshot!.reboot_reasons!.join(", ") : undefined}
          />
        ),
        holds: (
          <Kpi
            icon="jobs"
            label={t("Inhibitors")}
            value={snapshot?.inhibitors_known ? (snapshot.inhibitors ?? []).length : null}
            tone={blocking.length > 0 ? "warn" : "ok"}
            note={blocking.length > 0 ? t("{n} of them blocking", { n: blocking.length }) : undefined}
          />
        ),
        bands: (
          <Card
            title={t("Holds and reasons")}
            note={t("What logind would hold a shutdown for, and what asks for a reboot.")}
          >
            <Band segments={holds} testId="power-holds" />
          </Card>
        ),
        boot: (
          <Card title={t("This boot")} foot={freshnessOf(t, module.data)}>
            <Facts>
              <Fact label={t("Boot ID")}>
                {snapshot?.boot_id
                  ? (
                    <Link to={bootLogsPath(host.id, snapshot.boot_id)} title={t("The journal of this boot")}>
                      {snapshot.boot_id}
                    </Link>
                  )
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              {/* The boot instant absolute beside the relative one, and the
                  uptime marked as of the read: the two are read at different
                  moments and would otherwise seem to disagree. */}
              <Fact label={t("Booted")}>
                {snapshot?.booted_at
                  ? <span title={absoluteTime(snapshot.booted_at)}>{relativeTime(snapshot.booted_at)}</span>
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Uptime")}>
                {uptime === undefined || uptime === null
                  ? <Pill tone="unknown">{t("unknown")}</Pill>
                  : <span title={t("as of the last read")}>{uptimeWords(uptime)}</span>}
              </Fact>
              <Fact label={t("Running kernel")}>
                {snapshot?.running_kernel || <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Reboot required")}>
                {snapshot?.reboot_required === undefined || snapshot?.reboot_required === null
                  ? <Pill tone="unknown">{t("unknown")}</Pill>
                  : snapshot.reboot_required ? t("yes") : t("no")}
              </Fact>
              {/* "Why" is the whole answer here: a host that requires a
                  reboot without a reason tells the operator nothing. */}
              <Fact label={t("Why")}>
                {(snapshot?.reboot_reasons ?? []).length > 0
                  ? snapshot!.reboot_reasons!.join(", ")
                  : <Note>{t("nothing asks for one")}</Note>}
              </Fact>
              <Fact label={t("Scheduled shutdown")}>
                {snapshot?.scheduled_shutdown
                  ? (
                    <>
                      <Pill tone="warn">{snapshot.scheduled_shutdown.mode}</Pill>
                      {" "}
                      <span title={absoluteTime(snapshot.scheduled_shutdown.at)}>
                        {relativeTime(snapshot.scheduled_shutdown.at)}
                      </span>
                    </>
                  )
                  : t("none")}
              </Fact>
              <Fact label={t("Boots in the journal")}>
                {known ? (known.last_boots ?? []).length : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
            </Facts>
          </Card>
        ),
        maintenance: <MaintenanceWindow host={host} />,
        inhibitors: (
          <Card
            title={t("Inhibitors")}
            note={t("What logind would hold a shutdown for. A delay is waited out; a block stops the operation until an operator decides otherwise.")}
            flush
          >
            {!snapshot?.inhibitors_known ? (
              <Empty>{t("This host did not report inhibitors.")}</Empty>
            ) : (
              <Table
                rows={snapshot.inhibitors ?? []}
                keyOf={(one, index) => `${one.who}-${index}`}
                empty={t("Nothing is holding a shutdown on this host.")}
                columns={[
                  { key: "who", head: t("Who"), cell: (one) => one.who },
                  { key: "user", head: t("User"), minor: true, cell: (one) => one.user || "—" },
                  { key: "what", head: t("What"), tight: true, cell: (one) => one.what || "—" },
                  { key: "why", head: t("Why"), minor: true, cell: (one) => one.why || "—" },
                  { key: "mode", head: t("Mode"), cell: (one) => (
                    one.mode === "block" ? <Pill tone="warn">{t("block")}</Pill> : one.mode || "—"
                  ) },
                ]}
              />
            )}
          </Card>
        ),
        act: (
          <Card
            title={t("Power")}
            note={t("A reboot is finished only when the host comes back with a new boot ID; a shutdown is never finished here, because nothing in this panel can turn the machine back on.")}
          >
            <Fields>
              <Field
                label={t("Reason for shutting this host down")}
                hint={t("A reboot asks for its reason at the confirmation. A shutdown needs one here first, at least 10 characters: nobody will read the panel to find out why the host is dark.")}
                wide
              >
                <input
                  value={shutdownReason}
                  onChange={(event) => setShutdownReason(event.target.value)}
                  placeholder={t("disk replacement, ticket 1234")}
                  data-testid="shutdown-reason"
                />
              </Field>
            </Fields>
            {/* The checkbox stands over both buttons and governs both: a
                restart interrupts the same work a shutdown does. */}
            <Check checked={ignoreInhibitors} onChange={setIgnoreInhibitors}>
              {t("override inhibitors")}
            </Check>
            <Note>
              {t("Both are delayed 15 seconds on the host, so whoever is logged in sees the warning.")}
            </Note>
            <Guard action="system.reboot" host={host.id} explain>
              <Button
                testId="reboot"
                onClick={() => setIntent({
                  action: "system.reboot",
                  label: t("Reboot host"),
                  description: t("{host} will reboot. The panel treats the operation as finished only when the host comes back with a new boot ID, so a host that does not return shows up as failed, not as done.", { host: host.hostname }),
                  payload: { reboot: { delay_seconds: 15, reason: "operator reboot", ignore_inhibitors: ignoreInhibitors } },
                })}
              >
                {t("Reboot")}
              </Button>
            </Guard>
            <Guard action="system.shutdown" host={host.id} explain>
              <Button
                kind="danger"
                testId="shutdown"
                disabled={shutdownReason.trim().length < SHUTDOWN_REASON}
                title={t("a shutdown needs a reason: nobody will read the panel to find out why this host is dark")}
                onClick={() => setIntent({
                  action: "system.shutdown",
                  label: t("Shut down host"),
                  danger: true,
                  description: t("{host} will power off. Nothing in this panel can turn it back on — that needs physical or out-of-band access to the machine.", { host: host.hostname })
                    + (blocking.length
                      ? " " + (ignoreInhibitors
                        ? t("{n} blocking inhibitor(s) will be overridden.", { n: blocking.length })
                        : t("{n} inhibitor(s) are blocking shutdown; the host will refuse.", { n: blocking.length }))
                      : ""),
                  payload: {
                    power: {
                      mode: "poweroff",
                      delay_seconds: 15,
                      reason: shutdownReason,
                      ignore_inhibitors: ignoreInhibitors,
                    },
                  },
                })}
              >
                {t("Shut down")}
              </Button>
            </Guard>
          </Card>
        ),
        boots: (
          <Card
            title={t("Last boots")}
            note={t("The journal numbers boots back from the current one: 0 is this boot, -1 the one before.")}
            flush
          >
            <Table
              rows={boots}
              keyOf={(one) => one.boot_id}
              loading={module.isLoading}
              empty={t("The journal on this host lists no earlier boots.")}
              columns={[
                { key: "index", head: "#", num: true, cell: (one) => one.index },
                { key: "boot", head: t("Boot ID"), tight: true, cell: (one) => (
                  <>
                    <Link to={bootLogsPath(host.id, one.boot_id)} title={t("The journal of this boot")}>
                      {dashedBootID(one.boot_id)}
                    </Link>
                    {one.index === 0 && <Pill tone="ok">{t("this boot")}</Pill>}
                  </>
                ) },
                { key: "first", head: t("First entry"), cell: (one) => (
                  <span title={absoluteTime(one.first_entry)}>{relativeTime(one.first_entry)}</span>
                ) },
                { key: "last", head: t("Last entry"), cell: (one) => (
                  <span title={absoluteTime(one.last_entry)}>{relativeTime(one.last_entry)}</span>
                ) },
              ]}
            />
          </Card>
        ),
      }} />

      {intent && (
        <Confirm
          key={intent.action}
          host={host}
          intent={intent}
          busy={order.request.isPending}
          onConfirm={(reason, confirmation) => order.request.mutate({
            action: intent.action,
            reason,
            // A shutdown requires the target name typed out: the panel
            // cannot power this machine back on.
            target_confirmation: confirmation,
            payload: intent.payload,
          })}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}

/**
 * The maintenance window. It is not an operation on the host and does not
 * go through the job queue: it changes what the panel thinks about the
 * host.
 */
function MaintenanceWindow({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [minutes, setMinutes] = useState(120);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  const set = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Host>(`/api/v1/hosts/${host.id}/maintenance`, body),
    onSuccess: () => {
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const active = Boolean(host.maintenance && new Date(host.maintenance.until).getTime() > Date.now());

  return (
    <Card
      title={t("Maintenance window")}
      note={t("A window says somebody is working on this machine: campaigns skip it and its alerts stay quiet. It always has an end — a window without one ends as a host nobody patches and nobody remembers.")}
    >
      {active ? (
        <Facts>
          <Fact label={t("Until")}>
            <span title={absoluteTime(host.maintenance!.until)}>{relativeTime(host.maintenance!.until)}</span>
          </Fact>
          <Fact label={t("Reason")}>{host.maintenance!.reason || "—"}</Fact>
          <Fact label={t("Declared by")}>{host.maintenance!.set_by || "—"}</Fact>
        </Facts>
      ) : (
        <Empty>{t("This host is not in a maintenance window.")}</Empty>
      )}
      <Fields>
        <Field label={t("Duration (minutes)")} hint={t("Counted from now; the window ends on its own.")}>
          <input
            type="number"
            min={1}
            value={minutes}
            onChange={(event) => setMinutes(Number(event.target.value))}
            data-testid="window-minutes"
          />
        </Field>
        <Field label={t("Reason")} hint={t("Shown to whoever finds the host in a window; kept in the audit trail.")} wide>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={t("disk swap, ticket 1234")}
            data-testid="window-reason"
          />
        </Field>
      </Fields>
      <Button
        testId="window-start"
        disabled={!reason.trim() || set.isPending}
        onClick={() => set.mutate({ duration_minutes: minutes, reason })}
      >
        {active ? t("Extend window") : t("Start window")}
      </Button>
      <Button
        kind="quiet"
        testId="window-end"
        disabled={!active || set.isPending}
        onClick={() => set.mutate({ clear: true })}
      >
        {t("End window")}
      </Button>
      {message && <Note>{message}</Note>}
    </Card>
  );
}

/** The name this module's arrangement is stored under. */
export const POWER_SCREEN = "next_host_power";

/** The containers this module can draw, and the shape each ships with. */
export const HOST_POWER: BoardEntry[] = [
  { key: "uptime", title: "Uptime", width: 4, height: 2 },
  { key: "reboot", title: "Reboot required", width: 4, height: 2 },
  { key: "holds", title: "Inhibitors", width: 4, height: 2 },
  { key: "bands", title: "Holds and reasons", width: 7, height: 4 },
  { key: "boot", title: "This boot", width: 5, height: 5 },
  { key: "maintenance", title: "Maintenance window", width: 7, height: 5 },
  { key: "act", title: "Power", width: 5, height: 5 },
  { key: "inhibitors", title: "Inhibitors", width: 7, height: 5 },
  { key: "boots", title: "Last boots", width: 12, height: 5 },
];
