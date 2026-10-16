import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import {
  body, count, emptyForm, flag, operationForm, payloadTextOf, readPayloadText, text as textOf,
  type FieldSuggestions, type FieldValue, type FormProblem, type FormValue,
  type OperationEntry, type OperationField,
} from "../../../lib/operations";
import { relativeTime, absoluteTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Modal, Note,
  Pill, Readout, Stack, Table,
} from "../../kit";

/**
 * The sshd server as sshd itself reports it.
 *
 * The panel writes only its own file in sshd_config.d — the main config
 * belongs to the distribution and to whoever runs this host. Rotating a
 * host key changes this machine's identity for every client that has it
 * in known_hosts, so it is confirmed by name with a reason first.
 */

type HostKey = { type: string; bits: number; fingerprint: string; path: string };

type Snapshot = {
  ports?: string[];
  listen_addresses?: string[];
  permit_root_login?: string;
  password_authentication?: string;
  pubkey_authentication?: string;
  kbd_interactive_authentication?: string;
  gssapi_authentication?: string;
  max_auth_tries?: number;
  allow_users?: string[];
  allow_groups?: string[];
  deny_users?: string[];
  deny_groups?: string[];
  host_keys?: HostKey[];
  managed_config?: string;
  managed_path?: string;
  managed_present?: boolean;
  unit?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/* ------------------------------------------------------- the registry */

/** One order as the registry composes it: what would be sent, and what is wrong with it. */
export type RegistryOrder = {
  action: string;
  payload: Record<string, unknown>;
  problems: FormProblem[];
};

/** Puts an order through the registry entry of its action. */
export function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  if (!entry) {
    return {
      action,
      payload: {},
      problems: [{ message: "The registry has no form for {action} yet.", params: { action } }],
    };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

/** Whether the registry would take this order as it stands. */
export function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

/** The first refusal of an order as a sentence, or an empty string. */
export function refusalOf(t: Translate, order: RegistryOrder): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

/**
 * A change to the server's settings as an order, composed by the operation
 * registry so this screen and the Bulk workspace send one payload and
 * refuse one set of values.
 */
export function sshConfigOrder(form: FormValue): RegistryOrder {
  return registryOrder("ssh.config.apply", form);
}

/**
 * The settings the order would change, the lockout consent aside. An order
 * that changes nothing is not one the panel places, and the registry has no
 * way of saying so: "leave it alone" is a legal value for every field.
 */
export function sshConfigSettings(order: RegistryOrder): string[] {
  const section = (order.payload.ssh ?? {}) as Record<string, unknown>;
  return Object.keys(section).filter((name) => name !== "allow_lockout");
}

/** Whether the snapshot carries nothing of what "sshd -T" prints. */
export function effectiveConfigurationMissing(
  snapshot: Pick<Snapshot, "ports" | "permit_root_login" | "password_authentication" | "pubkey_authentication">,
): boolean {
  return (snapshot.ports ?? []).length === 0
    && !snapshot.permit_root_login
    && !snapshot.password_authentication
    && !snapshot.pubkey_authentication;
}

/** The shortest reason the API takes for a change of this weight. */
export const MIN_REASON_LENGTH = 8;

/** The changes this screen offers; when every one is refused, it says so once. */
export const SSH_CHANGES = ["ssh.config.apply", "ssh.hostkey.rotate"];

/** A count of the items that satisfy a test, or undefined when the list itself is unknown. */
export function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/** A control that is drawn only where the order it places would be taken. */
function Allowed({ host, action, children }: { host: string; action: string; children: ReactNode }) {
  const verdict = useAllowed(host, action);
  return verdict.allowed ? <>{children}</> : null;
}

/* -------------------------------------------------------- the screen */

export function SshServer({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const access = useModuleAccess(host.id, SSH_CHANGES);

  const module = useQuery({
    queryKey: ["inventory", host.id, "ssh"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/ssh`),
    retry: false,
  });

  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [editor, setEditor] = useState(false);

  const request = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, payload),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      setEditor(false);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (module.isLoading) return <Bones rows={5} />;
  if (!module.data) return <Empty>{t("This host has not reported its sshd yet.")}</Empty>;

  const snapshot = module.data.payload;
  const methods: [string, string | undefined][] = [
    [t("Password"), snapshot?.password_authentication],
    [t("Public key"), snapshot?.pubkey_authentication],
    [t("Keyboard interactive"), snapshot?.kbd_interactive_authentication],
    ["GSSAPI", snapshot?.gssapi_authentication],
  ];
  // An unread configuration has nothing to count: a dash, never a nought.
  const effectiveMissing = !!snapshot && !snapshot.unavailable_reason && effectiveConfigurationMissing(snapshot);
  const known = snapshot?.unavailable_reason || effectiveMissing ? undefined : snapshot;
  const knownMethods = known ? methods : undefined;
  // "prohibit-password" is neither yes nor no: what the server said is
  // what is shown, coloured by how exposed it leaves the host.
  const risky = (value?: string) => value === "yes" ? "warn" as const : value === "no" ? "ok" as const : "unknown" as const;
  // MaxAuthTries is never zero in a configuration sshd printed; a zero is
  // the value of a field the read left empty.
  const maxAuthTries = snapshot?.max_auth_tries ? snapshot.max_auth_tries : undefined;

  const notices: ReactNode[] = [];
  if (snapshot?.unavailable_reason) {
    notices.push(
      <Banner key="unread" tone="error">
        {t("sshd configuration could not be read: {reason}", { reason: snapshot.unavailable_reason })}
      </Banner>,
    );
  }
  if (effectiveMissing) {
    notices.push(
      <Banner key="effective" tone="warn">
        {t("The host returned no effective configuration: the read of sshd -T gave nothing, so the ports, the methods and the limits are unknown. The host keys were read from disk.")}
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
  if (message) notices.push(<Banner key="message" tone="info">{message}</Banner>);

  return (
    <>
      {intent && (
        <Confirm
          host={host}
          title={intent.label}
          what={intent.description}
          busy={request.isPending}
          danger={intent.action === "ssh.hostkey.rotate"}
          onConfirm={(reason) => request.mutate({ action: intent.action, reason, payload: intent.payload })}
          onCancel={() => setIntent(null)}
        />
      )}
      <Board screen={SSH_SCREEN} catalogue={SSH_BOARD} drawn={{
        notices: notices.length > 0 ? <Stack>{notices}</Stack> : undefined,
        ports: (
          <Kpi
            hero
            icon="ssh"
            label={t("Ports")}
            value={known ? (known.ports ?? []).length : null}
            note={known ? (known.ports ?? []).join(", ") || undefined : undefined}
          />
        ),
        open: (
          <Kpi
            icon="security"
            label={t("Methods enabled")}
            value={countWhere(knownMethods, ([, value]) => value === "yes") ?? null}
            tone="warn"
          />
        ),
        rootlogin: (
          <Kpi
            icon="user"
            label={t("Root login")}
            value={snapshot?.permit_root_login ?? null}
            tone={risky(snapshot?.permit_root_login)}
          />
        ),
        keys: (
          <Kpi
            icon="secrets"
            label={t("Host keys")}
            // The keys come from the disk, not from "sshd -T": they are
            // counted whenever the snapshot carries them, even when the
            // effective configuration could not be read.
            value={snapshot?.host_keys ? snapshot.host_keys.length : null}
          />
        ),
        ways: (
          <Card
            title={t("Ways in")}
            note={t("What sshd listens on and accepts, as it reports it.")}
          >
            <Bars items={[
              { label: t("ports"), value: known ? (known.ports ?? []).length : 0, tone: known ? "info" : "unknown" },
              { label: t("methods enabled"), value: countWhere(knownMethods, ([, value]) => value === "yes") ?? 0, tone: knownMethods ? "warn" : "unknown" },
              { label: t("methods disabled"), value: countWhere(knownMethods, ([, value]) => value === "no") ?? 0, tone: knownMethods ? "ok" : "unknown" },
              { label: t("methods unknown"), value: countWhere(knownMethods, ([, value]) => value !== "yes" && value !== "no") ?? 0, tone: "unknown" },
              { label: t("host keys"), value: snapshot?.host_keys ? snapshot.host_keys.length : 0, tone: snapshot?.host_keys ? "neutral" : "unknown" },
            ]} />
            {known === undefined && <Note>{t("Nothing was counted: the snapshot could not be read.")}</Note>}
          </Card>
        ),
        posture: (
          <Card
            title={t("Posture")}
            tools={
              <Allowed host={host.id} action="ssh.config.apply">
                <Button kind="quiet" testId="change-configuration" onClick={() => setEditor((open) => !open)}>
                  {editor ? t("Cancel") : t("Change configuration")}
                </Button>
              </Allowed>
            }
          >
            <Facts>
              <Fact label={t("Root login")}>
                <Pill tone={risky(snapshot?.permit_root_login)}>{snapshot?.permit_root_login || t("unknown")}</Pill>
              </Fact>
              <Fact label={t("Password")}>
                <Pill tone={risky(snapshot?.password_authentication)}>{snapshot?.password_authentication || t("unknown")}</Pill>
              </Fact>
              <Fact label={t("Max auth tries")}>
                {maxAuthTries ?? <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Access lists")}>
                {known ? (
                  <Bars items={[
                    { label: t("Allow users"), value: (known.allow_users ?? []).length, tone: "ok" },
                    { label: t("Allow groups"), value: (known.allow_groups ?? []).length, tone: "ok" },
                    { label: t("Deny users"), value: (known.deny_users ?? []).length, tone: "error" },
                    { label: t("Deny groups"), value: (known.deny_groups ?? []).length, tone: "error" },
                  ]} />
                ) : <span className="fl-faint">—</span>}
              </Fact>
            </Facts>
          </Card>
        ),
        editor: editor ? (
          <Allowed host={host.id} action="ssh.config.apply">
            <SshEditor state={snapshot} onIntent={setIntent} onCancel={() => setEditor(false)} />
          </Allowed>
        ) : undefined,
        effective: (
          <Card title={t("Effective configuration")}>
            <Facts>
              <Fact label={t("Port")}>
                <span className="fl-mono">{(snapshot?.ports ?? []).join(", ") || "—"}</span>
              </Fact>
              <Fact label={t("Listening on")}>
                <span className="fl-mono">{(snapshot?.listen_addresses ?? []).join(", ") || "—"}</span>
              </Fact>
              <Fact label={t("Root login")}>{snapshot?.permit_root_login || <span className="fl-faint">—</span>}</Fact>
              <Fact label={t("Max auth tries")}>{maxAuthTries ?? <span className="fl-faint">—</span>}</Fact>
              <Fact label={t("Allow users")}>
                <span className="fl-mono">{(snapshot?.allow_users ?? []).join(" ") || "—"}</span>
              </Fact>
              <Fact label={t("Allow groups")}>
                <span className="fl-mono">{(snapshot?.allow_groups ?? []).join(" ") || "—"}</span>
              </Fact>
              <Fact label={t("Deny users")}>
                <span className="fl-mono">{(snapshot?.deny_users ?? []).join(" ") || "—"}</span>
              </Fact>
              <Fact label={t("Service unit")}>
                <span className="fl-mono">{snapshot?.unit || "—"}</span>
              </Fact>
            </Facts>
          </Card>
        ),
        methods: (
          <Card title={t("Authentication methods")} flush>
            <Table
              testId="methods"
              rows={methods}
              keyOf={([name]) => name}
              rowTestId={([name]) => `method-${name}`}
              columns={[
                { key: "method", head: t("Method"), cell: ([name]) => name },
                { key: "enabled", head: t("Enabled"), cell: ([, value]) => (
                  value || <Pill tone="unknown">{t("unknown")}</Pill>
                ) },
              ]}
            />
          </Card>
        ),
        hostkeys: (
          <Card
            title={t("Host keys")}
            note={t("Fingerprints only — the panel has no reason to see a host's private key. Rotating one changes this host's identity for every client that has it in known_hosts.")}
            flush
          >
            <Table
              testId="host-keys"
              rows={snapshot?.host_keys ?? []}
              keyOf={(one) => one.path}
              rowTestId={(one) => `host-key-${one.type}`}
              empty={t("This host reported no host key.")}
              columns={[
                { key: "type", head: t("Type"), cell: (one) => one.type },
                { key: "bits", head: t("Bits"), num: true, cell: (one) => one.bits },
                { key: "fingerprint", head: t("Fingerprint"), tight: true, cell: (one) => (
                  <span className="fl-mono">{one.fingerprint}</span>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <Allowed host={host.id} action="ssh.hostkey.rotate">
                    <Button
                      kind="danger"
                      testId={`rotate-${one.type}`}
                      onClick={() => setIntent({
                        action: "ssh.hostkey.rotate",
                        label: t("Rotate host key"),
                        description: t("A new {type} host key will be generated on {host}. Every client with the old fingerprint in known_hosts will warn, and anything keyed to the old fingerprint stops working. The old key is kept on the host with a timestamp.", {
                          type: one.type, host: host.hostname,
                        }),
                        payload: { ssh: { key_type: one.type } },
                      })}
                    >
                      {t("Rotate")}
                    </Button>
                  </Allowed>
                ) },
              ]}
            />
          </Card>
        ),
        dropin: (
          <Card title={t("Managed drop-in")} note={snapshot?.managed_path}>
            {snapshot?.managed_present
              ? <Readout label={snapshot.managed_path} value={snapshot.managed_config ?? ""} lines={14} testId="managed-config" />
              : <Empty>{t("The panel has not written anything to this host yet.")}</Empty>}
          </Card>
        ),
        source: (
          <Card title={t("Where this came from")}>
            <Facts>
              <Fact label={t("Source")}>{module.data.source}</Fact>
              <Fact label={t("Revision")}><span className="fl-mono">{module.data.revision.slice(0, 12)}</span></Fact>
              <Fact label={t("Observed")}>
                <span title={absoluteTime(module.data.observed_at)}>{relativeTime(module.data.observed_at)}</span>
              </Fact>
              {snapshot?.observed_at && (
                <Fact label={t("Configuration read")}>
                  <span title={absoluteTime(snapshot.observed_at)}>{relativeTime(snapshot.observed_at)}</span>
                </Fact>
              )}
              {module.data.unavailable_reason && (
                <Fact label={t("Could not be read")}>{module.data.unavailable_reason}</Fact>
              )}
            </Facts>
          </Card>
        ),
      }} />
    </>
  );
}

/* ------------------------------------------------------- the editor */

/** One setting as the confirmation sentence reads it. */
export function describe(value: unknown): string {
  return Array.isArray(value) ? value.join(" ") : String(value);
}

/**
 * The managed file editor, drawn from the operation registry: the same
 * fields, the same refusals and the same payload as the Bulk workspace.
 */
function SshEditor({ state, onIntent, onCancel }: {
  state?: Snapshot;
  onIntent: (intent: Intent) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const entry = operationForm("ssh.config.apply");
  const [value, setValue] = useState<FormValue>(() => (entry ? emptyForm(entry) : {}));
  const [json, setJson] = useState("");
  if (!entry) return null;
  const order = sshConfigOrder(value);
  const settings = sshConfigSettings(order);
  const section = (order.payload.ssh ?? {}) as Record<string, unknown>;

  return (
    <Card
      title={t("Change configuration")}
      note={t("Empty means “leave it alone”. The host validates the file with sshd itself before reloading, and reloads instead of restarting so open sessions survive.")}
      tools={<Button kind="quiet" onClick={onCancel}>{t("Cancel")}</Button>}
    >
      <Stack>
        <RegistryFields entry={entry} value={value} onChange={setValue} json={json} onJson={setJson} />
        <Button
          testId="apply-configuration"
          disabled={!orderReady(order) || settings.length === 0 || json !== ""}
          title={refusalOf(t, order)}
          onClick={() => onIntent({
            action: order.action,
            label: t("Apply sshd configuration"),
            description: t("{changes} on {unit}. Existing sessions stay open.", {
              changes: settings.map((name) => `${name} = ${describe(section[name])}`).join(", "),
              unit: state?.unit ?? "sshd",
            }),
            payload: order.payload,
          })}
        >
          {t("Apply")}
        </Button>
      </Stack>
    </Card>
  );
}

/* --------------------------------------------- the registry's fields */

/**
 * The form of one operation, drawn from the registry.
 *
 * The advanced view is the escape hatch for a payload the fields cannot
 * show; while it holds one, the fields are not what the order carries and
 * the button that places it stays shut.
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
  // The text of the advanced view lives here rather than in the order: a
  // value that reformats itself on every keystroke cannot be typed into.
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

/** The confirmation of a change to the way this machine is logged into. */
function Confirm({ host, title, what, busy, danger, onConfirm, onCancel }: {
  host: Host;
  title: string;
  what: ReactNode;
  busy: boolean;
  danger?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ready = reason.trim().length >= MIN_REASON_LENGTH && typed === host.hostname;

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
          <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
            <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
          </Field>
        </Fields>
      </Stack>
    </Modal>
  );
}

/** The name this screen's arrangement is stored under. */
export const SSH_SCREEN = "next_host_ssh";

/** The containers this screen can draw, and the shape each ships with. */
export const SSH_BOARD: BoardEntry[] = [
  { key: "notices", title: "What has to be read first", width: 12, height: 1 },
  { key: "ports", title: "Ports", width: 3, height: 1 },
  { key: "open", title: "Methods enabled", width: 3, height: 1 },
  { key: "rootlogin", title: "Root login", width: 3, height: 1 },
  { key: "keys", title: "Host keys", width: 3, height: 1 },
  { key: "ways", title: "Ways in", width: 8, height: 2 },
  { key: "posture", title: "Posture", width: 4, height: 2 },
  { key: "editor", title: "Change configuration", width: 12, height: 5 },
  { key: "effective", title: "Effective configuration", width: 7, height: 3 },
  { key: "methods", title: "Authentication methods", width: 5, height: 3 },
  { key: "hostkeys", title: "Host keys", width: 7, height: 3 },
  { key: "dropin", title: "Managed drop-in", width: 5, height: 3 },
  { key: "source", title: "Where this came from", width: 12, height: 1 },
];
