import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import {
  body, count, emptyForm, flag, list as listOf, operationForm, payloadTextOf, readPayloadText,
  text as textOf, type FieldSuggestions, type FieldValue, type FormProblem, type FormValue,
  type OperationEntry, type OperationField,
} from "../../../lib/operations";
import { relativeTime, absoluteTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Modal, Note,
  Pill, Stack, Table,
} from "../../kit";

/**
 * The host's resolver: what it resolves names with, who writes that
 * configuration, and whether anything the panel writes would survive.
 *
 * A file owned by a service is rewritten on the next network event, so
 * ownership - not permission - decides what can be changed here. And a
 * host that cannot resolve names loses the directory, Kerberos and with
 * them logging in, which is why the change is armed with the same
 * rollback timer as an address change and confirmed by name first.
 */

type Link = {
  name: string;
  index?: number;
  servers?: string[];
  domains?: string[];
  default_route?: boolean;
  dnssec?: string;
  dns_over_tls?: string;
};

type Query = {
  name: string;
  addresses?: string[];
  server?: string;
  error?: string;
  took_millis: number;
};

type DNSResult = { kind?: string; queries?: { queries?: Query[] } };

type Snapshot = {
  owner?: string;
  mode?: string;
  resolv_conf?: string;
  resolv_conf_target?: string;
  servers?: string[];
  search_domains?: string[];
  links?: Link[];
  dnssec?: string;
  dns_over_tls?: string;
  writable?: boolean;
  write_adapter?: string;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

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
 * The resolver change as an order. It goes through the operation registry,
 * so this screen sends the payload the Bulk workspace sends and refuses the
 * values it refuses - a name server that is not an address among them.
 */
export function resolverOrder(form: FormValue): RegistryOrder {
  return registryOrder("dns.host.apply", form);
}

/** The shortest reason the API takes for a change of this weight. */
export const MIN_REASON_LENGTH = 8;

/** The changes this screen offers; when every one is refused, it says so once. */
export const RESOLVER_CHANGES = ["dns.host.apply"];

/* --------------------------------------------------------- the words */

/**
 * What each owner of resolv.conf means for the operator: who rewrites the
 * file, and so whether a change written by the panel would last.
 */
export function ownerMeaning(owner: string): string {
  switch (owner) {
    case "systemd-resolved": return "systemd-resolved writes resolv.conf; the servers come from its per-link configuration.";
    case "networkmanager": return "NetworkManager writes resolv.conf from the connection profiles; the panel changes it through those.";
    case "dhcp-client": return "A DHCP client writes resolv.conf on every lease; a change by hand is overwritten at the next renewal.";
    case "manual": return "resolv.conf was written by hand; no service rewrites it.";
    default: return "";
  }
}

/** What the resolver mode means: how resolv.conf relates to the daemon. */
export function modeMeaning(mode: string): string {
  switch (mode) {
    case "stub": return "resolv.conf points at the local stub of systemd-resolved; the real servers are per link.";
    case "static": return "resolv.conf lists the upstream servers as systemd-resolved knows them, without the stub.";
    case "uplink": return "resolv.conf lists the upstream servers of systemd-resolved directly.";
    case "foreign": return "resolv.conf is not managed by systemd-resolved; something else wrote it.";
    case "file": return "A plain file read by the libc resolver directly; there is no daemon in between.";
    default: return "";
  }
}

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

export function Resolver({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const access = useModuleAccess(host.id, RESOLVER_CHANGES);

  const module = useQuery({
    queryKey: ["inventory", host.id, "dns"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/dns`),
    retry: false,
  });

  const [names, setNames] = useState("ipa.flotestro.test");
  const [intent, setIntent] = useState<{ description: string; payload: Record<string, unknown> } | null>(null);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState(false);
  // The test result belongs to the job, so we wait for that specific job
  // instead of refreshing the whole list.
  const [testJob, setTestJob] = useState("");
  const mayTest = useAllowed(host.id, "dns.resolve.test");

  // The job result lives on the attempt, not on the job: it is the attempt
  // that knows what the host answered and when.
  const test = useQuery({
    queryKey: ["job-attempts", testJob],
    queryFn: () => api.get<{ items: { status?: string; detail?: DNSResult }[] }>(`/api/v1/jobs/${testJob}/attempts`),
    enabled: testJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      const last = attempts?.[attempts.length - 1];
      return last?.status ? false : 2000;
    },
  });

  const attempts = test.data?.items ?? [];
  const lastAttempt = attempts[attempts.length - 1];
  const answers = lastAttempt?.detail?.queries?.queries ?? [];

  const request = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, payload),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      if (!job.requires_approval) setTestJob(job.id);
      setIntent(null);
      setForm(false);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (module.isLoading) return <Bones rows={5} />;
  if (!module.data) return <Empty>{t("This host has not reported its resolver yet.")}</Empty>;

  const snapshot = module.data.payload;
  const nameList = names.split(",").map((one) => one.trim()).filter(Boolean);
  const managementLink = snapshot?.links?.find((link) => (link.servers ?? []).length > 0);
  // An unread resolver has nothing to count: a dash, never a nought.
  const known = snapshot?.unavailable_reason ? undefined : snapshot;
  const links = known?.links ?? (known ? [] : undefined);
  const unknownPill = <Pill tone="unknown">{t("unknown")}</Pill>;

  const notices: ReactNode[] = [];
  if (snapshot?.unavailable_reason) {
    notices.push(
      <Banner key="unread" tone="error">
        {t("Resolver state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
      </Banner>,
    );
  }
  if (snapshot?.read_only_reason) {
    notices.push(
      <Banner key="readonly" tone="info">
        {t("Read-only on this host: {reason}", { reason: snapshot.read_only_reason })}
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
          title={t("Change resolver")}
          what={intent.description}
          busy={request.isPending}
          onConfirm={(reason) => request.mutate({ action: "dns.host.apply", reason, payload: intent.payload })}
          onCancel={() => setIntent(null)}
        />
      )}
      <Board screen={RESOLVER_SCREEN} catalogue={RESOLVER_BOARD} notices={notices.length > 0 ? <Stack>{notices}</Stack> : undefined} drawn={{
        servers: (
          <Kpi
            hero
            icon="dns"
            label={t("Name servers")}
            value={known ? (known.servers ?? []).length : null}
            note={t("what this host resolves with")}
          />
        ),
        domains: (
          <Kpi
            icon="dns"
            label={t("Search domains")}
            value={known ? (known.search_domains ?? []).length : null}
          />
        ),
        encrypted: (
          <Kpi
            icon="security"
            label={t("Links with DoT")}
            value={countWhere(links, (link) => link.dns_over_tls === "yes") ?? null}
            note={t("DNS over TLS, as the daemon reports it")}
          />
        ),
        owner: (
          <Kpi
            icon="settings"
            label={t("Owner of resolv.conf")}
            value={snapshot?.owner ?? null}
            note={snapshot?.writable ? t("the panel may change it") : t("read only")}
            tone={snapshot?.writable ? "ok" : "warn"}
          />
        ),
        resolution: (
          <Card
            title={t("Resolution")}
            note={t("The servers, the search domains, and the links that carry servers or encrypt their queries.")}
          >
            <Bars items={[
              { label: t("Servers"), value: known ? (known.servers ?? []).length : 0, tone: known ? "info" : "unknown" },
              { label: t("Search domains"), value: known ? (known.search_domains ?? []).length : 0, tone: known ? "info" : "unknown" },
              { label: t("Links with servers"), value: countWhere(links, (link) => (link.servers ?? []).length > 0) ?? 0, tone: links ? "neutral" : "unknown" },
              { label: t("Links with DoT"), value: countWhere(links, (link) => link.dns_over_tls === "yes") ?? 0, tone: links ? "ok" : "unknown" },
            ]} />
            {known === undefined && <Note>{t("Nothing was counted: the snapshot could not be read.")}</Note>}
          </Card>
        ),
        ownership: (
          <Card
            title={t("Ownership")}
            tools={
              <Allowed host={host.id} action="dns.host.apply">
                <Button
                  kind="quiet"
                  testId="change-resolver"
                  onClick={() => setForm((open) => !open)}
                  disabled={!snapshot?.writable}
                  title={snapshot?.writable ? undefined : snapshot?.read_only_reason}
                >
                  {form ? t("Cancel") : t("Change resolver")}
                </Button>
              </Allowed>
            }
          >
            <Facts>
              {/* The owner and the mode are the daemon's words; the hover
                  says what each means for a change written here. */}
              <Fact label={t("Owner")}>
                {snapshot?.owner
                  ? <span title={t(ownerMeaning(snapshot.owner)) || undefined}>{snapshot.owner}</span>
                  : unknownPill}
                {snapshot?.mode && (
                  <span className="fl-faint" title={t(modeMeaning(snapshot.mode)) || undefined}> · {snapshot.mode}</span>
                )}
              </Fact>
              <Fact label={t("Write adapter")}>
                {snapshot?.writable
                  ? <Pill tone="ok">{snapshot.write_adapter || t("yes")}</Pill>
                  : <Pill tone="unknown">{t("read only")}</Pill>}
              </Fact>
              {/* "unsupported" and "disabled" are two different answers, so
                  we show what the host said, not yes/no. */}
              <Fact label="DNSSEC">{snapshot?.dnssec || unknownPill}</Fact>
              <Fact label="DNS over TLS">{snapshot?.dns_over_tls || unknownPill}</Fact>
              {/* What the owner means for a change made here, in a sentence
                  rather than on hover alone: it is the answer to "why can I
                  not change this". */}
              {snapshot?.owner && ownerMeaning(snapshot.owner) && (
                <Fact label={t("Meaning")}>{t(ownerMeaning(snapshot.owner))}</Fact>
              )}
            </Facts>
          </Card>
        ),
        configuration: (
          <Card title={t("Configuration")}>
            <Facts>
              <Fact label={t("Mode")}>
                {snapshot?.mode
                  ? <span title={t(modeMeaning(snapshot.mode)) || undefined}>{snapshot.mode}</span>
                  : <span className="fl-faint">—</span>}
                {snapshot?.mode && modeMeaning(snapshot.mode) && (
                  <span className="fl-faint"> · {t(modeMeaning(snapshot.mode))}</span>
                )}
              </Fact>
              <Fact label="resolv.conf">
                <span className="fl-mono">
                  {snapshot?.resolv_conf || "—"}
                  {snapshot?.resolv_conf_target ? ` → ${snapshot.resolv_conf_target}` : ""}
                </span>
              </Fact>
              <Fact label={t("Servers")}>
                <span className="fl-mono">{(snapshot?.servers ?? []).join(", ") || "—"}</span>
              </Fact>
              <Fact label={t("Search domains")}>
                <span className="fl-mono">{(snapshot?.search_domains ?? []).join(", ") || "—"}</span>
              </Fact>
            </Facts>
          </Card>
        ),
        test: (
          <Card
            title={t("Test resolution from the host")}
            note={t("The panel sits in a different network, so its own answer says nothing about what this host sees. The query runs on the host.")}
          >
            <Stack>
              <Fields>
                <Field label={t("Names, comma separated")} wide>
                  <input
                    value={names}
                    onChange={(event) => setNames(event.target.value)}
                    placeholder={t("Names, comma separated")}
                    data-testid="resolve-names"
                  />
                </Field>
              </Fields>
              {mayTest.allowed ? (
                <Button
                  testId="resolve"
                  onClick={() => request.mutate({ action: "dns.resolve.test", payload: { dns: { names: nameList } } })}
                  disabled={!nameList.length || request.isPending}
                >
                  {t("Resolve")}
                </Button>
              ) : mayTest.known ? (
                <Note>{mayTest.reason || t("This action is not available.")}</Note>
              ) : null}

              {/* The answers arrive with the job result: a fact from the
                  host at a specific moment, not a state to be refreshed. */}
              {testJob && (
                <Table
                  testId="answers"
                  rows={answers}
                  keyOf={(one) => one.name}
                  rowTestId={(one) => `answer-${one.name}`}
                  loading={!lastAttempt?.status}
                  empty={t("No answers.")}
                  columns={[
                    { key: "name", head: t("Name"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
                    { key: "addresses", head: t("Addresses"), cell: (one) => (
                      one.addresses?.length
                        ? <span className="fl-mono">{one.addresses.join(", ")}</span>
                        : <Pill tone="unknown">{one.error || t("no answer")}</Pill>
                    ) },
                    { key: "server", head: t("Answered by"), cell: (one) => (
                      one.server ? <span className="fl-mono">{one.server}</span> : <span className="fl-faint">—</span>
                    ) },
                    { key: "took", head: t("Took"), num: true, cell: (one) => `${one.took_millis} ms` },
                  ]}
                />
              )}
            </Stack>
          </Card>
        ),
        change: form ? (
          <Allowed host={host.id} action="dns.host.apply">
            <ResolverChange
              seed={{
                interface: managementLink?.name ?? "",
                servers: (snapshot?.servers ?? []).join("\n"),
                // A domain the host reports with a leading tilde is routed,
                // not searched; the name under it is what a search domain is.
                search_domains: (snapshot?.search_domains ?? []).map((one) => one.replace(/^~/, "")).join("\n"),
                ignore_auto_dns: true,
                rollback_seconds: 120,
              }}
              suggestions={{ interface: (snapshot?.links ?? []).map((link) => link.name) }}
              onIntent={setIntent}
            />
          </Allowed>
        ) : undefined,
        links: (
          <Card title={t("Per-link resolvers")} flush>
            <Table
              testId="links"
              rows={snapshot?.links ?? []}
              keyOf={(one) => one.name}
              rowTestId={(one) => `link-${one.name}`}
              empty={t("This host does not report per-link resolvers; it has one global list.")}
              columns={[
                { key: "name", head: t("Link"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
                { key: "servers", head: t("Servers"), cell: (one) => (
                  <span className="fl-mono">{(one.servers ?? []).join(", ") || "—"}</span>
                ) },
                { key: "domains", head: t("Domains"), cell: (one) => (
                  <span className="fl-mono">{(one.domains ?? []).join(", ") || "—"}</span>
                ) },
                // The default route decides which link answers a name
                // outside its domains - and that is the operator's question.
                { key: "route", head: t("Answers other names"), cell: (one) => (
                  one.default_route === undefined ? unknownPill : one.default_route ? t("yes") : t("no")
                ) },
                { key: "dnssec", head: "DNSSEC", minor: true, cell: (one) => one.dnssec || <span className="fl-faint">—</span> },
                // The heading is the abbreviation the daemon prints; what it
                // stands for was on the old panel's heading and stays here.
                { key: "dot", head: <span title={t("DNS over TLS")}>DoT</span>, label: "DoT", minor: true,
                  cell: (one) => one.dns_over_tls || <span className="fl-faint">—</span> },
              ]}
            />
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
                <Fact label={t("Resolver read")}>
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

/* ------------------------------------------------------ the change */

/**
 * The resolver change form, drawn from the operation registry: the fields,
 * the refusals and the payload are the ones the Bulk workspace uses.
 */
function ResolverChange({ seed, suggestions, onIntent }: {
  /** What this host resolves with now, as the form's starting value. */
  seed: FormValue;
  suggestions?: FieldSuggestions;
  onIntent: (intent: { description: string; payload: Record<string, unknown> }) => void;
}) {
  const t = useT();
  const entry = operationForm("dns.host.apply");
  const [value, setValue] = useState<FormValue>(() => (entry ? { ...emptyForm(entry), ...seed } : seed));
  // A payload typed by hand in the advanced view is not one this screen
  // sends: the change is armed with a rollback the form's own fields carry.
  const [json, setJson] = useState("");
  if (!entry) return null;
  const order = resolverOrder(value);
  const domains = listOf(value, "search_domains");

  return (
    <Card
      title={t("Change resolver")}
      note={t("A host that cannot resolve names loses the directory, Kerberos and with them logins — so this change is armed with the same rollback timer as an address change.")}
    >
      <Stack>
        <RegistryFields
          entry={entry}
          value={value}
          onChange={setValue}
          json={json}
          onJson={setJson}
          suggestions={suggestions}
        />
        <Button
          testId="apply-resolver"
          disabled={!orderReady(order) || json !== ""}
          title={refusalOf(t, order)}
          onClick={() => onIntent({
            description: t("{iface} will resolve through {servers}{domains}. The host rolls back after {seconds}s unless the agent confirms it still reaches the panel.", {
              iface: textOf(value, "interface"),
              servers: listOf(value, "servers").join(", "),
              domains: domains.length ? `, ${t("searching {domains}", { domains: domains.join(", ") })}` : "",
              seconds: Number(value.rollback_seconds) || 0,
            }),
            payload: order.payload,
          })}
        >
          {t("Apply resolver")}
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
      // The fields can carry this payload, so they take it back.
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
            // Not a problem box: a form that has not been filled in yet is
            // not a page that broke.
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
  // A field that is wrong says so where its explanation stood: one place to
  // look, and the explanation is no use until the value is right.
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
        <select value={textOf(value, field.name)} onChange={(event) => set(field, event.target.value)}>
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

  // What the host has is offered, not imposed: a list beside the field
  // rather than a select, because an operator may be naming something the
  // host does not report yet.
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

/** The confirmation of a change that can take the host away from the panel. */
function Confirm({ host, title, what, busy, onConfirm, onCancel }: {
  host: Host;
  title: string;
  what: ReactNode;
  busy: boolean;
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
          <Button disabled={!ready || busy} onClick={() => onConfirm(reason, typed)} testId="confirm">
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
export const RESOLVER_SCREEN = "next_host_dns";

/** The containers this screen can draw, and the shape each ships with. */
export const RESOLVER_BOARD: BoardEntry[] = [
  { key: "servers", title: "Name servers", width: 3, height: 2 },
  { key: "domains", title: "Search domains", width: 3, height: 2 },
  { key: "encrypted", title: "Links with DoT", width: 3, height: 2 },
  { key: "owner", title: "Owner of resolv.conf", width: 3, height: 2 },
  { key: "resolution", title: "Resolution", width: 8, height: 4 },
  { key: "ownership", title: "Ownership", width: 4, height: 4 },
  { key: "configuration", title: "Configuration", width: 6, height: 4 },
  { key: "test", title: "Test resolution from the host", width: 6, height: 5 },
  { key: "change", title: "Change resolver", width: 12, height: 9 },
  { key: "links", title: "Per-link resolvers", width: 12, height: 5 },
  { key: "source", title: "Where this came from", width: 12, height: 2 },
];
