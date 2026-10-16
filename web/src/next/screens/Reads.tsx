import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, LIST_PAGE, loadedItems, type Page } from "../../lib/api";
import { OPERATIONS_INTERVAL } from "../../lib/stream";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import { stateName } from "../../components/ui";
import { useToast } from "../../components/Toast";
import type {
  Host, ReadFanOut, ReadFanOutCounts, ReadFanOutHost, ReadFanOutView, Whoami,
} from "../../lib/types";
import { buildExpression, describeExpression, RULE_FIELDS, type Rule, type RuleField } from "../../pages/Groups";
import { FacetList, payloadSkeleton, useFleetFacets, useOperations, type Operation } from "../../pages/Bulk";
import { parsePayload, payloadHint } from "../../pages/Reads";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Bars, Bones, Card, Check, Dot, Empty, Field, Fields, Find, Grid, HeadActions, Modal, Note, Pill, Problem, Seg, Stack, Table, Tabs, Tag, Tags, Toolbar, TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * The same read on a handful of hosts at once.
 *
 * It is a diagnostic and not a change: nothing is approved, nothing is
 * written on a host, and the registry says which reads may fan out at all
 * and to how many machines. Every host gets an ordinary job, and what
 * comes back is merged here - as one timeline for a read of lines, or as
 * one host's typed result at a time for a read that answers in a shape.
 */

export function Reads() {
  const { id } = useParams();
  return id ? <OneRead id={id} /> : <ReadList />;
}

/** The catalogue entry with what a fan-out reads from it. */
type FanOutOperation = Operation & { fanout_limit?: number; fanout_refusal?: string };

/** The address of the form with a read already filled in, for a host page. */
export function readsPrefill(action: string, payload: unknown): string {
  return `/next/reads?action=${encodeURIComponent(action)}&payload=${encodeURIComponent(JSON.stringify(payload, null, 2))}`;
}

/**
 * The state of one host's job as a tone.
 *
 * A host that took no part is not a host that failed, so a skip wears the
 * unknown colour rather than the red one: the read says nothing about
 * that machine and must not look as though it did.
 */
export function jobTone(state: string): Tone {
  if (["succeeded", "completed", "no_change"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired"].includes(state)) return "error";
  if (["skipped", "ineligible", "superseded_by_result"].includes(state)) return "unknown";
  return "warn";
}

/* ------------------------------------------------------------ the list */

function ReadList() {
  const t = useT();
  const [prefill] = useSearchParams();
  // A link from a host page opens the form already filled in; the plain
  // address opens on the list.
  const [building, setBuilding] = useState(prefill.has("action"));

  // The list grows page by page from the newest read, so an operator who
  // reads a lot keeps the old fan-outs one click away rather than losing
  // them past a fixed ceiling. The page comes from the server; nothing
  // here narrows what the server already decided to send.
  const list = useInfiniteQuery({
    queryKey: ["reads", "list"],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: String(LIST_PAGE) });
      if (pageParam) params.set("cursor", pageParam);
      return api.get<Page<ReadFanOut>>(`/api/v1/reads?${params}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    refetchInterval: OPERATIONS_INTERVAL * 5,
  });

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  const reads = loadedItems(list.data);
  // Before the first answer nobody has counted anything, and the band
  // says "not counted" rather than drawing a nought for each state.
  const sum = (key: keyof ReadFanOutCounts) =>
    list.data ? reads.reduce((total, one) => total + one.counts[key], 0) : undefined;
  const states: Segment[] = [
    { label: t("Queued"), value: sum("queued"), tone: "warn" },
    { label: t("Running"), value: sum("running"), tone: "info" },
    { label: t("Succeeded"), value: sum("succeeded"), tone: "ok" },
    { label: t("Failed"), value: sum("failed"), tone: "error" },
  ];
  const byOperation = Object.entries(
    reads.reduce<Record<string, number>>((acc, read) => {
      acc[read.action] = (acc[read.action] ?? 0) + 1;
      return acc;
    }, {}),
  ).sort((a, b) => b[1] - a[1]);

  return (
    <>
      <HeadActions><button
            type="button"
            className={building ? "fl-quiet" : undefined}
            onClick={() => setBuilding(!building)}
            data-testid="new-read"
          >
            {building ? t("Hide the form") : t("New read")}
          </button></HeadActions>
      <Board screen={READS_SCREEN} catalogue={READS} drawn={{
        // A container with nothing to draw is left off the grid, so the
        // form takes its place only while it is open.
        form: building && <NewRead onDone={() => setBuilding(false)} />,
        states: (
          <Card
            title={t("Hosts by state")}
            note={t("every host of the {n} reads listed, counted once per read", { n: reads.length })}
          >
            <Band segments={states} testId="read-states" />
          </Card>
        ),
        list: (
          <Card
            title={t("Your reads")}
            flush
            foot={
              list.hasNextPage
                ? (
                  <button type="button" className="fl-quiet fl-small"
                          onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                    {list.isFetchingNextPage ? t("loading…") : t("Load more")}
                  </button>
                )
                : t("{n} reads listed", { n: reads.length })
            }
          >
            <Table
              rows={reads}
              keyOf={(one) => one.id}
              rowTestId={(one) => `read-${one.id}`}
              testId="reads"
              loading={list.isLoading} empty={t("No reads yet.")}
              columns={[
                {
                  key: "action",
                  head: t("Operation"),
                  tight: true,
                  cell: (one) => (
                    <TwoLine sub={one.created_by}>
                      <Link to={`/next/reads/${one.id}`}><code>{one.action}</code></Link>
                    </TwoLine>
                  ),
                },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.host_count },
                { key: "progress", head: t("Progress"), cell: (one) => <Counts counts={one.counts} /> },
                {
                  key: "reason",
                  head: t("Reason"),
                  minor: true,
                  cell: (one) => one.reason || <span className="fl-faint">—</span>,
                },
                {
                  key: "created",
                  head: t("Created"),
                  minor: true,
                  cell: (one) => <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>,
                },
              ]}
            />
          </Card>
        ),
        operations: (
          <Card title={t("By operation")} note={t("among the {n} listed", { n: reads.length })}>
            {!list.data
              ? <Bones rows={4} />
              : byOperation.length === 0
                ? <Empty>{t("No reads yet.")}</Empty>
                : <Bars items={byOperation.map(([action, n]) => ({ label: <code>{action}</code>, value: n }))} />}
          </Card>
        ),
      }} />
    </>
  );
}

/** The four counts of a fan-out, each wearing what it means. */
function Counts({ counts }: { counts: ReadFanOutCounts }) {
  const t = useT();
  return (
    <Tags>
      {counts.queued > 0 && <Pill tone="warn" dot={false}>{t("{n} queued", { n: counts.queued })}</Pill>}
      {counts.running > 0 && <Pill tone="info" dot={false}>{t("{n} running", { n: counts.running })}</Pill>}
      <Pill tone="ok" dot={false}>{t("{n} succeeded", { n: counts.succeeded })}</Pill>
      {counts.failed > 0 && <Pill tone="error" dot={false}>{t("{n} failed", { n: counts.failed })}</Pill>}
    </Tags>
  );
}

/* ------------------------------------------------------------ the form */

/**
 * The payload a read starts from where an example says more than a
 * skeleton: a log path and a line count are what an operator would have
 * typed anyway. Every other read starts from the skeleton the registry
 * describes.
 */
const DEFAULT_PAYLOADS: Record<string, unknown> = {
  "journal.read": { journal: { lines: 100 } },
  "logfile.read": { logfile: { path: "/var/log/syslog", lines: 100 } },
  "process.list": { process_list: { sort_by: "rss", limit: 100 } },
  "dns.resolve.test": { dns: { names: ["example.com"] } },
  "security.scan": {},
  "packages.list": {},
  "unit.status": {},
};

type TargetMode = "filters" | "expression" | "hosts";

/**
 * A refusal in the operator's words. A busy panel is not a wrong order:
 * the answer says to wait, and names what for.
 */
export function refusalMessage(error: unknown, t: Translate): string {
  if (error instanceof ApiError) {
    if (error.code === "fanout_busy") return `${t("The panel is busy with other reads; try again in a moment.")} ${error.message}`;
    if (error.code === "fanout_too_broad") return `${t("The selector names more hosts than this read fans out to; narrow it.")} ${error.message}`;
    return error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

/** The order form: the read, its payload, the hosts and the reason. */
function NewRead({ onDone }: { onDone: () => void }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [prefill] = useSearchParams();
  const operations = useOperations();
  const fannable = useMemo(
    () => ((operations.data?.items ?? []) as FanOutOperation[]).filter((one) => (one.fanout_limit ?? 0) > 0),
    [operations.data],
  );

  const [action, setAction] = useState(prefill.get("action") ?? "journal.read");
  // The example if there is one, then what the registry says the
  // operation reads, and an empty object only for a read that takes no
  // payload.
  const startingPayload = useCallback(
    (name: string) => JSON.stringify(
      DEFAULT_PAYLOADS[name] ?? payloadSkeleton(fannable.find((one) => one.action === name)),
      null, 2),
    [fannable],
  );
  const [payloadText, setPayloadText] = useState(
    prefill.get("payload") ?? JSON.stringify(DEFAULT_PAYLOADS[action] ?? {}, null, 2),
  );
  // Whether the operator has written in the field. The starting payload
  // is only put there while they have not: a skeleton that overwrote what
  // somebody typed would be worse than the empty object it replaces.
  const [payloadTyped, setPayloadTyped] = useState(prefill.has("payload"));
  const [payloadFor, setPayloadFor] = useState(action);

  // A group page hands over its name: the read then opens on the group's
  // selector rather than on the filters.
  const prefilledGroup = prefill.get("group") ?? "";
  const [mode, setMode] = useState<TargetMode>(prefilledGroup ? "expression" : "filters");
  const [site, setSite] = useState(prefill.get("site") ?? "");
  const [environment, setEnvironment] = useState(prefill.get("environment") ?? "");
  const [osFamily, setOsFamily] = useState("");
  const [rules, setRules] = useState<Rule[]>(prefilledGroup
    ? [{ field: "group", value: prefilledGroup, negated: false }]
    : [{ field: "tag", value: "", negated: false }]);
  const [combine, setCombine] = useState<"all" | "any">("all");
  const [hostIDs, setHostIDs] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const facets = useFleetFacets();

  // A read picked from the list starts from its own payload unless the
  // form was opened with one filled in. The registry arrives after the
  // first render, so this also fills the field for the operation the form
  // opened on - but never over what the operator has written for it.
  useEffect(() => {
    if (prefill.get("payload") && prefill.get("action") === action) return;
    if (payloadFor === action && payloadTyped) return;
    setPayloadText(startingPayload(action));
    setPayloadFor(action);
    setPayloadTyped(false);
  }, [action, payloadFor, payloadTyped, prefill, startingPayload]);

  const chosen = fannable.find((one) => one.action === action);
  const limit = chosen?.fanout_limit ?? 0;
  const expression = buildExpression(rules, combine);
  const payload = parsePayload(payloadText);

  const create = useMutation({
    mutationFn: () =>
      api.post<ReadFanOutView>("/api/v1/reads", {
        action,
        payload: payload.value ?? {},
        reason: reason.trim() || undefined,
        selector: mode === "hosts"
          ? { host_ids: [...hostIDs] }
          : mode === "expression"
            ? { expression: expression ?? undefined }
            : { site: site || undefined, environment: environment || undefined, os_family: osFamily || undefined },
      }),
    onSuccess: (view) => {
      void queryClient.invalidateQueries({ queryKey: ["reads"] });
      onDone();
      navigate(`/next/reads/${view.id}`);
    },
    onError: (error) => setErrorMessage(refusalMessage(error, t)),
  });

  const named = mode === "hosts"
    ? hostIDs.size > 0
    : mode === "expression"
      ? expression !== null
      : Boolean(site || environment || osFamily);
  const tooMany = mode === "hosts" && limit > 0 && hostIDs.size > limit;
  const ready = Boolean(chosen) && payload.value !== undefined && named && !tooMany;

  return (
    <Card
      title={t("New read")}
      note={t("Every host gets an ordinary job with this payload; the results are merged here. A read needs no approval.")}
      foot={
        <Actions>
          <button type="button" onClick={() => create.mutate()} disabled={!ready || create.isPending} data-testid="order-read">
            {create.isPending ? t("Ordering…") : t("Read")}
          </button>
          <button type="button" className="fl-quiet" onClick={onDone}>{t("Cancel")}</button>
        </Actions>
      }
    >
      {errorMessage && <Problem>{errorMessage}</Problem>}
      <Fields>
        <Field
          label={t("Operation")}
          hint={chosen
            ? t("Fans out to at most {n} hosts.", { n: limit })
            : t("Only reads the registry opens to a fan-out are listed.")}
        >
          <select value={action} onChange={(event) => setAction(event.target.value)} data-testid="read-action">
            {fannable.map((one) => (
              <option key={one.action} value={one.action}>
                {one.action} — {t("up to {n} hosts", { n: one.fanout_limit ?? 0 })}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("Reason")} hint={t("Optional; it goes to the audit log next to the order.")}>
          <input
            placeholder={t("e.g. checking the leak on the web tier")}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </Field>
        <Field label={t("Payload")} hint={payloadHint(t, payload)} wide>
          <textarea
            rows={6}
            className="fl-mono"
            value={payloadText}
            spellCheck={false}
            data-testid="read-payload"
            onChange={(event) => { setPayloadText(event.target.value); setPayloadTyped(true); }}
          />
        </Field>
      </Fields>

      <h3 className="fl-subhead">{t("Targets")}</h3>
      <Toolbar
        end={
          <span className="fl-note">
            {t("The ceiling applies to what the selector matches; a broader selector is refused, not trimmed.")}
          </span>
        }
      >
        <Seg
          value={mode}
          onChange={setMode}
          options={[
            { value: "filters", label: t("site, environment and OS") },
            { value: "expression", label: t("groups and tags") },
            { value: "hosts", label: t("hosts by name") },
          ]}
        />
      </Toolbar>

      {mode === "filters" && (
        /* The values the fleet really has are offered under each field;
           free text still goes through, because a site with no host yet
           is a valid selector that names nobody. */
        <Fields>
          <Field label={t("Site")}>
            <input placeholder={t("site")} value={site} list="next-reads-sites"
                   onChange={(event) => setSite(event.target.value)} />
            <FacetList id="next-reads-sites" facets={facets.data?.by_site} />
          </Field>
          <Field label={t("Environment")}>
            <input placeholder={t("environment")} value={environment} list="next-reads-environments"
                   onChange={(event) => setEnvironment(event.target.value)} />
            <FacetList id="next-reads-environments" facets={facets.data?.by_environment} />
          </Field>
          <Field label={t("OS family")}>
            <input placeholder={t("e.g. debian")} value={osFamily} list="next-reads-os-families"
                   onChange={(event) => setOsFamily(event.target.value)} />
            <FacetList id="next-reads-os-families" facets={facets.data?.by_os_family} />
          </Field>
        </Fields>
      )}

      {mode === "expression" && (
        <Stack>
          <Rules rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
          <Note>
            {expression
              ? `${t("the read will carry")} ${describeExpression(expression)}`
              : t("give a rule a value; until then the selector names nobody")}
          </Note>
        </Stack>
      )}

      {mode === "hosts" && (
        <Stack>
          <HostPicker chosen={hostIDs} onChange={setHostIDs} />
          {tooMany && (
            <Problem>
              {t("{n} hosts chosen; this read fans out to at most {limit}.", { n: hostIDs.size, limit })}
            </Problem>
          )}
        </Stack>
      )}
    </Card>
  );
}

/**
 * The selector as rows of fact and value, joined by all or any.
 *
 * The expression itself is the panel's own model - the same one the group
 * page builds - so this draws it and does not invent a second grammar.
 */
function Rules({ rules, combine, onRules, onCombine }: {
  rules: Rule[];
  combine: "all" | "any";
  onRules: (rules: Rule[]) => void;
  onCombine: (combine: "all" | "any") => void;
}) {
  const t = useT();
  const update = (index: number, delta: Partial<Rule>) =>
    onRules(rules.map((rule, i) => (i === index ? { ...rule, ...delta } : rule)));
  const names: Record<RuleField, string> = {
    tag: t("tag"), group: t("group"), site: t("site"), environment: t("environment"),
    os_family: t("os family"), os_version: t("os version"), capability: t("capability"),
    connection_state: t("connection state"), lifecycle_state: t("lifecycle state"), owner: t("owner"),
    channel: t("release channel"), security_updates: t("security updates waiting"),
    reboot_required: t("reboot required"), failed_units: t("failed units"),
    agent_version: t("agent version"), relay: t("relay"), failure_domain: t("failure domain"),
  };
  return (
    <Stack>
      <Toolbar>
        <span className="fl-note">{t("the host has to match")}</span>
        <select
          value={combine}
          aria-label={t("the host has to match")}
          onChange={(event) => onCombine(event.target.value as "all" | "any")}
        >
          <option value="all">{t("every rule")}</option>
          <option value="any">{t("any rule")}</option>
        </select>
      </Toolbar>
      {rules.map((rule, index) => (
        <Toolbar
          key={index}
          end={
            <button
              type="button"
              className="fl-quiet fl-small"
              disabled={rules.length === 1}
              onClick={() => onRules(rules.filter((_, i) => i !== index))}
            >
              {t("Remove")}
            </button>
          }
        >
          <Check checked={rule.negated} onChange={(on) => update(index, { negated: on })}>{t("not")}</Check>
          <select
            value={rule.field}
            aria-label={t("Rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { field: event.target.value as RuleField, value: "" })}
          >
            {RULE_FIELDS.map((field) => <option key={field} value={field}>{names[field]}</option>)}
          </select>
          <input
            value={rule.value}
            placeholder={t("value")}
            aria-label={t("Value of rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { value: event.target.value })}
          />
        </Toolbar>
      ))}
      <Actions>
        <button
          type="button"
          className="fl-quiet fl-small"
          onClick={() => onRules([...rules, { field: "tag", value: "", negated: false }])}
        >
          {t("Add a rule")}
        </button>
      </Actions>
    </Stack>
  );
}

/**
 * The hosts named one by one.
 *
 * What is searched is searched in the database: the box sends `q` and the
 * server answers with the page. Narrowing the hundred rows already loaded
 * would answer a different question and look like the same one.
 */
function HostPicker({ chosen, onChange }: { chosen: Set<string>; onChange: (next: Set<string>) => void }) {
  const t = useT();
  const [search, setSearch] = useState("");
  const query = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (search.trim()) query.set("q", search.trim());
  const hosts = useQuery({
    queryKey: ["hosts", query.toString()],
    queryFn: () => api.get<Page<Host>>(`/api/v1/hosts?${query}`),
  });
  const rows = hosts.data?.items ?? [];
  const toggle = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id); else next.add(id);
    onChange(next);
  };
  return (
    <Stack>
      <Toolbar end={<span className="fl-note">{t("{n} chosen", { n: chosen.size })}</span>}>
        <Find value={search} onChange={setSearch} placeholder={t("Search hosts…")} testId="read-host-search" />
        <button
          type="button"
          className="fl-quiet fl-small"
          onClick={() => onChange(new Set([...chosen, ...rows.map((one) => one.id)]))}
        >
          {t("Choose every listed host")}
        </button>
        <button type="button" className="fl-quiet fl-small" disabled={chosen.size === 0} onClick={() => onChange(new Set())}>
          {t("Clear")}
        </button>
      </Toolbar>
      {hosts.error
        ? <Problem>{String(hosts.error)}</Problem>
        : (
          <Table
            rows={rows}
            keyOf={(one) => one.id}
            rowTestId={(one) => `pick-${one.hostname}`}
            testId="read-hosts"
            loading={hosts.isLoading} empty={t("No host matches this.")}
            columns={[
              {
                key: "chosen",
                head: t("Chosen"),
                cell: (one) => (
                  <Check checked={chosen.has(one.id)} onChange={() => toggle(one.id)}>{one.hostname}</Check>
                ),
              },
              {
                key: "address",
                head: t("Address"),
                minor: true,
                tight: true,
                cell: (one) => one.management_address || <span className="fl-faint">—</span>,
              },
              {
                key: "state",
                head: t("State"),
                // A machine answers or it does not; that is the dot's
                // question, and it is not the question a job's state asks.
                cell: (one) => <><Dot state={one.connection_state} /> {t(stateName(one.connection_state))}</>,
              },
            ]}
          />
        )}
    </Stack>
  );
}

/* ---------------------------------------------------------- one fan-out */

/** One fan-out: the hosts by state, and the merged result. */
function OneRead({ id }: { id: string }) {
  const t = useT();
  const [selected, setSelected] = useState("");
  const [grouping, setGrouping] = useState<"timeline" | "host">("timeline");

  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canCancel = (whoami.data?.permissions ?? []).includes("job.cancel");

  const read = useQuery({
    queryKey: ["read", id],
    queryFn: () => api.get<ReadFanOutView>(`/api/v1/reads/${id}`),
    // The page follows the jobs while any of them is open; a finished
    // fan-out is a record and is not read again.
    refetchInterval: (query) => {
      const view = query.state.data;
      return view && view.counts.queued + view.counts.running === 0 ? false : OPERATIONS_INTERVAL;
    },
  });

  if (read.error) return <Problem>{String(read.error)}</Problem>;
  const view = read.data;
  if (!view) return <Bones rows={4} />;

  const open = view.counts.queued + view.counts.running;
  const answered = view.hosts.filter((one) => one.state === "succeeded");
  const current = view.hosts.find((one) => one.host_id === selected) ?? answered[0];
  const states: Segment[] = [
    { label: t("Queued"), value: view.counts.queued, tone: "warn" },
    { label: t("Running"), value: view.counts.running, tone: "info" },
    { label: t("Succeeded"), value: view.counts.succeeded, tone: "ok" },
    { label: t("Failed"), value: view.counts.failed, tone: "error" },
  ];

  return (
    <>
      <HeadActions><>
            {canCancel && open > 0 && <Withdraw view={view} />}
            <Link className="fl-btn fl-quiet" to={readsPrefill(view.action, view.payload)}>
              {t("Order the same again")}
            </Link>
          </></HeadActions>
      <Grid>
        <Card span={12} title={t("Hosts by state")}>
          <Band segments={states} testId="read-host-states" />
        </Card>

        <Card span={12} title={t("Hosts")} flush>
          <Table
            rows={[
              ...view.hosts.map((one) => ({ kind: "job" as const, host: one })),
              // A host the fan-out never reached is listed with the rest
              // and says why: leaving it out would make the read look as
              // though it covered the fleet it was aimed at.
              ...(view.skipped ?? []).map((one) => ({ kind: "skipped" as const, host: one })),
            ]}
            keyOf={(row) => (row.kind === "job" ? row.host.job_id : row.host.host_id)}
            rowTestId={(row) => `fanout-${row.host.hostname || row.host.host_id}`}
            testId="fanout-hosts"
            empty={t("This read names no host.")}
            columns={[
              {
                key: "host",
                head: t("Host"),
                cell: (row) => (
                  <Link to={`/next/hosts/${row.host.host_id}`}>{row.host.hostname || row.host.host_id}</Link>
                ),
              },
              {
                key: "state",
                head: t("State"),
                cell: (row) => {
                  const state = row.kind === "job" ? row.host.state : "skipped";
                  return <Pill tone={jobTone(state)}>{t(stateName(state))}</Pill>;
                },
              },
              {
                key: "result",
                head: t("Result"),
                cell: (row) => (row.kind === "job"
                  ? (
                    <Stack>
                      {row.host.error_code && <code>{row.host.error_code}</code>}
                      {row.host.message && <span className="fl-note">{row.host.message}</span>}
                      {row.host.truncated && <Pill tone="warn">{t("output truncated")}</Pill>}
                    </Stack>
                  )
                  : (
                    <Stack>
                      <code>{row.host.reason}</code>
                      <span className="fl-note">{row.host.message}</span>
                    </Stack>
                  )),
              },
              {
                key: "finished",
                head: t("Finished"),
                minor: true,
                cell: (row) => (row.kind === "job" && row.host.finished_at
                  ? <span title={absoluteTime(row.host.finished_at)}>{relativeTime(row.host.finished_at)}</span>
                  : <span className="fl-faint">—</span>),
              },
              {
                key: "job",
                head: t("Job"),
                minor: true,
                tight: true,
                cell: (row) => (row.kind === "job"
                  ? <Link to={`/next/jobs?fanout_id=${view.id}`}><code>{row.host.job_id.slice(0, 8)}</code></Link>
                  : <span className="fl-faint">—</span>),
              },
            ]}
          />
        </Card>

        {view.kind === "timeline" ? (
          <Card
            span={12}
            title={t("Timeline")}
            note={grouping === "timeline"
              ? t("The lines of every host in one sequence by their timestamps. The order between hosts is best-effort - clocks differ - and the order within a host is the host's own.")
              : t("The lines of every host, host by host, as each gave them.")}
            tools={
              <Seg
                value={grouping}
                onChange={setGrouping}
                options={[
                  { value: "timeline", label: t("merged timeline") },
                  { value: "host", label: t("group by host") },
                ]}
              />
            }
          >
            {answered.length === 0
              ? <Empty>{open > 0 ? t("Waiting for the first host to answer…") : t("No host answered.")}</Empty>
              : grouping === "timeline"
                ? (
                  <Stack>
                    {(view.timeline ?? []).length === 0
                      ? <Empty>{t("No line carries a timestamp; see the lines by host below.")}</Empty>
                      : (
                        <pre className="fl-mono" data-testid="read-timeline">
                          {(view.timeline ?? []).map((line, index) => (
                            <div key={index}>
                              <Tag>{line.hostname || line.host_id}</Tag> {line.line}
                            </div>
                          ))}
                        </pre>
                      )}
                    {(view.untimed ?? []).map((group) => (
                      <div key={group.host_id}>
                        <h3 className="fl-subhead">
                          {t("Without a timestamp: {host}", { host: group.hostname || group.host_id })}
                        </h3>
                        <pre className="fl-mono">{group.lines.join("\n")}</pre>
                      </div>
                    ))}
                  </Stack>
                )
                : (
                  <Stack>
                    {answered.map((one) => (
                      <div key={one.host_id}>
                        <h3 className="fl-subhead">
                          {one.hostname || one.host_id} · {t("{n} lines", { n: one.lines?.length ?? 0 })}
                        </h3>
                        <pre className="fl-mono">{(one.lines ?? []).join("\n") || t("Nothing matched.")}</pre>
                      </div>
                    ))}
                  </Stack>
                )}
          </Card>
        ) : (
          <Card
            span={12}
            title={t("Results")}
            note={t("The answer of every host, side by side; pick a host to read its result.")}
          >
            {answered.length === 0
              ? <Empty>{open > 0 ? t("Waiting for the first host to answer…") : t("No host answered.")}</Empty>
              : (
                <Stack>
                  <Tabs
                    value={current?.host_id ?? ""}
                    onChange={setSelected}
                    tabs={answered.map((one) => ({ value: one.host_id, label: one.hostname || one.host_id }))}
                  />
                  {current && <Result action={view.action} host={current} />}
                </Stack>
              )}
          </Card>
        )}
      </Grid>
    </>
  );
}

/**
 * Withdrawing the hosts that have not answered.
 *
 * It is destructive and it goes in the trail, which is the one kind of
 * question that belongs in a dialog rather than on the page.
 */
function Withdraw({ view }: { view: ReadFanOutView }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const [reason, setReason] = useState("");
  const open = view.hosts.filter((one) => one.state === "queued" || one.state === "running");

  const cancel = useMutation({
    mutationFn: async (why: string) => {
      const outcomes = await Promise.allSettled(
        open.map((one) => api.post(`/api/v1/jobs/${one.job_id}/cancel`, { reason: why })),
      );
      return outcomes.filter((outcome) => outcome.status === "rejected").length;
    },
    onSuccess: (refused) => {
      void queryClient.invalidateQueries({ queryKey: ["read", view.id] });
      void queryClient.invalidateQueries({ queryKey: ["reads"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
      if (refused === 0) {
        toast.success(t("{n} hosts withdrawn from the read.", { n: open.length }));
      } else {
        toast.error(t("{n} of {total} hosts could not be withdrawn; see their jobs.", { n: refused, total: open.length }));
      }
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
  });

  return (
    <>
      <button
        type="button"
        className="fl-danger"
        disabled={cancel.isPending}
        onClick={() => setAsking(true)}
        data-testid="withdraw"
      >
        {cancel.isPending ? t("Withdrawing…") : t("Withdraw the open hosts")}
      </button>
      {asking && (
        <Modal
          title={t("Withdraw the {n} hosts still to answer?", { n: open.length })}
          onClose={() => setAsking(false)}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => setAsking(false)}>{t("Back")}</button>
              <button
                type="button"
                className="fl-danger"
                disabled={!reason.trim()}
                data-testid="withdraw-confirm"
                onClick={() => { setAsking(false); cancel.mutate(reason.trim()); }}
              >
                {t("Withdraw")}
              </button>
            </>
          }
        >
          <Note>
            {t("Each open job of this read is cancelled; a host already running a read the agent cannot stop stays until it answers. The reason goes to the audit trail with every job.")}
          </Note>
          <Fields>
            <Field label={t("Reason")} wide>
              <input value={reason} data-testid="withdraw-reason" onChange={(event) => setReason(event.target.value)} />
            </Field>
          </Fields>
        </Modal>
      )}
    </>
  );
}

type ProcessRow = { pid: number; user?: string; name: string; command?: string; state: string; rss_bytes: number; threads: number };
type DNSQuery = { name: string; addresses?: string[]; server?: string; error?: string; took_millis: number };

/** The result of a structured read for one host. */
function Result({ action, host }: { action: string; host: ReadFanOutHost }) {
  const t = useT();

  if (action === "process.list") {
    const snapshot = host.snapshot as { processes?: ProcessRow[]; total?: number; truncated?: boolean } | undefined;
    if (!snapshot) return <Empty>{t("The snapshot of this host has not been recorded yet.")}</Empty>;
    const processes = snapshot.processes ?? [];
    return (
      <Stack>
        <Note>
          {t("{n} of {total} processes", { n: processes.length, total: snapshot.total ?? processes.length })}
          {snapshot.truncated ? ` · ${t("output truncated")}` : ""}
        </Note>
        <Table
          rows={processes}
          keyOf={(one) => String(one.pid)}
          testId="process-list"
          empty={t("No process in the result.")}
          columns={[
            { key: "pid", head: "PID", num: true, cell: (one) => <code>{one.pid}</code> },
            { key: "user", head: t("User"), cell: (one) => one.user ?? <span className="fl-faint">—</span> },
            { key: "command", head: t("Command"), tight: true, cell: (one) => <code>{one.command ?? one.name}</code> },
            { key: "state", head: t("State"), minor: true, cell: (one) => one.state },
            { key: "rss", head: "RSS", num: true, cell: (one) => bytes(one.rss_bytes) },
            { key: "threads", head: t("Threads"), num: true, minor: true, cell: (one) => one.threads },
          ]}
        />
      </Stack>
    );
  }

  if (action === "dns.resolve.test") {
    const detail = host.detail as { queries?: { queries?: DNSQuery[] } } | undefined;
    const queries = detail?.queries?.queries ?? [];
    return (
      <Table
        rows={queries}
        keyOf={(one) => one.name}
        testId="dns-queries"
        empty={t("No query in the result.")}
        columns={[
          { key: "name", head: t("Name"), tight: true, cell: (one) => <code>{one.name}</code> },
          {
            key: "addresses",
            head: t("Addresses"),
            cell: (one) => (one.error
              ? <Pill tone="error">{one.error}</Pill>
              : <code>{(one.addresses ?? []).join(", ")}</code>),
          },
          {
            key: "server",
            head: t("Server"),
            minor: true,
            tight: true,
            // A resolver nobody named is unknown, not the empty string.
            cell: (one) => (one.server ? <code>{one.server}</code> : <span className="fl-faint">—</span>),
          },
          { key: "took", head: t("Took"), num: true, cell: (one) => `${one.took_millis} ms` },
        ]}
      />
    );
  }

  const shown = host.snapshot ?? host.detail;
  if (!shown) return <Empty>{t("The host answered without a typed result.")}</Empty>;
  return <pre className="fl-mono">{JSON.stringify(shown, null, 2)}</pre>;
}

export const READS_SCREEN = "next_reads";

export const READS: BoardEntry[] = [
  { key: "form", title: "New read", width: 12, height: 6 },
  { key: "states", title: "Hosts by state", width: 12, height: 1 },
  { key: "list", title: "Your reads", width: 9, height: 4 },
  { key: "operations", title: "By operation", width: 3, height: 3 },
];
