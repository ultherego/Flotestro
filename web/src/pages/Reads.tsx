import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, ApiError, LIST_PAGE, loadedItems, type Page } from "../lib/api";
import type { ReadFanOut, ReadFanOutHost, ReadFanOutView, Whoami } from "../lib/types";
import { bytes } from "../lib/format";
import { ErrorBox, ErrorCode, Time, Empty, JobState } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { Breakdown, StatusBar } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { OPERATIONS_INTERVAL } from "../lib/stream";
import { buildExpression, describeExpression, HostChooser, SelectorBuilder, type Rule } from "./Groups";
import { FacetList, useFleetFacets, useOperations, type Operation } from "./Bulk";
import { useT } from "../i18n";

/**
 * Diagnostic reads on many hosts at once.
 *
 * A read fan-out is the same read the operator orders on one host - the
 * process list, the journal, a security scan - ordered on a handful at
 * once. It is not a campaign: nothing changes, nothing is approved, and
 * there are no waves. One ordinary job per host carries the result; this
 * page merges what the hosts brought back.
 */
export function Reads() {
  const { id } = useParams();
  return id ? <FanOutPage id={id} /> : <ReadsList />;
}

/** The catalogue entry with what a fan-out reads from it. */
type FanOutOperation = Operation & { fanout_limit?: number; fanout_refusal?: string };

/** The address of the form with a read already filled in, for a host page. */
export function readsPrefill(action: string, payload: unknown): string {
  return `/reads?action=${encodeURIComponent(action)}&payload=${encodeURIComponent(JSON.stringify(payload, null, 2))}`;
}

function ReadsList() {
  const t = useT();
  const [prefill] = useSearchParams();
  // A link from a host page opens the form already filled in; the plain
  // page opens on the list.
  const [building, setBuilding] = useState(prefill.has("action"));
  // The list grows page by page from the newest read: an operator who
  // reads a lot keeps the old fan-outs one click away rather than losing
  // them past a fixed ceiling.
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
  const { data, error } = list;
  if (error) return <ErrorBox error={error} />;

  const reads = loadedItems(data);
  const sum = (key: keyof ReadFanOut["counts"]) => (data ? reads.reduce((n, read) => n + read.counts[key], 0) : undefined);
  const listed = t("among the {n} listed", { n: reads.length });
  const operations = Object.entries(
    reads.reduce<Record<string, number>>((acc, read) => { acc[read.action] = (acc[read.action] ?? 0) + 1; return acc; }, {}),
  ).sort((a, b) => b[1] - a[1]);

  return (
    <>
      <PageHeader
        icon="reads"
        title={t("Reads")}
        description={t("The same read on a handful of hosts at once: a diagnostic, not a change. Nothing is approved and nothing changes on the hosts.")}
        actions={
          <button className={building ? "secondary" : ""} onClick={() => setBuilding(!building)}>
            {building ? t("Hide the form") : t("New read")}
          </button>
        }
      />

      {building && <NewRead onDone={() => setBuilding(false)} />}

      <div className="widgets">
        {/* The bar counts host answers, not reads: four reads of four
            hosts are sixteen answers, and the caption says which. */}
        <Card className="span-12" title={t("Hosts by state")} description={t("every host of the {n} reads listed, counted once per read", { n: reads.length })}>
          <StatusBar segments={[
            { label: t("Queued"), value: sum("queued"), tone: "warn" },
            { label: t("Running"), value: sum("running"), tone: "info" },
            { label: t("Succeeded"), value: sum("succeeded"), tone: "ok" },
            { label: t("Failed"), value: sum("failed"), tone: "error" },
          ]} />
        </Card>

        <Card className="span-9" title={t("Your reads")} flush>
          {reads.length === 0 ? (
            <EmptyState action={!building && <button onClick={() => setBuilding(true)}>{t("New read")}</button>}>
              {t("No reads yet.")}
            </EmptyState>
          ) : (
            <>
              <table>
                <thead>
                  <tr><th>{t("Operation")}</th><th className="num">{t("Hosts")}</th><th>{t("Progress")}</th><th>{t("Reason")}</th><th>{t("Created")}</th></tr>
                </thead>
                <tbody>
                  {reads.map((read) => (
                    <tr key={read.id}>
                      <td><Link to={`/reads/${read.id}`} className="mono">{read.action}</Link></td>
                      <td className="num">{read.host_count}</td>
                      <td><CountChips counts={read.counts} /></td>
                      <td>{read.reason || "—"}</td>
                      <td><Time value={read.created_at} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {list.hasNextPage && (
                <p>
                  <button className="secondary" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                    {t("Load more")}
                  </button>
                </p>
              )}
            </>
          )}
        </Card>

        <Card className="span-3" title={t("By operation")} description={listed}>
          {!data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : operations.length === 0 ? (
            <p className="fp-blank">{t("No reads yet.")}</p>
          ) : (
            <Breakdown tone="neutral" items={operations.map(([action, n]) => ({ label: <span className="mono">{action}</span>, value: n }))} />
          )}
        </Card>
      </div>
    </>
  );
}

/** The four counts as chips, for a table cell. */
function CountChips({ counts }: { counts: ReadFanOut["counts"] }) {
  const t = useT();
  return (
    <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
      {counts.queued > 0 && <span className="chip" title={t("queued")}>{counts.queued} {t("queued")}</span>}
      {counts.running > 0 && <span className="chip" title={t("running")}>{counts.running} {t("running")}</span>}
      <span className="chip" title={t("succeeded")}>{counts.succeeded} {t("succeeded")}</span>
      {counts.failed > 0 && <span className="chip" title={t("failed")}>{counts.failed} {t("failed")}</span>}
    </span>
  );
}

/**
 * The payload a read starts from, for the operations the form knows. The
 * rest start empty; the operator writes the payload the operation takes.
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
 * The order form: the read, its payload, the hosts and the reason. The
 * operations come from the catalogue with the ceiling of hosts each one
 * fans out to; the selector is the one a campaign takes.
 */
function NewRead({ onDone }: { onDone: () => void }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [prefill] = useSearchParams();
  const operations = useOperations();
  const fannable = useMemo(
    () => ((operations.data?.items ?? []) as FanOutOperation[]).filter((item) => (item.fanout_limit ?? 0) > 0),
    [operations.data],
  );

  const [action, setAction] = useState(prefill.get("action") ?? "journal.read");
  const [payloadText, setPayloadText] = useState(
    prefill.get("payload") ?? JSON.stringify(DEFAULT_PAYLOADS[action] ?? {}, null, 2),
  );
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
  // The sites, environments and OS families the fleet has, for the
  // target fields' suggestions.
  const facets = useFleetFacets();

  // A read picked from the list starts from its own payload, unless the
  // form was opened with one already filled in.
  useEffect(() => {
    if (prefill.get("payload") && prefill.get("action") === action) return;
    setPayloadText(JSON.stringify(DEFAULT_PAYLOADS[action] ?? {}, null, 2));
  }, [action, prefill]);

  const chosen = fannable.find((item) => item.action === action);
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
      queryClient.invalidateQueries({ queryKey: ["reads"] });
      onDone();
      navigate(`/reads/${view.id}`);
    },
    onError: (error) => setErrorMessage(refusalMessage(error, t)),
  });

  const named = mode === "hosts" ? hostIDs.size > 0 : mode === "expression" ? expression !== null : Boolean(site || environment || osFamily);
  const tooMany = mode === "hosts" && limit > 0 && hostIDs.size > limit;
  const ready = Boolean(chosen) && payload.value !== undefined && named && !tooMany;

  return (
    <Card
      title={t("New read")}
      description={t("Every host gets an ordinary job with this payload; the results are merged here. A read needs no approval.")}
      footer={
        <Actions>
          <button onClick={() => create.mutate()} disabled={!ready || create.isPending}>
            {create.isPending ? t("Ordering…") : t("Read")}
          </button>
          <button className="secondary" onClick={onDone}>{t("Cancel")}</button>
          {errorMessage && <p className="page-error">{errorMessage}</p>}
        </Actions>
      }
    >
      <FieldGrid>
        <Field
          label={t("Operation")}
          hint={chosen ? t("Fans out to at most {n} hosts.", { n: limit }) : t("Only reads the registry opens to a fan-out are listed.")}
        >
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            {fannable.map((item) => (
              <option key={item.action} value={item.action}>
                {item.action} — {t("up to {n} hosts", { n: item.fanout_limit ?? 0 })}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("Reason")} hint={t("Optional; it goes to the audit log next to the order.")}>
          <input placeholder={t("e.g. checking the leak on the web tier")} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <Field label={t("Payload")} hint={payload.error ? t("The payload is not valid JSON.") : t("The same payload the host page sends for this read.")} wide>
          <textarea rows={6} className="mono" value={payloadText} onChange={(e) => setPayloadText(e.target.value)} spellCheck={false} />
        </Field>
      </FieldGrid>

      <h4 className="widget-subhead">{t("Targets")}</h4>
      <FieldGrid>
        <Field label={t("Named by")} hint={t("The ceiling applies to what the selector matches; a broader selector is refused, not trimmed.")}>
          <select value={mode} onChange={(e) => setMode(e.target.value as TargetMode)}>
            <option value="filters">{t("site, environment and OS")}</option>
            <option value="expression">{t("groups and tags")}</option>
            <option value="hosts">{t("hosts by name")}</option>
          </select>
        </Field>
        {mode === "filters" && (
          <>
            {/* The values the fleet really has are offered under each
                field; free text still goes through, and the ceiling
                below says what it matched. */}
            <Field label={t("Site")}>
              <input placeholder={t("site")} value={site} list="reads-sites" onChange={(e) => setSite(e.target.value)} />
              <FacetList id="reads-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")}>
              <input placeholder={t("environment")} value={environment} list="reads-environments" onChange={(e) => setEnvironment(e.target.value)} />
              <FacetList id="reads-environments" facets={facets.data?.by_environment} />
            </Field>
            <Field label={t("OS family")}>
              <input placeholder={t("e.g. debian")} value={osFamily} list="reads-os-families" onChange={(e) => setOsFamily(e.target.value)} />
              <FacetList id="reads-os-families" facets={facets.data?.by_os_family} />
            </Field>
          </>
        )}
      </FieldGrid>
      {mode === "expression" && (
        <>
          <SelectorBuilder rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
          <p className="source">
            {expression
              ? <>{t("the read will carry")} <span className="mono">{describeExpression(expression)}</span></>
              : t("give a rule a value; until then the selector names nobody")}
          </p>
        </>
      )}
      {mode === "hosts" && (
        <>
          <HostChooser selected={hostIDs} onChange={setHostIDs} />
          {tooMany && (
            <p className="page-error">{t("{n} hosts chosen; this read fans out to at most {limit}.", { n: hostIDs.size, limit })}</p>
          )}
        </>
      )}
    </Card>
  );
}

/** The payload text as an object, or the reason it is not one. */
function parsePayload(text: string): { value?: Record<string, unknown>; error?: string } {
  if (!text.trim()) return { value: {} };
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return { value: parsed as Record<string, unknown> };
    return { error: "not an object" };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * A refusal in the operator's words. A busy panel is not a wrong order:
 * the answer says to wait, and names what for.
 */
function refusalMessage(error: unknown, t: (key: string, params?: Record<string, string | number>) => string): string {
  if (error instanceof ApiError) {
    if (error.code === "fanout_busy") return `${t("The panel is busy with other reads; try again in a moment.")} ${error.message}`;
    if (error.code === "fanout_too_broad") return `${t("The selector names more hosts than this read fans out to; narrow it.")} ${error.message}`;
    return error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

/** One fan-out: the hosts by state, and the merged result. */
function FanOutPage({ id }: { id: string }) {
  const t = useT();
  const [selected, setSelected] = useState<string>("");
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
    // fan-out is a record and is not re-read.
    refetchInterval: (query) => {
      const view = query.state.data;
      return view && view.counts.queued + view.counts.running === 0 ? false : OPERATIONS_INTERVAL;
    },
  });
  if (read.error) return <ErrorBox error={read.error} />;
  const view = read.data;
  if (!view) return <Empty>{t("Loading…")}</Empty>;

  const open = view.counts.queued + view.counts.running;
  const answered = view.hosts.filter((host) => host.state === "succeeded");
  const current = view.hosts.find((host) => host.host_id === selected) ?? answered[0];

  return (
    <>
      <PageHeader
        icon="reads"
        breadcrumb={[{ label: t("Reads"), to: "/reads" }]}
        title={<span className="mono">{view.action}</span>}
        description={
          <>
            {t("Ordered by {who}", { who: view.created_by })} · <Time value={view.created_at} />
            {view.reason && <> · {view.reason}</>}
            {open > 0 ? ` · ${t("{n} hosts still to answer", { n: open })}` : ` · ${t("every host answered")}`}
          </>
        }
        actions={
          <>
            {canCancel && open > 0 && <CancelFanOut view={view} />}
            <Link className="button" to={readsPrefill(view.action, view.payload)}>{t("Order the same again")}</Link>
          </>
        }
      />

      <div className="widgets">
        <Card className="span-12" title={t("Hosts by state")}>
          <StatusBar segments={[
            { label: t("Queued"), value: view.counts.queued, tone: "warn" },
            { label: t("Running"), value: view.counts.running, tone: "info" },
            { label: t("Succeeded"), value: view.counts.succeeded, tone: "ok" },
            { label: t("Failed"), value: view.counts.failed, tone: "error" },
          ]} />
        </Card>

        <Card className="span-12" title={t("Hosts")} flush>
          <table>
            <thead>
              <tr><th>{t("Host")}</th><th>{t("State")}</th><th>{t("Result")}</th><th>{t("Finished")}</th><th>{t("Job")}</th></tr>
            </thead>
            <tbody>
              {view.hosts.map((host) => (
                <tr key={host.job_id}>
                  <td><Link to={`/hosts/${host.host_id}`}>{host.hostname || host.host_id}</Link></td>
                  <td><JobState state={host.state} /></td>
                  <td>
                    {host.error_code && <ErrorCode code={host.error_code} />}
                    {host.message && <span className="source"> {host.message}</span>}
                    {host.truncated && <span className="badge warn">{t("output truncated")}</span>}
                  </td>
                  <td><Time value={host.finished_at} /></td>
                  <td><Link to={`/jobs?fanout_id=${view.id}`} className="mono">{host.job_id.slice(0, 8)}</Link></td>
                </tr>
              ))}
              {view.skipped?.map((host) => (
                <tr key={host.host_id}>
                  <td><Link to={`/hosts/${host.host_id}`}>{host.hostname}</Link></td>
                  <td><JobState state="skipped" /></td>
                  <td><ErrorCode code={host.reason} /> <span className="source">{host.message}</span></td>
                  <td>—</td>
                  <td>—</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        {view.kind === "timeline" ? (
          <Card
            className="span-12"
            title={t("Timeline")}
            description={grouping === "timeline"
              ? t("The lines of every host in one sequence by their timestamps. The order between hosts is best-effort - clocks differ - and the order within a host is the host's own.")
              : t("The lines of every host, host by host, as each gave them.")}
            actions={
              <div className="tabs" style={{ margin: 0, borderBottom: 0 }}>
                <button className={grouping === "timeline" ? "active" : ""} onClick={() => setGrouping("timeline")}>{t("merged timeline")}</button>
                <button className={grouping === "host" ? "active" : ""} onClick={() => setGrouping("host")}>{t("group by host")}</button>
              </div>
            }
          >
            {answered.length === 0 ? (
              <Empty>{open > 0 ? t("Waiting for the first host to answer…") : t("No host answered.")}</Empty>
            ) : grouping === "timeline" ? (
              <>
                {(view.timeline ?? []).length === 0 ? (
                  <Empty>{t("No line carries a timestamp; see the lines by host below.")}</Empty>
                ) : (
                  <pre className="hm-log">
                    {(view.timeline ?? []).map((line, index) => (
                      <div key={index}><HostChip name={line.hostname || line.host_id} /> {line.line}</div>
                    ))}
                  </pre>
                )}
                {(view.untimed ?? []).map((group) => (
                  <div key={group.host_id}>
                    <h4 className="widget-subhead">{t("Without a timestamp: {host}", { host: group.hostname || group.host_id })}</h4>
                    <pre className="hm-log">{group.lines.join("\n")}</pre>
                  </div>
                ))}
              </>
            ) : (
              answered.map((host) => (
                <div key={host.host_id}>
                  <h4 className="widget-subhead">{host.hostname || host.host_id} · {t("{n} lines", { n: host.lines?.length ?? 0 })}</h4>
                  <pre className="hm-log">{(host.lines ?? []).join("\n") || t("Nothing matched.")}</pre>
                </div>
              ))
            )}
          </Card>
        ) : (
          <Card className="span-12" title={t("Results")} description={t("The answer of every host, side by side; pick a host to read its result.")}>
            {answered.length === 0 ? (
              <Empty>{open > 0 ? t("Waiting for the first host to answer…") : t("No host answered.")}</Empty>
            ) : (
              <>
                <div className="tabs">
                  {answered.map((host) => (
                    <button
                      key={host.host_id}
                      className={current?.host_id === host.host_id ? "active" : ""}
                      onClick={() => setSelected(host.host_id)}
                    >
                      {host.hostname || host.host_id}
                    </button>
                  ))}
                </div>
                {current && <StructuredResult action={view.action} host={current} />}
              </>
            )}
          </Card>
        )}
      </div>
    </>
  );
}

/**
 * Withdrawing the hosts that have not answered. A fan-out is nothing but
 * its jobs, so the cancel goes to each open job through the job's own
 * route, with one reason for all of them; a host already running a read
 * the agent cannot stop is refused by that route and counted here, not
 * hidden. The finished hosts keep their answers.
 */
function CancelFanOut({ view }: { view: ReadFanOutView }) {
  const t = useT();
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const open = view.hosts.filter((host) => host.state === "queued" || host.state === "running");

  const cancel = useMutation({
    mutationFn: async (reason: string) => {
      const outcomes = await Promise.allSettled(
        open.map((host) => api.post(`/api/v1/jobs/${host.job_id}/cancel`, { reason })),
      );
      return outcomes.filter((outcome) => outcome.status === "rejected").length;
    },
    onSuccess: (refused) => {
      queryClient.invalidateQueries({ queryKey: ["read", view.id] });
      queryClient.invalidateQueries({ queryKey: ["reads"] });
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      if (refused === 0) {
        toast.success(t("{n} hosts withdrawn from the read.", { n: open.length }));
      } else {
        toast.error(t("{n} of {total} hosts could not be withdrawn; see their jobs.", { n: refused, total: open.length }));
      }
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
  });

  const ask = async () => {
    const { ok, reason } = await confirm({
      title: t("Withdraw the {n} hosts still to answer?", { n: open.length }),
      body: <p>{t("Each open job of this read is cancelled; a host already running a read the agent cannot stop stays until it answers. The reason goes to the audit trail with every job.")}</p>,
      confirmLabel: t("Withdraw"),
      danger: true,
      reason: { required: true },
    });
    if (ok && reason) cancel.mutate(reason);
  };

  return (
    <button className="danger" onClick={ask} disabled={cancel.isPending}>
      {cancel.isPending ? t("Withdrawing…") : t("Withdraw the open hosts")}
    </button>
  );
}

/** The host a line came from, in front of it. */
function HostChip({ name }: { name: string }) {
  return <span className="chip chip-mono">{name}</span>;
}

type ProcessRow = { pid: number; user?: string; name: string; command?: string; state: string; rss_bytes: number; threads: number };
type DNSQuery = { name: string; addresses?: string[]; server?: string; error?: string; took_millis: number };

/**
 * The result of a structured read for one host. The process list and the
 * resolver test get a table, because those are what the operator reads
 * across hosts; everything else is shown as the host gave it.
 */
function StructuredResult({ action, host }: { action: string; host: ReadFanOutHost }) {
  const t = useT();
  if (action === "process.list") {
    const snapshot = host.snapshot as { processes?: ProcessRow[]; total?: number; truncated?: boolean } | undefined;
    const processes = snapshot?.processes ?? [];
    if (!snapshot) return <Empty>{t("The snapshot of this host has not been recorded yet.")}</Empty>;
    return (
      <>
        <Toolbar end={<span className="source">{t("{n} of {total} processes", { n: processes.length, total: snapshot.total ?? processes.length })}{snapshot.truncated ? ` · ${t("output truncated")}` : ""}</span>} />
        <table>
          <thead>
            <tr><th className="num">PID</th><th>{t("User")}</th><th>{t("Command")}</th><th>{t("State")}</th><th className="num">RSS</th><th className="num">{t("Threads")}</th></tr>
          </thead>
          <tbody>
            {processes.map((process) => (
              <tr key={process.pid}>
                <td className="num mono">{process.pid}</td>
                <td>{process.user ?? "?"}</td>
                <td className="mono">{process.command ?? process.name}</td>
                <td>{process.state}</td>
                <td className="num">{bytes(process.rss_bytes)}</td>
                <td className="num">{process.threads}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>
    );
  }
  if (action === "dns.resolve.test") {
    const detail = host.detail as { queries?: { queries?: DNSQuery[] } } | undefined;
    const queries = detail?.queries?.queries ?? [];
    return (
      <table>
        <thead>
          <tr><th>{t("Name")}</th><th>{t("Addresses")}</th><th>{t("Server")}</th><th className="num">{t("Took")}</th></tr>
        </thead>
        <tbody>
          {queries.map((query) => (
            <tr key={query.name}>
              <td className="mono">{query.name}</td>
              <td className="mono">{query.error ? <span className="badge error">{query.error}</span> : (query.addresses ?? []).join(", ")}</td>
              <td className="mono">{query.server ?? "—"}</td>
              <td className="num">{query.took_millis} ms</td>
            </tr>
          ))}
          {queries.length === 0 && <tr><td colSpan={4}><Empty>{t("No query in the result.")}</Empty></td></tr>}
        </tbody>
      </table>
    );
  }
  const shown = host.snapshot ?? host.detail;
  if (!shown) return <Empty>{t("The host answered without a typed result.")}</Empty>;
  return <pre className="hm-log">{JSON.stringify(shown, null, 2)}</pre>;
}
