import { Fragment, useEffect, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, loadedItems, LIST_PAGE, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { toInstant } from "../lib/format";
import type { AuditEvent } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { BarChart, Breakdown, StatusBar } from "../components/widgets";
import { useT } from "../i18n";

/**
 * The actor of an event as it was when the event was written: the
 * immutable identifier, the name then, the kind, and the resource that
 * acted for a non-person. The trail keeps it with the row; nothing here
 * is joined with the live tables.
 */
export type AuditActor = {
  principal_id?: string;
  subject?: string;
  display_name?: string;
  kind?: string;
  resource_type?: string;
  resource_id?: string;
  resource_name?: string;
  credential_id?: string;
};

/** The snapshot of an event's actor, where the trail kept one. */
export function actorOf(event: Pick<AuditEvent, "actor_id">): AuditActor | undefined {
  return (event as { actor?: AuditActor }).actor;
}

/** The resource types the panel has a page for. A machine identifier has none, and a host identifier pasted as an actor is not a host. */
const LINKED_RESOURCES: Record<string, (id: string) => string> = {
  host: (id) => `/hosts/${encodeURIComponent(id)}/overview`,
  relay: (id) => `/relays/${encodeURIComponent(id)}`,
  campaign: (id) => `/campaigns/${encodeURIComponent(id)}`,
};

/**
 * How an actor is shown: the name it had, the immutable identifier it
 * keeps, and a way to it only where the snapshot names a resource the
 * panel has a page for - a host, a relay, a campaign. The text of
 * actor_id decides nothing: a machine identifier parses as a host
 * identifier and is not one, and a name is not a page.
 */
export function actorView(
  event: Pick<AuditEvent, "actor_type" | "actor_id">,
  t: (text: string) => string,
): { text: string; id: string; kind: string; to?: string } {
  const actor = actorOf(event);
  if (!actor) {
    return { text: event.actor_id, id: event.actor_id, kind: event.actor_type };
  }
  const id = actor.principal_id || actor.resource_id || actor.subject || event.actor_id;
  const kind = actor.kind || event.actor_type;
  const named = actor.display_name || actor.resource_name;
  const text = named
    ? kind === "agent" ? `${t("agent")} ${named}` : named
    : actor.subject || event.actor_id;
  const resourceID = actor.resource_id ?? "";
  const link = actor.resource_type && resourceID ? LINKED_RESOURCES[actor.resource_type] : undefined;
  return { text, id, kind, to: link ? link(resourceID) : undefined };
}

/**
 * The key a review groups the trail by: the kind and the immutable
 * identifier, so a renamed person is one actor across both names and a
 * machine identifier never merges with a host.
 */
export function actorKey(event: Pick<AuditEvent, "actor_type" | "actor_id">): string {
  const actor = actorOf(event);
  if (!actor) return `${event.actor_type}:${event.actor_id}`;
  return `${actor.kind || event.actor_type}:${actor.principal_id || actor.resource_id || actor.subject || event.actor_id}`;
}

/**
 * The audit trail. Denials are as visible as successes.
 *
 * The trail is filtered on the server and read page by page: it grows
 * with every request the panel answers, and "the denials of this actor"
 * is a question for an index, not for a screen holding the last two
 * hundred rows.
 *
 * The filters live in the address as well: a view of the trail is a
 * thing to hand to somebody, and the address is how it is handed over.
 */
export function Audit() {
  const t = useT();
  const [initial, setSearchParams] = useSearchParams();
  const [outcome, setOutcome] = useState(initial.get("outcome") ?? "");
  const [actor, setActor] = useState(initial.get("actor") ?? "");
  const [action, setAction] = useState(initial.get("action") ?? "");
  const [targetType, setTargetType] = useState(initial.get("target_type") ?? "");
  const [targetID, setTargetID] = useState(initial.get("target_id") ?? "");
  // One actor by its immutable identifier and its kind: set from the
  // breakdown or handed over in the address, never typed - a name is
  // typed into the actor field, which reads actor_id as it was written.
  const [actorKind, setActorKind] = useState(initial.get("actor_kind") ?? "");
  const [actorPrincipalID, setActorPrincipalID] = useState(initial.get("actor_principal_id") ?? "");
  const [actorResourceID, setActorResourceID] = useState(initial.get("actor_resource_id") ?? "");
  // The bounds arrive as instants - a tile links here with one - and are
  // edited as the browser's local time.
  const [since, setSince] = useState(toLocalInput(initial.get("since")));
  const [until, setUntil] = useState(toLocalInput(initial.get("until")));
  const [expanded, setExpanded] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const settledActor = useDebounced(actor.trim());
  const settledAction = useDebounced(action.trim());
  const settledTargetType = useDebounced(targetType.trim());
  const settledTargetID = useDebounced(targetID.trim());

  // The filter as the server reads it, without the page size: the export
  // asks with the same one, and the address carries the same one.
  const filter = new URLSearchParams();
  if (outcome) filter.set("outcome", outcome);
  if (settledActor) filter.set("actor", settledActor);
  if (actorKind) filter.set("actor_kind", actorKind);
  if (actorPrincipalID) filter.set("actor_principal_id", actorPrincipalID);
  if (actorResourceID) filter.set("actor_resource_id", actorResourceID);
  if (settledAction) filter.set("action", settledAction);
  if (settledTargetType) filter.set("target_type", settledTargetType);
  if (settledTargetID) filter.set("target_id", settledTargetID);
  if (toInstant(since)) filter.set("since", toInstant(since));
  if (toInstant(until)) filter.set("until", toInstant(until));
  const filterKey = filter.toString();
  useEffect(() => {
    setSearchParams(new URLSearchParams(filterKey), { replace: true });
  }, [filterKey, setSearchParams]);

  const params = new URLSearchParams(filter);
  params.set("limit", String(LIST_PAGE));

  const trail = useInfiniteQuery({
    queryKey: ["audit", params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<AuditEvent>>(`/api/v1/audit?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });

  // The export is the trail between the bounds as one file, linked by a
  // hash chain; the browser carries the session, and the file is saved
  // through a link the page makes for it and removes again.
  const exportTrail = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const response = await fetch(`/api/v1/audit/export${filterKey ? `?${filterKey}` : ""}`, { credentials: "same-origin" });
      if (!response.ok) {
        let detail = response.statusText;
        try { detail = ((await response.json()) as { detail?: string }).detail ?? detail; } catch { /* a proxy's page, not the API's answer */ }
        throw new Error(detail);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = exportFileName(response.headers.get("Content-Disposition"));
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : String(error));
    } finally {
      setExporting(false);
    }
  };
  const applyPreset = (hours: number) => {
    setSince(toLocalInput(new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()));
    setUntil("");
  };

  if (trail.error instanceof ApiError && trail.error.forbidden) {
    return (
      <>
        <PageHeader title={t("Audit")} />
        <Card>
          <Empty>
            {t("You do not have permission to read the fleet-wide audit trail. A single host's audit trail is available in its own view.")}
          </Empty>
        </Card>
      </>
    );
  }
  if (trail.error) return <ErrorBox error={trail.error} />;

  const events = loadedItems(trail.data);
  const loaded = trail.data !== undefined;
  const listed = t("among the {n} listed", { n: events.length });
  const outcomeCount = (kind: AuditEvent["outcome"]) => (loaded ? events.filter((event) => event.outcome === kind).length : undefined);
  const hourly = eventsPerHour(events);
  // The actors behind the listed events, the busiest first: a trail
  // dominated by one token or one operator is read here at a glance.
  const byActor = Object.values(
    events.reduce<Record<string, { event: AuditEvent; count: number }>>((acc, event) => {
      const key = actorKey(event);
      const entry = acc[key] ?? { event, count: 0 };
      entry.count += 1;
      acc[key] = entry;
      return acc;
    }, {}),
  ).sort((x, y) => y.count - x.count).slice(0, 8);
  // One actor of the breakdown narrows the trail to that actor by its
  // immutable identifier, whatever it was called at the time.
  const pickActor = (event: AuditEvent) => {
    const actor = actorOf(event);
    if (!actor) {
      setActor(event.actor_id);
      return;
    }
    setActorKind(actor.kind ?? "");
    setActorPrincipalID(actor.principal_id ?? "");
    setActorResourceID(actor.principal_id ? "" : actor.resource_id ?? "");
    if (!actor.principal_id && !actor.resource_id) setActor(actor.subject ?? event.actor_id);
  };
  const clearActor = () => { setActorKind(""); setActorPrincipalID(""); setActorResourceID(""); };
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });

  return (
    <>
      <PageHeader
        title={t("Audit")}
        description={t("Every success and failure creates an event; so does every denial.")}
      />

      <div className="widgets">
        {/* The chart is drawn from the page in the browser, not from the
            database: it is the shape of what is listed, and the caption
            says so. A filter narrows the chart with the list. */}
        <Card className="span-8" title={t("Events per hour")} description={`${t("By outcome")} · ${listed}`}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : hourly.labels.length === 0 ? (
            <p className="fp-blank">{t("No events.")}</p>
          ) : (
            <BarChart
              labels={hourly.labels.map(hourLabel)}
              everyLabel={Math.max(1, Math.ceil(hourly.labels.length / 8))}
              series={[
                { name: t("success"), tone: "ok", values: hourly.success },
                { name: t("failure"), tone: "error", values: hourly.failure },
                { name: t("denied"), tone: "warn", values: hourly.denied },
              ]}
            />
          )}
        </Card>

        <Card className="span-4" title={t("Outcome")} description={listed}>
          <div className="fp-stack">
            <StatusBar compact segments={[
              { label: t("success"), value: outcomeCount("success"), tone: "ok" },
              { label: t("failure"), value: outcomeCount("failure"), tone: "error" },
              { label: t("denied"), value: outcomeCount("denied"), tone: "warn" },
            ]} />
            <div>
              <h4 className="widget-subhead">{t("By actor")}</h4>
              {!loaded ? (
                <Empty>{t("Loading…")}</Empty>
              ) : byActor.length === 0 ? (
                <p className="fp-blank">{t("No events.")}</p>
              ) : (
                <Breakdown tone="neutral" items={byActor.map((entry) => ({
                  label: (
                    <button type="button" className="link" onClick={() => pickActor(entry.event)} title={t("Only this actor")}>
                      <ActorCell event={entry.event} plain />
                    </button>
                  ),
                  value: entry.count,
                }))} />
              )}
            </div>
          </div>
        </Card>

        <Card
          className="span-12"
          title={t("Events")}
          description={t("The export is the trail between the bounds as JSON lines linked by a hash chain; flotestro-auditverify checks a saved file without the panel.")}
          actions={
            <button className="secondary" onClick={exportTrail} disabled={exporting}>
              {exporting ? t("Exporting…") : t("Export")}
            </button>
          }
          flush
        >
          {exportError && (
            <div className="warning">
              <div>{t("The export failed: {message}", { message: exportError })}</div>
              <div className="operations"><button onClick={() => setExportError(null)}>{t("Close")}</button></div>
            </div>
          )}
          <Toolbar end={<span>{t("{n} events", { n: events.length })}</span>}>
            <select value={outcome} onChange={(e) => setOutcome(e.target.value)} aria-label={t("Outcome")}>
              <option value="">{t("outcome: any")}</option>
              <option value="denied">{t("denials only")}</option>
              <option value="failure">{t("failures only")}</option>
              <option value="success">{t("successes only")}</option>
            </select>
            <input placeholder={t("actor")} aria-label={t("Actor")} value={actor} onChange={(e) => setActor(e.target.value)} />
            {(actorPrincipalID || actorResourceID) && (
              <span className="badge" title={actorPrincipalID || actorResourceID}>
                {actorKind || t("actor")} {(actorPrincipalID || actorResourceID).slice(0, 8)}{" "}
                <button type="button" className="link" onClick={clearActor} aria-label={t("Clear the actor filter")}>×</button>
              </span>
            )}
            <input placeholder={t("operation, e.g. job.create")} aria-label={t("Operation")} value={action} onChange={(e) => setAction(e.target.value)} />
            <input placeholder={t("target type, e.g. host")} aria-label={t("Target type")} value={targetType} onChange={(e) => setTargetType(e.target.value)} />
            <input placeholder={t("target identifier")} aria-label={t("Target identifier")} value={targetID} onChange={(e) => setTargetID(e.target.value)} />
            <label className="toggle">
              {t("Since")}{" "}
              <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
            </label>
            <label className="toggle">
              {t("Until")}{" "}
              <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
            </label>
            {/* The usual windows, one click each: the bound is the moment of
                the click, so the address keeps what was asked. */}
            <div className="segmented">
              <button onClick={() => applyPreset(1)}>{t("Last hour")}</button>
              <button onClick={() => applyPreset(24)}>{t("Last 24 h")}</button>
              <button onClick={() => applyPreset(24 * 7)}>{t("Last 7 days")}</button>
              {(since || until) && <button onClick={() => { setSince(""); setUntil(""); }}>{t("Any time")}</button>}
            </div>
          </Toolbar>

          {trail.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : events.length === 0 ? (
            <Empty>{t("No events.")}</Empty>
          ) : (
            <table>
              <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Kind")}</th><th>{t("Operation")}</th><th>{t("Target")}</th><th>{t("Result")}</th><th>{t("Details")}</th></tr></thead>
              <tbody>
                {events.map((event) => {
                  const changes = changedKeys(event.before, event.after);
                  const chain = event.approval_chain;
                  const open = expanded === event.id;
                  return (
                    <Fragment key={event.id}>
                      <tr>
                        <td>
                          <Time value={event.occurred_at} />
                          {/* The whole event, as the trail keeps it: the
                              digest above shows a few keys, and an incident
                              wants every one of them. */}
                          <div>
                            <button className="secondary" style={{ padding: "0 6px", fontSize: 11 }} onClick={() => setExpanded(open ? null : event.id)}>
                              {open ? t("Hide JSON") : t("Show JSON")}
                            </button>
                          </div>
                        </td>
                        <td className="mono">
                          <ActorCell event={event} />
                          {/* The session and how it was authenticated stand
                              under the actor: they say which sign-in acted,
                              which the name alone does not. */}
                          {(event.session_id || event.acr) && (
                            <div className="source fp-audit-session">
                              {event.session_id && (
                                <span title={`${t("Session")} ${event.session_id}`}>{t("session")} {event.session_id.slice(0, 12)}</span>
                              )}
                              {event.acr && <span title={t("Authentication context class")}>acr={event.acr}</span>}
                            </div>
                          )}
                        </td>
                        <td>{t(ACTOR_KINDS[actorOf(event)?.kind ?? event.actor_type] ?? actorOf(event)?.kind ?? event.actor_type)}</td>
                        <td className="mono">{event.action}</td>
                        <td className="mono"><TargetCell event={event} /></td>
                        <td><OutcomeBadge outcome={event.outcome} /></td>
                        <td className="source">{digest(event.detail, t)}</td>
                      </tr>
                      {/* What an approval rests on and what a change did,
                          under the row rather than in columns of their
                          own: the table keeps its width on a phone. */}
                      {open && (
                        <tr className="detail-row">
                          <td colSpan={7}>
                            <pre style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(event, null, 2)}</pre>
                          </td>
                        </tr>
                      )}
                      {(chain || changes.length > 0) && (
                        <tr className="detail-row">
                          <td colSpan={7}>
                            {chain && (
                              <p className="source fp-audit-chain">
                                {t("Approval chain")}: {t("ordered by {creator}, approved by {approvers}", {
                                  creator: chain.created_by,
                                  approvers: chain.approvers.length > 0 ? chain.approvers.join(", ") : "—",
                                })}
                              </p>
                            )}
                            {changes.length > 0 && (
                              <ul className="fp-audit-diff">
                                {changes.map((change) => (
                                  <li key={change.key}>
                                    <span className="mono">{change.key}</span>: <span className="fp-audit-before">{change.before}</span> → <span className="fp-audit-after">{change.after}</span>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
          {trail.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => trail.fetchNextPage()} disabled={trail.isFetchingNextPage}>
                {t("Load more")}
              </button>
            </p>
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * The listed events in hourly buckets, from the oldest listed to the
 * newest, with the outcomes side by side. An hour with no event keeps
 * its bucket, so a quiet night shows as a gap and not as a jump.
 */
function eventsPerHour(events: AuditEvent[]): { labels: string[]; success: number[]; failure: number[]; denied: number[] } {
  const empty = { labels: [], success: [], failure: [], denied: [] };
  if (events.length === 0) return empty;
  const hour = 60 * 60 * 1000;
  // One stamp per event, in step with the events; a stamp that could not
  // be read stays NaN and its event is left out of the buckets.
  const stamps = events.map((event) => Math.floor(new Date(event.occurred_at).getTime() / hour) * hour);
  const readable = stamps.filter((value) => !Number.isNaN(value));
  if (readable.length === 0) return empty;
  const first = Math.min(...readable);
  const last = Math.max(...readable);
  // A page that spans more than a fortnight is bucketed by hour all the
  // same; the bars get thin, but the shape stays honest.
  const buckets = Math.floor((last - first) / hour) + 1;
  const labels: string[] = [];
  const success = new Array<number>(buckets).fill(0);
  const failure = new Array<number>(buckets).fill(0);
  const denied = new Array<number>(buckets).fill(0);
  for (let i = 0; i < buckets; i++) labels.push(new Date(first + i * hour).toISOString());
  events.forEach((event, i) => {
    const stamp = stamps[i] ?? Number.NaN;
    if (Number.isNaN(stamp)) return;
    const index = Math.floor((stamp - first) / hour);
    if (event.outcome === "success") success[index]++;
    else if (event.outcome === "failure") failure[index]++;
    else if (event.outcome === "denied") denied[index]++;
  });
  return { labels, success, failure, denied };
}

/**
 * Where the target of an event lives in the panel, or null for a target
 * the panel has no page for. A host opens on its overview; an identity
 * opens the access screen searched for it, because identities have no
 * page of their own.
 */
export function targetLink(targetType?: string, targetID?: string): string | null {
  if (!targetType || !targetID) return null;
  const id = encodeURIComponent(targetID);
  switch (targetType) {
    case "host": return `/hosts/${id}/overview`;
    case "campaign": return `/campaigns/${id}`;
    case "job": return `/jobs/${id}`;
    case "principal": return `/access?tab=identities&q=${id}`;
    case "host_group": return `/groups/${id}`;
    case "relay": return `/relays/${id}`;
    case "policy": return `/policies/${id}`;
    case "read": return `/reads/${id}`;
    // The trail names a secret by its name, which is what its page is
    // addressed by.
    case "secret": return `/secrets/${id}`;
    // The rest have a list but no page of their own; the list is where
    // the object is found.
    case "alert_rule": return "/monitoring";
    case "budget": return "/budgets";
    case "notification_channel": return "/notifications";
    case "tag": return "/tags";
    case "pki": return "/access?tab=ca";
    default: return null;
  }
}

/**
 * The value of a datetime-local input for an instant, in the browser's
 * local time; empty for no instant or one that cannot be read. The
 * inverse of toInstant, for a bound that arrives in the address.
 */
export function toLocalInput(instant?: string | null): string {
  if (!instant) return "";
  const date = new Date(instant);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/**
 * The file name the server gave the export, read off the disposition
 * header; the server names the file after its bounds, and the saved file
 * is to carry that name. Without a header the file is the plain trail.
 */
export function exportFileName(disposition?: string | null): string {
  const match = /filename="([^"]+)"/.exec(disposition ?? "");
  return match?.[1] ?? "audit.jsonl";
}

/* Who acted, as the trail types it: a signed-in person or a token in
   their name, the panel itself, or an agent reporting for its host. */
const ACTOR_KINDS: Record<string, string> = {
  user: "person",
  service: "service",
  anonymous: "anonymous",
  system: "panel",
  agent: "agent",
  relay: "relay",
  machine: "machine",
};

/**
 * The target of an event: the host by the name and the address it had when
 * the event was written, where the trail kept them, else the type and the
 * start of the identifier. The full identifier stays in the title, and
 * the cell links to the object where the panel has a page for it.
 */
function TargetCell({ event }: { event: AuditEvent }) {
  if (!event.target_type) return <>—</>;
  const ref = `${event.target_type}/${event.target_id ?? ""}`;
  const to = targetLink(event.target_type, event.target_id);
  // A name is shown whole; an identifier by its first eight characters,
  // the way every other screen shortens one.
  const named = event.target_type === "secret" || event.target_type === "tag" || event.target_type === "settings";
  const short = `${event.target_type}/${named ? event.target_id ?? "" : (event.target_id ?? "").slice(0, 8)}`;
  if (!event.target_hostname && !event.target_address) {
    return to ? <Link to={to} title={ref}>{short}</Link> : <span title={ref}>{short}</span>;
  }
  const name = event.target_hostname || short;
  return (
    <span className="fp-host-cell" title={ref}>
      <span>{to ? <Link to={to}>{name}</Link> : name}</span>
      {event.target_address && <span className="fp-host-address">{event.target_address}</span>}
    </span>
  );
}

/**
 * The outcome in the colours of the bar above the list: a denial is not a
 * job state, and the grey badge of an unknown state is not what a refusal
 * looks like.
 */
function OutcomeBadge({ outcome }: { outcome: AuditEvent["outcome"] }) {
  const t = useT();
  const tone = outcome === "success" ? "ok" : outcome === "failure" ? "error" : outcome === "denied" ? "warn" : "unknown";
  const name = outcome === "success" ? t("success") : outcome === "failure" ? t("failure") : outcome === "denied" ? t("denied") : outcome;
  return <span className={`badge ${tone}`}>{name}</span>;
}

/**
 * The actor of an event as the trail kept it: the name it had then, the
 * immutable identifier on hover and, where the name is not the
 * identifier, beside it in small print; a link only to a host, a relay
 * or a campaign the snapshot names. `plain` leaves the link out, for a
 * cell that is itself a button.
 */
function ActorCell({ event, plain }: { event: AuditEvent; plain?: boolean }) {
  const t = useT();
  const who = actorView(event, t);
  const name = who.to && !plain ? <Link to={who.to} title={who.id}>{who.text}</Link> : <span title={who.id}>{who.text}</span>;
  if (who.text === who.id) return name;
  return (
    <>
      {name}{" "}
      <span className="source mono" title={who.id}>{who.id.slice(0, 8)}</span>
    </>
  );
}

type Change = { key: string; before: string; after: string };

/**
 * The keys whose value differs between the two sides of a change, each
 * side rendered for a line. A side the event does not carry - the
 * creation has nothing before it, the deletion nothing after - reads as a
 * dash, so every key of the other side is listed.
 */
function changedKeys(before: unknown, after: unknown): Change[] {
  if (before === undefined && after === undefined) return [];
  const left = asRecord(before);
  const right = asRecord(after);
  const keys = Array.from(new Set([...Object.keys(left), ...Object.keys(right)])).sort();
  return keys
    .filter((key) => JSON.stringify(left[key]) !== JSON.stringify(right[key]))
    .map((key) => ({ key, before: renderSide(left[key]), after: renderSide(right[key]) }))
    // An empty string against a missing key is the same nothing on both
    // sides; a line reading "— → —" says a change happened where none did.
    .filter((change) => change.before !== change.after);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function renderSide(value: unknown): string {
  if (value === undefined || value === null) return "—";
  if (typeof value === "string") return value === "" ? "—" : value;
  return JSON.stringify(value);
}

function digest(detail: Record<string, unknown>, t: (key: string) => string): string {
  // The keys of the detail as the trail keeps them, with the word each
  // is read by: "action_type=packages.plan" is a record, "type: packages
  // plan" is a sentence.
  const interesting: [string, string][] = [
    ["reason", "reason"], ["action_type", "type"], ["hostname", "host"],
    ["state", "state"], ["permission", "permission"], ["scope", "scope"],
  ];
  const parts = interesting
    .filter(([key]) => detail?.[key] !== undefined && detail[key] !== null && detail[key] !== "")
    .map(([key, word]) => `${t(word)}: ${String(detail[key])}`);
  return parts.join(" · ").slice(0, 120);
}
