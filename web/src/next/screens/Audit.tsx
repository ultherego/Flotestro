import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, ApiError, fetchWithCredentials, loadedItems, LIST_PAGE, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, relativeTime, toInstant } from "../../lib/format";
import type { AuditEvent } from "../../lib/types";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Banner, Bars, Card, Chart, Empty, Fact, Facts, Field, Fields, HeadActions, Note, Pill, Problem, Readout, Row, Seg, type Segment, type Series, Stack, Table, type Tone, TwoLine,
} from "../kit";

/**
 * The trail: what the panel did, what it refused, and who asked for it.
 *
 * The whole of the narrowing happens on the server. A trail is the one
 * list where reading a page and then sifting it here would be a lie - the
 * three events that matter are rarely in the newest hundred - so every
 * field of the filter is a query parameter, and the address carries the
 * same one so that a question can be handed to somebody else.
 *
 * A refusal is not a failure and neither is a success: the three outcomes
 * carry three colours and are counted apart, because "what was not
 * allowed" is as much a fact about the fleet as what was.
 */

/** The actor of an event as the trail kept it at the moment it was written. */
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

/** How long a page the trail is read in. */
const PAGE_LIMIT = LIST_PAGE;

/** The windows the presets offer, as hours. */
const WINDOWS: Record<string, number> = { "1h": 1, "24h": 24, "7d": 24 * 7 };

export function Audit() {
  const t = useT();
  const [address, setAddress] = useSearchParams();
  const [outcome, setOutcome] = useState(address.get("outcome") ?? "");
  const [actor, setActor] = useState(address.get("actor") ?? "");
  const [action, setAction] = useState(address.get("action") ?? "");
  const [targetType, setTargetType] = useState(address.get("target_type") ?? "");
  const [targetID, setTargetID] = useState(address.get("target_id") ?? "");
  // One actor by the identifier it keeps whatever it was called: set from
  // the breakdown or handed over in the address, never typed. A name is
  // typed into the actor field, which reads actor_id as it was written.
  const [actorKind, setActorKind] = useState(address.get("actor_kind") ?? "");
  const [actorPrincipalID, setActorPrincipalID] = useState(address.get("actor_principal_id") ?? "");
  const [actorResourceID, setActorResourceID] = useState(address.get("actor_resource_id") ?? "");
  // The bounds arrive as instants - a tile links here with one - and are
  // edited in the browser's own time.
  const [since, setSince] = useState(toLocalInput(address.get("since")));
  const [until, setUntil] = useState(toLocalInput(address.get("until")));
  const [window_, setWindow] = useState("");
  const [opened, setOpened] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Typing is not a question: each field settles before the server is asked,
  // so a target identifier pasted in is one read and not thirty-six.
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
    setAddress(new URLSearchParams(filterKey), { replace: true });
  }, [filterKey, setAddress]);

  const query = new URLSearchParams(filter);
  query.set("limit", String(PAGE_LIMIT));

  const trail = useInfiniteQuery({
    queryKey: ["audit", query.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(query);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<AuditEvent>>(`/api/v1/audit?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });

  // The export is the trail between the bounds as one file linked by a hash
  // chain. The browser carries the session, and the file is saved through a
  // link the page makes for it and takes away again.
  const exportTrail = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const response = await fetchWithCredentials(`/api/v1/audit/export${filterKey ? `?${filterKey}` : ""}`);
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

  const applyWindow = (name: string) => {
    setWindow(name);
    const hours = WINDOWS[name];
    setSince(hours === undefined ? "" : toLocalInput(new Date(Date.now() - hours * 3600 * 1000).toISOString()));
    setUntil("");
  };
  // A bound edited by hand is nobody's preset any more.
  const editSince = (value: string) => { setSince(value); setWindow(""); };
  const editUntil = (value: string) => { setUntil(value); setWindow(""); };

  if (trail.error instanceof ApiError && trail.error.forbidden) {
    return (
      <>
        
        <Empty>
          {t("You may not read the fleet-wide trail. The trail of a single host is on that host's own screen.")}
        </Empty>
      </>
    );
  }
  if (trail.error) return <Problem>{String(trail.error)}</Problem>;

  const events = loadedItems(trail.data);
  const loaded = trail.data !== undefined;
  const listed = t("among the {n} read", { n: events.length });
  // Counted over what the server returned for this filter, which is the
  // question that was put; until it answers, nobody has counted anything.
  const outcomeCount = (kind: AuditEvent["outcome"]) =>
    (loaded ? events.filter((one) => one.outcome === kind).length : undefined);
  const outcomes: Segment[] = [
    { label: t("success"), value: outcomeCount("success"), tone: "ok" },
    { label: t("failure"), value: outcomeCount("failure"), tone: "error" },
    { label: t("denied"), value: outcomeCount("denied"), tone: "warn" },
  ];

  const hourly = eventsPerHour(events);
  const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit" });
  const series: Series[] = [
    { name: t("success"), tone: "ok", values: hourly.success },
    { name: t("failure"), tone: "error", values: hourly.failure },
    { name: t("denied"), tone: "warn", values: hourly.denied },
  ];

  // The actors behind what was read, the busiest first: a trail dominated
  // by one token or one operator is seen here at a glance.
  const byActor = Object.values(
    events.reduce<Record<string, { event: AuditEvent; count: number }>>((all, event) => {
      const key = actorKey(event);
      const entry = all[key] ?? { event, count: 0 };
      entry.count += 1;
      all[key] = entry;
      return all;
    }, {}),
  ).sort((x, y) => y.count - x.count).slice(0, 8);

  // One actor from the breakdown narrows the trail to that actor by the
  // identifier it keeps, whatever it was called at the time.
  const pickActor = (event: AuditEvent) => {
    const who = event.actor;
    if (!who) {
      setActor(event.actor_id);
      return;
    }
    setActorKind(who.kind ?? "");
    setActorPrincipalID(who.principal_id ?? "");
    setActorResourceID(who.principal_id ? "" : who.resource_id ?? "");
    if (!who.principal_id && !who.resource_id) setActor(who.subject ?? event.actor_id);
  };
  const clearActor = () => { setActorKind(""); setActorPrincipalID(""); setActorResourceID(""); };
  const pinned = actorPrincipalID || actorResourceID;

  return (
    <>
      <HeadActions><button type="button" className="fl-quiet" onClick={exportTrail} disabled={exporting} data-testid="export">
            {exporting ? t("Exporting…") : t("Export the trail")}
          </button></HeadActions>

      <Board screen={AUDIT_SCREEN} catalogue={AUDIT} drawn={{
        filter: (
          <Card
            title={t("What to read")}
            note={t("The trail narrows on the server: what is asked for is what is read.")}
          >
            <Stack>
              {exportError && (
                <Banner
                  tone="error"
                  actions={<button type="button" className="fl-quiet" onClick={() => setExportError(null)}>{t("Close")}</button>}
                >
                  {t("The export failed: {message}", { message: exportError })}
                </Banner>
              )}
              <Fields>
                <Field label={t("Outcome")}>
                  <select value={outcome} onChange={(event) => setOutcome(event.target.value)} data-testid="outcome">
                    <option value="">{t("outcome: any")}</option>
                    <option value="denied">{t("denials only")}</option>
                    <option value="failure">{t("failures only")}</option>
                    <option value="success">{t("successes only")}</option>
                  </select>
                </Field>
                <Field label={t("Actor")} hint={t("The name or the identifier as the event was written.")}>
                  <input value={actor} onChange={(event) => setActor(event.target.value)} data-testid="actor" />
                </Field>
                <Field label={t("Operation")} hint={t("For example job.create")}>
                  <input value={action} onChange={(event) => setAction(event.target.value)} data-testid="action" />
                </Field>
                <Field label={t("Target type")} hint={t("For example host")}>
                  <input value={targetType} onChange={(event) => setTargetType(event.target.value)} data-testid="target-type" />
                </Field>
                <Field label={t("Target identifier")}>
                  <input value={targetID} onChange={(event) => setTargetID(event.target.value)} data-testid="target-id" />
                </Field>
                <Field label={t("Since")}>
                  <input type="datetime-local" value={since} onChange={(event) => editSince(event.target.value)} data-testid="since" />
                </Field>
                <Field label={t("Until")}>
                  <input type="datetime-local" value={until} onChange={(event) => editUntil(event.target.value)} data-testid="until" />
                </Field>
              </Fields>
              <Row>
                <Seg
                  value={window_}
                  onChange={applyWindow}
                  options={[
                    { value: "", label: t("Any time") },
                    { value: "1h", label: t("Last hour") },
                    { value: "24h", label: t("Last 24 h") },
                    { value: "7d", label: t("Last 7 days") },
                  ]}
                />
                {pinned && (
                  <Pill tone="info" title={pinned}>
                    {`${actorKind || t("actor")} ${pinned.slice(0, 8)}`}
                    <button type="button" className="fl-word" onClick={clearActor} data-testid="clear-actor"
                            aria-label={t("Read every actor again")}>×</button>
                  </Pill>
                )}
              </Row>
            </Stack>
          </Card>
        ),
        per_hour: (
          <Card title={t("Events per hour")} note={`${t("By outcome")} · ${listed}`}>
            {!loaded
              ? <Empty>{t("Reading the trail…")}</Empty>
              : hourly.labels.length === 0
                ? <Empty>{t("No event answers this.")}</Empty>
                : (
                  <Chart
                    labels={hourly.labels.map(hourLabel)}
                    everyLabel={Math.max(1, Math.ceil(hourly.labels.length / 8))}
                    series={series}
                  />
                )}
          </Card>
        ),
        outcome: (
          <Card title={t("Outcome")} note={listed}>
            <Band segments={outcomes} testId="outcomes" />
          </Card>
        ),
        actors: (
          <Card title={t("By actor")} note={t("Who the read trail is made of. One of them narrows it to that actor.")}>
            {!loaded
              ? <Empty>{t("Reading the trail…")}</Empty>
              : byActor.length === 0
                ? <Empty>{t("No event answers this.")}</Empty>
                : (
                  <Bars items={byActor.map((entry) => ({
                    label: (
                      <button type="button" className="fl-word" onClick={() => pickActor(entry.event)}
                              title={t("Only this actor")}>
                        {actorView(entry.event, t).text}
                      </button>
                    ),
                    value: entry.count,
                  }))} />
                )}
          </Card>
        ),
        events: (
          <Card
            title={t("Events")}
            flush
            note={t("The export is this same filter as one file of JSON lines linked by a hash chain; flotestro-auditverify checks a saved file without the panel.")}
            foot={
              trail.hasNextPage
                ? (
                  <button type="button" className="fl-quiet fl-small" data-testid="more"
                          onClick={() => trail.fetchNextPage()} disabled={trail.isFetchingNextPage}>
                    {trail.isFetchingNextPage ? t("Reading the trail…") : t("Read further back")}
                  </button>
                )
                : t("{n} events read", { n: events.length })
            }
          >
            <Table
              rows={events}
              keyOf={(one) => String(one.id)}
              rowTestId={(one) => `event-${one.id}`}
              testId="events"
              /* An event opens under its own row, across the width of the
                 list. The panel being replaced read it there, and a card
                 elsewhere on the board makes the reader hunt for the thing
                 they just clicked. */
              opened={(one) => one.id === opened}
              detail={(one) => <EventDetail event={one} />}
              /* What an approval rested on and which fields a change
                 touched are read on the way past, not looked up: the
                 panel being replaced carried both under every row that
                 had them, and a trail is scanned before it is opened. */
              under={(one) => <EventUnder event={one} />}
              empty={trail.isLoading ? t("Reading the trail…") : t("No event answers this.")}
              columns={[
                { key: "when", head: t("When"), cell: (one) => (
                  <span title={absoluteTime(one.occurred_at)}>{relativeTime(one.occurred_at)}</span>
                ) },
                { key: "actor", head: t("Actor"), cell: (one) => <ActorCell event={one} /> },
                { key: "kind", head: t("Kind"), minor: true, cell: (one) => (
                  t(ACTOR_KINDS[one.actor?.kind ?? one.actor_type] ?? one.actor?.kind ?? one.actor_type)
                ) },
                // An operation reads as one word: cut, never broken over
                // two lines, where `host.enrollment.replace` would read as
                // two things.
                { key: "action", head: t("Operation"), tight: true, cell: (one) => (
                  <code title={one.action}>{one.action}</code>
                ) },
                { key: "target", head: t("Target"), tight: true, cell: (one) => <TargetCell event={one} /> },
                { key: "outcome", head: t("Result"), cell: (one) => (
                  <Pill tone={outcomeTone(one.outcome)}>{t(one.outcome)}</Pill>
                ) },
                { key: "digest", head: t("Detail"), minor: true, tight: true, cell: (one) => {
                  const text = digest(one.detail, t);
                  return text ? <span title={text}>{text}</span> : <span className="fl-faint">—</span>;
                } },
                { key: "open", actions: true, cell: (one) => (
                  <button type="button" className="fl-quiet fl-small" data-testid={`open-${one.id}`}
                          onClick={() => setOpened(one.id === opened ? null : one.id)}>
                    {one.id === opened ? t("Close") : t("Open")}
                  </button>
                ) },
              ]}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * The line a row carries without being clicked: what the approval rested
 * on, and which fields the event moved. A row with neither says nothing.
 */
function EventUnder({ event }: { event: AuditEvent }) {
  const t = useT();
  const chain = event.approval_chain;
  const changes = changedKeys(event.before, event.after);
  if (!chain && changes.length === 0) return null;
  return (
    <Note testId={`under-${event.id}`}>
      {chain && t("Ordered by {creator}, approved by {approvers}.", {
        creator: chain.created_by,
        approvers: chain.approvers.length > 0 ? chain.approvers.join(", ") : "\u2014",
      })}
      {changes.map((change, index) => (
        <span key={change.key}>
          {index > 0 || chain ? " \u00b7 " : ""}
          <code>{change.key}</code>{": "}
          <span className="fl-faint">{change.before}</span>{" \u2192 "}{change.after}
        </span>
      ))}
    </Note>
  );
}

/**
 * Everything the trail kept about one event: who, what, on what, how it
 * came out - and, where the event changed something, both sides of it.
 */
function EventDetail({ event }: { event: AuditEvent }) {
  const t = useT();
  const who = actorView(event, t);
  const changes = changedKeys(event.before, event.after);
  const chain = event.approval_chain;
  // The detail is the payload the writer of the event chose; every key of
  // it is shown, because an incident is read key by key.
  const detail = Object.entries(event.detail ?? {});
  const target = targetLink(event.target_type, event.target_id);
  return (
    <Stack>
      <Facts>
        <Fact label={t("When")}>{absoluteTime(event.occurred_at)}</Fact>
        <Fact label={t("Actor")}>
          <TwoLine sub={<code>{who.id}</code>}>
            {who.to ? <Link to={who.to}>{who.text}</Link> : who.text}
          </TwoLine>
        </Fact>
        <Fact label={t("Kind")}>{t(ACTOR_KINDS[who.kind] ?? who.kind)}</Fact>
        <Fact label={t("Operation")}><code>{event.action}</code></Fact>
        <Fact label={t("Target")}>
          {event.target_type
            ? (
              <TwoLine sub={event.target_address || undefined}>
                {target
                  ? <Link to={target}>{event.target_hostname || `${event.target_type}/${event.target_id ?? ""}`}</Link>
                  : <code>{`${event.target_type}/${event.target_id ?? ""}`}</code>}
              </TwoLine>
            )
            : <span className="fl-faint">{t("— nothing in particular")}</span>}
        </Fact>
        <Fact label={t("Result")}><Pill tone={outcomeTone(event.outcome)}>{t(event.outcome)}</Pill></Fact>
        {/* The sign-in behind the event: the name alone does not say which
            session acted, nor how it was authenticated. */}
        <Fact label={t("Session")}>
          {event.session_id
            ? <code title={event.session_id}>{event.session_id}</code>
            : <span className="fl-faint">{t("— not a sign-in")}</span>}
        </Fact>
        <Fact label={t("Authentication")}>
          {event.acr
            ? <>{event.acr}{event.amr && event.amr.length > 0 ? ` · ${event.amr.join(", ")}` : ""}</>
            : <span className="fl-faint">{t("— unknown")}</span>}
        </Fact>
      </Facts>

      {chain && (
        <Note>
          {t("Ordered by {creator}, approved by {approvers}.", {
            creator: chain.created_by,
            approvers: chain.approvers.length > 0 ? chain.approvers.join(", ") : "—",
          })}
        </Note>
      )}

      {changes.length > 0 && (
        <Table
          rows={changes}
          keyOf={(one) => one.key}
          testId="changes"
          columns={[
            { key: "field", head: t("Field"), tight: true, cell: (one) => <code title={one.key}>{one.key}</code> },
            { key: "before", head: t("Before"), tight: true, cell: (one) => (
              <span className="fl-faint" title={one.before}>{one.before}</span>
            ) },
            { key: "after", head: t("After"), tight: true, cell: (one) => <span title={one.after}>{one.after}</span> },
          ]}
        />
      )}

      {detail.length > 0 && (
        <Facts>
          {detail.map(([key, value]) => (
            <Fact key={key} label={<code>{key}</code>}>{renderSide(value)}</Fact>
          ))}
        </Facts>
      )}

      {/* The record itself, verbatim. An incident is read key by key,
          and a field the panel has no sentence for is exactly the one
          somebody is looking for when they open an event at all. */}
      <Readout
        label={t("The event as the trail wrote it")}
        value={JSON.stringify(event, null, 2)}
        lines={16}
        testId={`event-record-${event.id}`}
      />
    </Stack>
  );
}

/** The actor of an event: the name it had, the identifier it keeps under it. */
function ActorCell({ event }: { event: AuditEvent }) {
  const t = useT();
  const who = actorView(event, t);
  const name = who.to ? <Link to={who.to} title={who.id}>{who.text}</Link> : <span title={who.id}>{who.text}</span>;
  if (who.text === who.id) return <TwoLine>{name}</TwoLine>;
  return <TwoLine sub={<code title={who.id}>{who.id.slice(0, 8)}</code>}>{name}</TwoLine>;
}

/**
 * The target of an event: the host by the name and the address it had when
 * the event was written, where the trail kept them, else the type and the
 * start of the identifier.
 */
function TargetCell({ event }: { event: AuditEvent }) {
  const t = useT();
  if (!event.target_type) return <span className="fl-faint">{t("— nothing in particular")}</span>;
  const whole = `${event.target_type}/${event.target_id ?? ""}`;
  const to = targetLink(event.target_type, event.target_id);
  // A name is shown whole; an identifier by its first eight characters, the
  // way every other screen of the panel shortens one.
  const named = event.target_type === "secret" || event.target_type === "tag" || event.target_type === "settings";
  const short = `${event.target_type}/${named ? event.target_id ?? "" : (event.target_id ?? "").slice(0, 8)}`;
  const text = event.target_hostname || short;
  return to
    ? <Link to={to} title={whole}>{text}</Link>
    : <span title={whole}>{text}</span>;
}

/* ----------------------------------------------------------- the facts */

/** The colour of an outcome: a refusal is not a failure, and neither is a success. */
export function outcomeTone(outcome: string): Tone {
  if (outcome === "success") return "ok";
  if (outcome === "failure") return "error";
  if (outcome === "denied") return "warn";
  return "unknown";
}

/* Who acted, as the trail types it: a signed-in person or a token in their
   name, the panel itself, or an agent reporting for its host. */
const ACTOR_KINDS: Record<string, string> = {
  user: "person",
  service: "service",
  anonymous: "anonymous",
  system: "panel",
  agent: "agent",
  relay: "relay",
  machine: "machine",
};

/** The resource types the new panel has a screen for. A machine identifier has none. */
const LINKED_RESOURCES: Record<string, (id: string) => string> = {
  host: (id) => `/next/hosts/${encodeURIComponent(id)}`,
  relay: (id) => `/next/relays/${encodeURIComponent(id)}`,
  campaign: (id) => `/next/campaigns/${encodeURIComponent(id)}`,
};

/**
 * How an actor is shown: the name it had, the identifier it keeps, and a
 * way to it only where the snapshot names a resource the panel has a
 * screen for - a host, a relay, a campaign.
 */
export function actorView(
  event: Pick<AuditEvent, "actor_type" | "actor_id"> & { actor?: AuditActor },
  t: (text: string) => string,
): { text: string; id: string; kind: string; to?: string } {
  const who = event.actor;
  if (!who) return { text: event.actor_id, id: event.actor_id, kind: event.actor_type };
  const id = who.principal_id || who.resource_id || who.subject || event.actor_id;
  const kind = who.kind || event.actor_type;
  const named = who.display_name || who.resource_name;
  const text = named
    ? kind === "agent" ? `${t("agent")} ${named}` : named
    : who.subject || event.actor_id;
  const resourceID = who.resource_id ?? "";
  const link = who.resource_type && resourceID ? LINKED_RESOURCES[who.resource_type] : undefined;
  return { text, id, kind, to: link ? link(resourceID) : undefined };
}

/**
 * The key the breakdown groups by: the kind and the identifier that does
 * not change, so a renamed person is one actor across both names and a
 * machine identifier never merges with a host.
 */
export function actorKey(event: Pick<AuditEvent, "actor_type" | "actor_id"> & { actor?: AuditActor }): string {
  const who = event.actor;
  if (!who) return `${event.actor_type}:${event.actor_id}`;
  return `${who.kind || event.actor_type}:${who.principal_id || who.resource_id || who.subject || event.actor_id}`;
}

/** Where the target of an event lives in the new panel, or null for one it has no screen for. */
export function targetLink(targetType?: string, targetID?: string): string | null {
  if (!targetType || !targetID) return null;
  const id = encodeURIComponent(targetID);
  switch (targetType) {
    case "host": return `/next/hosts/${id}`;
    case "campaign": return `/next/campaigns/${id}`;
    case "job": return `/next/jobs/${id}`;
    case "principal": return `/next/access?tab=identities&q=${id}`;
    case "host_group": return `/next/groups/${id}`;
    case "relay": return `/next/relays/${id}`;
    case "policy": return `/next/policies/${id}`;
    case "read": return `/next/reads/${id}`;
    // The trail names a secret by its name, which is what its screen is
    // addressed by.
    case "secret": return `/next/secrets/${id}`;
    // The rest have a list but no screen of their own; the list is where
    // the object is found.
    case "alert_rule": return "/next/monitoring";
    case "budget": return "/next/budgets";
    case "notification_channel": return "/next/notifications";
    case "tag": return "/next/tags";
    // The fleet authority is a section of the settings screen in this
    // panel; the old one's access tab for it does not exist here.
    case "pki": return "/next/settings";
    default: return null;
  }
}

/**
 * The value of a datetime-local input for an instant, in the browser's own
 * time; empty for no instant or one that cannot be read.
 */
export function toLocalInput(instant?: string | null): string {
  if (!instant) return "";
  const date = new Date(instant);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/**
 * The name the server gave the export, read off the disposition header: the
 * server names the file after its bounds, and the saved file carries it.
 */
export function exportFileName(disposition?: string | null): string {
  const match = /filename="([^"]+)"/.exec(disposition ?? "");
  return match?.[1] ?? "audit.jsonl";
}

/**
 * What was read, in hourly buckets from the oldest to the newest, the three
 * outcomes side by side.
 */
export function eventsPerHour(events: AuditEvent[]): {
  labels: string[]; success: number[]; failure: number[]; denied: number[];
} {
  const nothing = { labels: [], success: [], failure: [], denied: [] };
  if (events.length === 0) return nothing;
  const hour = 60 * 60 * 1000;
  // One stamp per event, in step with the events; a stamp that could not be
  // read stays NaN and its event is left out of the buckets.
  const stamps = events.map((one) => Math.floor(new Date(one.occurred_at).getTime() / hour) * hour);
  const readable = stamps.filter((one) => !Number.isNaN(one));
  if (readable.length === 0) return nothing;
  const first = Math.min(...readable);
  const last = Math.max(...readable);
  // A page spanning more than a fortnight is bucketed by the hour all the
  // same: the bars get thin, but the shape stays honest.
  const buckets = Math.floor((last - first) / hour) + 1;
  const labels: string[] = [];
  const success = new Array<number>(buckets).fill(0);
  const failure = new Array<number>(buckets).fill(0);
  const denied = new Array<number>(buckets).fill(0);
  for (let i = 0; i < buckets; i++) labels.push(new Date(first + i * hour).toISOString());
  events.forEach((one, i) => {
    const stamp = stamps[i] ?? Number.NaN;
    if (Number.isNaN(stamp)) return;
    const index = Math.floor((stamp - first) / hour);
    if (one.outcome === "success") success[index]++;
    else if (one.outcome === "failure") failure[index]++;
    else if (one.outcome === "denied") denied[index]++;
  });
  return { labels, success, failure, denied };
}

export type Change = { key: string; before: string; after: string };

/** The keys whose value differs between the two sides of a change. */
export function changedKeys(before: unknown, after: unknown): Change[] {
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

/** The keys of a detail worth a column's width, in the words they are read by. */
export function digest(detail: Record<string, unknown>, t: (key: string) => string): string {
  const interesting: [string, string][] = [
    ["reason", "reason"], ["action_type", "type"], ["hostname", "host"],
    ["state", "state"], ["permission", "permission"], ["scope", "scope"],
  ];
  return interesting
    .filter(([key]) => detail?.[key] !== undefined && detail[key] !== null && detail[key] !== "")
    .map(([key, word]) => `${t(word)}: ${String(detail[key])}`)
    .join(" · ")
    .slice(0, 120);
}

export const AUDIT_SCREEN = "next_audit";

export const AUDIT: BoardEntry[] = [
  { key: "filter", title: "What to read", width: 12, height: 3 },
  { key: "per_hour", title: "Events per hour", width: 8, height: 3 },
  { key: "outcome", title: "Outcome", width: 4, height: 2 },
  { key: "events", title: "Events", width: 12, height: 6 },
  { key: "actors", title: "By actor", width: 4, height: 3 },
];
