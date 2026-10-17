import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, ApiError, loadedItems, type Page } from "../../../lib/api";
import { useDebounced } from "../../../lib/debounce";
import { absoluteTime, relativeTime, toInstant } from "../../../lib/format";
import type { AuditEvent, Host } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { actorKey, actorView, outcomeTone, type AuditActor } from "../Audit";
import { hoursAgo } from "../Jobs";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Bars, Bones, Button, Card, Empty, Pill, Presets, Problem, Readout, Table, Toolbar,
  TwoLine, type Segment,
} from "../../kit";

/**
 * Who did what on this machine, and what the panel refused them.
 *
 * A refusal is not a failure and neither is a success: the three outcomes
 * are counted apart and wear three colours, because "what was not allowed
 * on this host" is as much a fact about it as what was. The whole record
 * of an event opens beside the list, verbatim, because an incident is read
 * key by key and not column by column.
 */

/** How many events one page of the trail carries. */
const AUDIT_PAGE = 50;

/**
 * Who an actor is, in the operator's words: a person by the name it had, a
 * campaign by a link to it, the agent of this host by the host's name, the
 * panel as itself.
 */
export function actorLabel(
  event: Pick<AuditEvent, "actor_type" | "actor_id"> & { actor?: AuditActor },
  host: { id: string; hostname: string },
  t: Translate,
): { text: string; to?: string; title?: string } {
  const actor = event.actor;
  const id = event.actor_id;
  if (!actor) {
    if (id.startsWith("campaign:")) {
      const campaign = id.slice("campaign:".length);
      return {
        text: t("campaign {id}", { id: campaign.slice(0, 8) }),
        to: `/campaigns/${encodeURIComponent(campaign)}`,
        title: id,
      };
    }
    if (event.actor_type === "agent" || id === host.id) {
      return { text: t("agent of {host}", { host: host.hostname }), title: id };
    }
    return { text: id };
  }
  // The agent of this very host: its own trail names it as such, and a
  // link to the host would lead where the reader already is.
  if (actor.resource_type === "host" && actor.resource_id === host.id) {
    return { text: t("agent of {host}", { host: host.hostname }), title: actor.resource_id };
  }
  const who = actorView(event, t);
  if (actor.resource_type === "campaign" && actor.resource_id) {
    return {
      text: actor.resource_name
        ? `${t("campaign")} ${actor.resource_name}`
        : t("campaign {id}", { id: actor.resource_id.slice(0, 8) }),
      to: who.to,
      title: actor.resource_id,
    };
  }
  return { text: who.text, to: who.to, title: who.id };
}

/**
 * The few keys of the detail an incident review reads first, as one line;
 * the whole record opens beside the row.
 */
export function digest(detail: Record<string, unknown> | undefined): string {
  const interesting = ["reason", "action_type", "state", "permission", "scope", "error_code"];
  return interesting
    .filter((key) => detail?.[key] !== undefined && detail[key] !== "")
    .map((key) => `${key}=${String(detail?.[key])}`)
    .join(" · ")
    .slice(0, 120);
}

/** A count of what satisfies a test, or undefined where the list itself is unknown. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

export function Audit({ host }: { host: Host }) {
  const t = useT();
  const [outcome, setOutcome] = useState("");
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [since, setSince] = useState("");
  const [opened, setOpened] = useState<number | null>(null);
  // The typed filters reach the server after a pause, not per keystroke.
  const settledAction = useDebounced(action.trim());
  const settledActor = useDebounced(actor.trim());

  const params = new URLSearchParams({ limit: String(AUDIT_PAGE) });
  if (outcome) params.set("outcome", outcome);
  if (settledAction) params.set("action_prefix", settledAction);
  if (settledActor) params.set("actor", settledActor);
  if (toInstant(since)) params.set("since", toInstant(since));
  const filtered = outcome !== "" || settledAction !== "" || settledActor !== "" || toInstant(since) !== "";

  const trail = useInfiniteQuery({
    queryKey: ["audit", host.id, params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<AuditEvent>>(`/api/v1/hosts/${host.id}/audit?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });

  if (trail.error instanceof ApiError && trail.error.forbidden) {
    return <Empty icon="audit">{t("You do not have permission to read this host's audit trail.")}</Empty>;
  }
  if (trail.error) return <Problem>{String(trail.error)}</Problem>;

  // The listed events by outcome, and by who caused them; unknown until
  // the trail loads, which is a dash and not a nought.
  const loaded = trail.data !== undefined;
  const events = loaded ? loadedItems(trail.data) : undefined;
  const outcomes: Segment[] = [
    { label: t("success"), value: countWhere(events, (one) => one.outcome === "success"), tone: "ok" },
    { label: t("failure"), value: countWhere(events, (one) => one.outcome === "failure"), tone: "error" },
    { label: t("denied"), value: countWhere(events, (one) => one.outcome === "denied"), tone: "warn" },
  ];

  // Grouped by the identifier that does not change and by the kind, not by
  // the text of the name: a renamed person is one actor across both names.
  const actors = Object.values((events ?? []).reduce<Record<string, { event: AuditEvent; count: number }>>((all, event) => {
    const key = actorKey(event);
    const entry = all[key] ?? { event, count: 0 };
    entry.count += 1;
    all[key] = entry;
    return all;
  }, {})).sort((a, b) => b.count - a.count).slice(0, 8);

  const rows = events ?? [];
  const listed = filtered
    ? t("The {n} listed events on this host that match the filter, by how they ended.", { n: rows.length })
    : t("The last {n} events on this host, by how they ended.", { n: loaded ? rows.length : AUDIT_PAGE });

  return (
    <Board screen={HOST_AUDIT_SCREEN} catalogue={HOST_AUDIT} drawn={{
      outcomes: (
        <Card title={t("Outcomes")} note={listed}>
          <Band segments={outcomes} testId="outcomes" />
        </Card>
      ),
      actors: (
        <Card title={t("By actor")} note={t("Who caused the most of them.")}>
          {!loaded
            ? <Bones rows={4} />
            : actors.length === 0
              ? <Empty icon="audit">{t("No events.")}</Empty>
              : (
                <Bars items={actors.map(({ event, count }) => {
                  const who = actorLabel(event, host, t);
                  return {
                    label: (
                      <Button
                        kind="word"
                        title={who.title ?? t("Only this actor")}
                        onClick={() => setActor(who.title ?? who.text)}
                      >
                        {who.text}
                      </Button>
                    ),
                    value: count,
                  };
                })} />
              )}
        </Card>
      ),
      events: (
        <Card
          title={t("Audit")}
          flush
          note={t("Who did what on this host, from the audit trail.")}
          foot={
            // The next page comes on request; the trail has no total,
            // because nobody counts a host's history, they browse it.
            <>
              <span className="fl-note">{t("{n} listed", { n: rows.length })}</span>
              {trail.hasNextPage && (
                <Button
                  kind="quiet"
                  onClick={() => void trail.fetchNextPage()}
                  disabled={trail.isFetchingNextPage}
                  testId="more"
                >
                  {trail.isFetchingNextPage ? t("loading…") : t("Load more")}
                </Button>
              )}
            </>
          }
        >
          <Toolbar>
            <select
              value={outcome}
              onChange={(event) => setOutcome(event.target.value)}
              aria-label={t("outcome: any")}
              data-testid="outcome"
            >
              <option value="">{t("outcome: any")}</option>
              <option value="denied">{t("denials only")}</option>
              <option value="failure">{t("failures only")}</option>
              <option value="success">{t("successes only")}</option>
            </select>
            <input
              placeholder={t("action prefix, e.g. job.")}
              aria-label={t("action prefix, e.g. job.")}
              value={action}
              onChange={(event) => setAction(event.target.value)}
              data-testid="action"
            />
            <input
              placeholder={t("actor")}
              aria-label={t("actor")}
              value={actor}
              onChange={(event) => setActor(event.target.value)}
              data-testid="actor"
            />
            <input
              type="datetime-local"
              value={since}
              onChange={(event) => setSince(event.target.value)}
              aria-label={t("Since")}
              data-testid="since"
            />
            <Presets
              label={t("Time range")}
              options={([[1, t("last hour")], [24, t("last 24 h")], [24 * 7, t("last 7 days")]] as const)
                .map(([hours, label]) => ({ label, onPick: () => setSince(hoursAgo(hours)) }))}
            />
            {filtered && (
              <Button
                kind="plain"
                onClick={() => { setOutcome(""); setAction(""); setActor(""); setSince(""); }}
                testId="clear"
              >
                {t("Clear filters")}
              </Button>
            )}
          </Toolbar>

          <Table
            rows={rows}
            keyOf={(one) => String(one.id)}
            rowTestId={(one) => `event-${one.id}`}
            /* The whole record opens under the event it belongs to, as the
               panel being replaced opened it: the row shows five columns,
               and an incident wants every key of what the trail kept. */
            opened={(one) => one.id === opened}
            detail={(one) => (
              <Readout
                label={t("The event as the trail wrote it")}
                value={JSON.stringify(one, null, 2)}
                lines={24}
                wrap
                testId="record"
              />
            )}
            testId="events"
            loading={trail.isLoading}
            empty={filtered ? t("No event matches the filter.") : t("No events.")}
            columns={[
              { key: "when", head: t("Time"), cell: (one) => (
                <span title={absoluteTime(one.occurred_at)}>{relativeTime(one.occurred_at)}</span>
              ) },
              { key: "actor", head: t("Actor"), cell: (one) => <ActorCell event={one} host={host} /> },
              // An operation reads as one word: cut, never broken over two
              // lines, where `host.enrollment.replace` would read as two
              // things.
              { key: "action", head: t("Operation"), tight: true, cell: (one) => (
                <code title={one.action}>{one.action}</code>
              ) },
              { key: "outcome", head: t("Result"), cell: (one) => (
                <Pill tone={outcomeTone(one.outcome)}>{t(one.outcome)}</Pill>
              ) },
              { key: "detail", head: t("Details"), minor: true, tight: true, cell: (one) => {
                const text = digest(one.detail);
                return text ? <span title={text}>{text}</span> : <span className="fl-faint">—</span>;
              } },
              { key: "open", actions: true, cell: (one) => (
                <Button
                  kind="quiet"
                  onClick={() => setOpened(one.id === opened ? null : one.id)}
                  testId={`open-${one.id}`}
                >
                  {one.id === opened ? t("Close") : t("Open")}
                </Button>
              ) },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

/**
 * The actor of an event: the name it had, the identifier it keeps under
 * it, and the sign-in that acted where the trail recorded one.
 */
function ActorCell({ event, host }: { event: AuditEvent; host: Host }) {
  const t = useT();
  const who = actorLabel(event, host, t);
  const name = who.to
    ? <Link to={who.to} title={who.title}>{who.text}</Link>
    : <span title={who.title}>{who.text}</span>;
  // The session and how it was authenticated stand under the actor: they
  // say which sign-in acted, which the name alone does not.
  const session = event.session_id || event.acr
    ? (
      <>
        {event.session_id && (
          <span title={event.session_id}>{`${t("session")} ${event.session_id.slice(0, 12)}`}</span>
        )}
        {event.session_id && event.acr && " · "}
        {event.acr && <span title={t("Authentication context class")}>{`acr=${event.acr}`}</span>}
      </>
    )
    // The immutable identifier beside the name it had, so a rename later
    // still reads as one actor.
    : who.title && who.title !== who.text
      ? <code title={who.title}>{who.title.slice(0, 8)}</code>
      : undefined;
  return <TwoLine sub={session}>{name}</TwoLine>;
}

/** The name this screen's arrangement is stored under. */
export const HOST_AUDIT_SCREEN = "next_host_audit";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_AUDIT: BoardEntry[] = [
  { key: "outcomes", title: "Outcomes", width: 8, height: 4 },
  { key: "actors", title: "By actor", width: 4, height: 5 },
  { key: "events", title: "Audit", width: 12, height: 11 },
];
