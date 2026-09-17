import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, ApiError, loadedItems, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { toInstant } from "../../lib/format";
import type { AuditEvent } from "../../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { Foot, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, useHost } from "./shared";
import { hoursAgo } from "../Jobs";
import { actorKey, actorOf, actorView } from "../Audit";
import { useT } from "../../i18n";

/** How many events one page of the trail carries. */
const AUDIT_PAGE = 50;

/**
 * Who an actor is, in the operator's words: a person by the name it had,
 * a campaign by a link to it, the agent of this host by the host's name,
 * the panel as itself. The immutable identifier stays on hover - it is
 * what the trail keeps. The snapshot decides the words and the link; the
 * text of actor_id only stands in for an event written before it.
 */
export function actorLabel(
  event: Pick<AuditEvent, "actor_type" | "actor_id">,
  host: { id: string; hostname: string },
  t: (text: string, params?: Record<string, string | number>) => string,
): { text: string; to?: string; title?: string } {
  const actor = actorOf(event);
  const id = event.actor_id;
  if (!actor) {
    if (id.startsWith("campaign:")) {
      const campaign = id.slice("campaign:".length);
      return { text: t("campaign {id}", { id: campaign.slice(0, 8) }), to: `/campaigns/${encodeURIComponent(campaign)}`, title: id };
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
      text: actor.resource_name ? `${t("campaign")} ${actor.resource_name}` : t("campaign {id}", { id: actor.resource_id.slice(0, 8) }),
      to: who.to, title: actor.resource_id,
    };
  }
  return { text: who.text, to: who.to, title: who.id };
}

/**
 * The few keys of the detail an incident review reads first, as one
 * line; the whole record opens under the row.
 */
export function digest(detail: Record<string, unknown> | undefined): string {
  const interesting = ["reason", "action_type", "state", "permission", "scope", "error_code"];
  return interesting
    .filter((key) => detail?.[key] !== undefined && detail[key] !== "")
    .map((key) => `${key}=${String(detail?.[key])}`)
    .join(" · ")
    .slice(0, 120);
}

/**
 * The audit trail of one host.
 *
 * The trail is the fleet trail narrowed to the host, with the same
 * filters and the same pages: "the denials on this host since Monday" is
 * asked here the way it is asked on the fleet page, and a host with a long
 * history is browsed rather than cut off at the newest rows. Every event
 * opens on the whole record, because a digest of a few keys is not what an
 * incident review reads.
 */
export function HostAudit() {
  const t = useT();
  const host = useHost();
  const [outcome, setOutcome] = useState("");
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [since, setSince] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
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
    return <Empty>{t("You do not have permission to read this host's audit trail.")}</Empty>;
  }
  if (trail.error) return <ErrorBox error={trail.error} />;

  // The listed events by outcome, and by who caused them; unknown until
  // the trail loads.
  const events = trail.data ? loadedItems(trail.data) : undefined;
  // Grouped by the immutable identifier and the kind, not by the text of
  // the name: a renamed person is one actor across both names.
  const actors = Object.values((events ?? []).reduce<Record<string, { event: AuditEvent; count: number }>>((acc, event) => {
    const key = actorKey(event);
    const entry = acc[key] ?? { event, count: 0 };
    entry.count += 1;
    acc[key] = entry;
    return acc;
  }, {})).sort((a, b) => b.count - a.count).slice(0, 8);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Audit")}
        description={t("Who did what on this host, from the audit trail.")}
      />
      <Widgets>
      <Summary
        title={t("Outcomes")}
        description={filtered
          ? t("The {n} listed events on this host that match the filter, by how they ended.", { n: events?.length ?? 0 })
          : t("The last {n} events on this host, by how they ended.", { n: events?.length ?? AUDIT_PAGE })}
        span={8}
        segments={[
          { label: t("success"), value: countWhere(events, (event) => event.outcome === "success"), tone: "ok" },
          { label: t("failure"), value: countWhere(events, (event) => event.outcome === "failure"), tone: "error" },
          { label: t("denied"), value: countWhere(events, (event) => event.outcome === "denied"), tone: "warn" },
        ]}
      />
      <Section title={t("By actor")} span={4} description={t("Who caused the most of them.")}>
        {!events ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : !actors.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No events.")}</p>
        ) : (
          <Breakdown items={actors.map(({ event, count }) => {
            const who = actorLabel(event, host, t);
            return { label: <span title={who.title}>{who.text}</span>, value: count };
          })} />
        )}
      </Section>
      <Section
        title={t("Audit")}
        count={events?.length}
        span={12}
        tools={
          <>
            <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
              <option value="">{t("outcome: any")}</option>
              <option value="denied">{t("denials only")}</option>
              <option value="failure">{t("failures only")}</option>
              <option value="success">{t("successes only")}</option>
            </select>
            <input placeholder={t("action prefix, e.g. job.")} value={action} onChange={(e) => setAction(e.target.value)} />
            <input placeholder={t("actor")} value={actor} onChange={(e) => setActor(e.target.value)} />
            <label className="toggle">
              {t("Since")}{" "}
              <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
            </label>
            <span className="segmented">
              <button type="button" onClick={() => setSince(hoursAgo(1))}>{t("last hour")}</button>
              <button type="button" onClick={() => setSince(hoursAgo(24))}>{t("last 24 h")}</button>
              <button type="button" onClick={() => setSince(hoursAgo(24 * 7))}>{t("last 7 days")}</button>
            </span>
            {filtered && (
              <button type="button" className="secondary" onClick={() => { setOutcome(""); setAction(""); setActor(""); setSince(""); }}>
                {t("Clear filters")}
              </button>
            )}
          </>
        }
        flush
      >
        {!events ? (
          <Empty>{t("Loading…")}</Empty>
        ) : events.length === 0 ? (
          <Empty>{filtered ? t("No event matches the filter.") : t("No events.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Operation")}</th><th>{t("Result")}</th><th>{t("Details")}</th></tr></thead>
            <tbody>
              {events.map((event) => {
                const open = expanded === event.id;
                return (
                  <Fragment key={event.id}>
                    <tr>
                      <td>
                        {/* The row opens on the whole record, the way a job
                            row opens on its attempts: one mark at the left
                            edge instead of a link repeated on every row. */}
                        <button
                          className="expander"
                          aria-expanded={open}
                          aria-label={open ? t("Hide the record") : t("Show the record")}
                          title={open ? t("Hide the record") : t("Show the record")}
                          onClick={() => setExpanded(open ? null : event.id)}
                        >
                          {open ? "▾" : "▸"}
                        </button>
                        {" "}
                        <Time value={event.occurred_at} />
                      </td>
                      <td>
                        {(() => {
                          const who = actorLabel(event, host, t);
                          return (
                            <>
                              {who.to
                                ? <Link to={who.to} title={who.title}>{who.text}</Link>
                                : <span title={who.title}>{who.text}</span>}
                              {/* The immutable identifier beside the name
                                  it had, so a rename later still reads as
                                  one actor. */}
                              {who.title && who.title !== who.text && (
                                <> <span className="source hm-mono" title={who.title}>{who.title.slice(0, 8)}</span></>
                              )}
                            </>
                          );
                        })()}
                        {/* The session and how it was authenticated stand
                            under the actor: they say which sign-in acted,
                            which the name alone does not. */}
                        {(event.session_id || event.acr) && (
                          <div className="source">
                            {event.session_id && <span title={event.session_id}>{t("session")} {event.session_id.slice(0, 12)}</span>}
                            {event.session_id && event.acr && " · "}
                            {event.acr && <span title={t("Authentication context class")}>acr={event.acr}</span>}
                          </div>
                        )}
                      </td>
                      <td className="hm-mono">{event.action}</td>
                      <td><JobState state={event.outcome} /></td>
                      <td>
                        {/* A line of the detail, then the whole event as
                            the trail keeps it: the row shows four columns,
                            and an incident wants every key of the record. */}
                        {digest(event.detail)
                          ? <span className="source">{digest(event.detail)}</span>
                          : <span className="source">—</span>}
                      </td>
                    </tr>
                    {open && (
                      <tr className="detail-row">
                        <td colSpan={5}>
                          <pre style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(event, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </Table>
        )}
        {/* The next page comes on request; the trail has no total, because
            nobody counts a host's history, they browse it. */}
        {trail.hasNextPage && (
          <Foot>
            <span>{t("{n} listed", { n: events?.length ?? 0 })}</span>
            <button className="secondary" onClick={() => trail.fetchNextPage()} disabled={trail.isFetchingNextPage}>
              {trail.isFetchingNextPage ? t("Loading…") : t("Load more")}
            </button>
          </Foot>
        )}
      </Section>
      </Widgets>
    </ModulePage>
  );
}
