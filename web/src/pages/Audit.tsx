import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ApiError, loadedItems, LIST_PAGE, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { toInstant } from "../lib/format";
import type { AuditEvent } from "../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../components/ui";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { useT } from "../i18n";

/**
 * The audit trail. Denials are as visible as successes.
 *
 * The trail is filtered on the server and read page by page: it grows
 * with every request the panel answers, and "the denials of this actor"
 * is a question for an index, not for a screen holding the last two
 * hundred rows.
 */
export function Audit() {
  const t = useT();
  const [initial] = useSearchParams();
  const [outcome, setOutcome] = useState(initial.get("outcome") ?? "");
  const [actor, setActor] = useState(initial.get("actor") ?? "");
  const [action, setAction] = useState(initial.get("action") ?? "");
  const [targetType, setTargetType] = useState(initial.get("target_type") ?? "");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const settledActor = useDebounced(actor.trim());
  const settledAction = useDebounced(action.trim());
  const settledTargetType = useDebounced(targetType.trim());

  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (outcome) params.set("outcome", outcome);
  if (settledActor) params.set("actor", settledActor);
  if (settledAction) params.set("action", settledAction);
  if (settledTargetType) params.set("target_type", settledTargetType);
  if (toInstant(since)) params.set("since", toInstant(since));
  if (toInstant(until)) params.set("until", toInstant(until));

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

  return (
    <>
      <PageHeader
        title={t("Audit")}
        description={t("Every success and failure creates an event; so does every denial.")}
      />

      <Card flush>
        <Toolbar end={<span>{t("{n} events", { n: events.length })}</span>}>
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">{t("outcome: any")}</option>
            <option value="denied">{t("denials only")}</option>
            <option value="failure">{t("failures only")}</option>
            <option value="success">{t("successes only")}</option>
          </select>
          <input placeholder={t("actor")} value={actor} onChange={(e) => setActor(e.target.value)} />
          <input placeholder={t("operation, e.g. job.create")} value={action} onChange={(e) => setAction(e.target.value)} />
          <input placeholder={t("target type, e.g. host")} value={targetType} onChange={(e) => setTargetType(e.target.value)} />
          <label className="toggle">
            {t("Since")}{" "}
            <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
          </label>
          <label className="toggle">
            {t("Until")}{" "}
            <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
          </label>
        </Toolbar>

        {trail.isLoading ? (
          <Empty>{t("Loading…")}</Empty>
        ) : events.length === 0 ? (
          <Empty>{t("No events.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Time")}</th><th>{t("Actor")}</th><th>{t("Kind")}</th><th>{t("Operation")}</th><th>{t("Target")}</th><th>{t("Result")}</th><th>{t("Details")}</th></tr></thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td><Time value={event.occurred_at} /></td>
                  <td className="mono">{event.actor_id}</td>
                  <td>{event.actor_type}</td>
                  <td className="mono">{event.action}</td>
                  <td className="mono">{event.target_type ? `${event.target_type}/${(event.target_id ?? "").slice(0, 8)}` : "—"}</td>
                  <td><JobState state={event.outcome} /></td>
                  <td className="source">{digest(event.detail)}</td>
                </tr>
              ))}
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
    </>
  );
}

function digest(detail: Record<string, unknown>): string {
  const interesting = ["reason", "action_type", "hostname", "state", "permission", "scope"];
  const parts = interesting
    .filter((key) => detail?.[key] !== undefined)
    .map((key) => `${key}=${String(detail[key])}`);
  return parts.join(" ").slice(0, 90);
}
