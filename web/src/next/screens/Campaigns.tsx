import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { usePageSize } from "../../components/SortableTable";
import { relativeTime, absoluteTime, toInstant } from "../../lib/format";
import type { Campaign } from "../../lib/types";
import { stateName } from "../../lib/states";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Card, Find, Pager, Pill, Problem, Seg, Table, Toolbar, type Segment, type Tone,
} from "../kit";

/**
 * The campaigns: how the fleet is changed at scale.
 *
 * The list narrows on the server, so what is counted above it and what is
 * drawn below it are the same question asked once. A state nobody has a
 * campaign in is a word under the band rather than a sliver inside it.
 */

type Progress = { total: number; succeeded: number; failed: number; unknown: number; skipped: number; pending: number };
type CampaignPage = { items: (Campaign & { progress?: Progress })[]; count: number; total: number; limit: number; offset: number };

/** The states the filter offers, in the order a campaign moves through them. */
const STATES = [
  "planning", "planned", "awaiting_approval", "canary", "manual_gate", "running", "pausing", "paused", "canceling",
  "completed", "completed_with_issues", "failed", "plan_failed", "expired", "canceled",
];

const PAGE = 50;

export function Campaigns() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const state = params.get("state") ?? "";
  const [action, setAction] = useState(params.get("action") ?? "");
  const [requester, setRequester] = useState(params.get("requester") ?? "");
  const [since, setSince] = useState(params.get("since") ?? "");
  const [page, setPage] = useState(1);
  // The page size is the reader's preference and is kept in the browser,
  // under the same name the panel being replaced kept it under.
  const [size, setSize] = usePageSize("campaigns", PAGE);
  // Typed filters settle before they are sent: a letter at a time is a
  // request at a time, and the list under the hand flickers.
  const settledAction = useDebounced(action.trim());
  const settledRequester = useDebounced(requester.trim());
  const sinceInstant = toInstant(since);

  // The address follows the filter, not the other way round: what the
  // reader narrowed the list to is what the link they copy carries.
  useEffect(() => {
    const next = new URLSearchParams();
    if (state) next.set("state", state);
    if (settledAction) next.set("action", settledAction);
    if (settledRequester) next.set("requester", settledRequester);
    if (since) next.set("since", since);
    if (next.toString() !== params.toString()) setParams(next, { replace: true });
  }, [state, settledAction, settledRequester, since, params, setParams]);

  const query = new URLSearchParams({ limit: String(size) });
  if (state) query.set("state", state);
  if (settledAction) query.set("action", settledAction);
  if (settledRequester) query.set("requester", settledRequester);
  if (sinceInstant) query.set("since", sinceInstant);
  if (page > 1) query.set("offset", String((page - 1) * size));

  const list = useQuery({
    queryKey: ["campaigns", query.toString()],
    queryFn: () => api.get<CampaignPage>(`/api/v1/campaigns?${query}`),
  });

  // The band counts the page the server returned, which is what the filter
  // asked for: a count over the newest fifty of everything would answer a
  // question nobody put.
  const rows = list.data?.items ?? [];
  const count = (...states: string[]) => rows.filter((one) => states.includes(one.state)).length;
  const band: Segment[] = [
    { label: t("Awaiting approval"), value: count("awaiting_approval"), tone: "warn" },
    { label: t("In progress"), value: count("planning", "planned", "canary", "running"), tone: "info" },
    { label: t("At a gate"), value: count("manual_gate"), tone: "warn" },
    { label: t("Paused"), value: count("paused", "pausing"), tone: "warn" },
    { label: t("Completed"), value: count("completed"), tone: "ok" },
    { label: t("With issues"), value: count("completed_with_issues"), tone: "warn" },
    { label: t("Failed"), value: count("failed", "plan_failed", "expired"), tone: "error" },
    { label: t("Canceled"), value: count("canceled", "canceling"), tone: "unknown" },
  ];

  const narrow = (next: string) => {
    const after = new URLSearchParams(params);
    if (next) after.set("state", next); else after.delete("state");
    setParams(after, { replace: true });
    setPage(1);
  };

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  return (
    <Board screen={CAMPAIGNS_SCREEN} catalogue={CAMPAIGNS} drawn={{
      state: (
        <Card
          title={t("State")}
          note={list.data ? t("{shown} of {total} shown", { shown: rows.length, total: list.data.total }) : undefined}
        >
          <Band segments={band} testId="campaign-states" />
        </Card>
      ),
      list: (
        <Card
          title={t("Campaigns")}
          flush
          foot={
            <Pager
              page={page}
              size={size}
              total={list.data?.total ?? 0}
              onPage={setPage}
              onSize={setSize}
            />
          }
        >
          <Toolbar
            end={
              <Seg
                value={state}
                onChange={narrow}
                options={[
                  { value: "", label: t("All") },
                  { value: "awaiting_approval", label: t("Awaiting approval") },
                  { value: "running", label: t("Running") },
                  { value: "paused", label: t("Paused") },
                ]}
              />
            }
          >
            <Find value={requester} onChange={(value) => { setRequester(value); setPage(1); }}
                  placeholder={t("Requested by")} testId="requester" />
            <input
              value={action}
              onChange={(event) => { setAction(event.target.value); setPage(1); }}
              placeholder={t("operation")}
              aria-label={t("operation")}
              title={t("the operation the campaign orders, e.g. packages.upgrade")}
              data-testid="action"
            />
            <input
              type="datetime-local"
              value={since}
              onChange={(event) => { setSince(event.target.value); setPage(1); }}
              aria-label={t("Started after")}
              title={t("Started after")}
              data-testid="since"
            />
            <select
              value={state}
              onChange={(event) => narrow(event.target.value)}
              aria-label={t("state: any")}
              data-testid="state"
            >
              <option value="">{t("state: any")}</option>
              {STATES.map((one) => <option key={one} value={one}>{t(stateName(one))}</option>)}
            </select>
          </Toolbar>
          <Table
            rows={rows}
            keyOf={(one) => one.id}
            rowTestId={(one) => `campaign-${one.name}`}
            loading={list.isLoading} empty={t("No campaign matches this.")}
            columns={[
              { key: "name", head: t("Name"), cell: (one) => <Link to={`/campaigns/${one.id}`}>{one.name}</Link> },
              { key: "state", head: t("State"), cell: (one) => (
                <Pill tone={campaignTone(one.state)}>{t(stateName(one.state))}</Pill>
              ) },
              { key: "action", head: t("Operation"), tight: true, cell: (one) => (
                <code title={one.action_type}>{one.action_type}</code>
              ) },
              { key: "progress", head: t("Done / failed / pending"), num: true, cell: (one) => (
                one.progress
                  ? (
                    <span className="fl-nowrap">
                      <b className="fl-ok">{one.progress.succeeded}</b>
                      {" / "}
                      <b className={one.progress.failed > 0 ? "fl-error" : undefined}>{one.progress.failed}</b>
                      {" / "}
                      {one.progress.pending}
                    </span>
                  )
                  : <span className="fl-faint">—</span>
              ) },
              { key: "by", head: t("Requested by"), minor: true, tight: true, cell: (one) => (
                <span title={one.created_by}>{one.created_by}</span>
              ) },
              { key: "created", head: t("Created"), minor: true, cell: (one) => (
                <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
              ) },
              { key: "pause", head: t("Pause reason"), minor: true, tight: true, cell: (one) => (
                one.pause_reason ? <span title={one.pause_reason}>{one.pause_reason}</span> : <span className="fl-faint">—</span>
              ) },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

/** The state of a campaign as a tone: a gate is a person, a failure is a fault. */
export function campaignTone(state: string): Tone {
  if (state === "completed") return "ok";
  if (["failed", "plan_failed", "expired", "partially_applied"].includes(state)) return "error";
  if (["pausing", "paused", "manual_gate", "awaiting_approval", "planned", "completed_with_issues"].includes(state)) return "warn";
  if (["canceled", "canceling", "cancelled"].includes(state)) return "unknown";
  return "info";
}

export const CAMPAIGNS_SCREEN = "next_campaigns";

export const CAMPAIGNS: BoardEntry[] = [
  { key: "state", title: "State", width: 12, height: 2 },
  { key: "list", title: "Campaigns", width: 12, height: 11 },
];
