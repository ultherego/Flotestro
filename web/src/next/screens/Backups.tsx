import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Bars, Card, Chart, Empty, Kpi, Pill, Problem, Seg, Table, TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * What the fleet copies, where to, and how old the newest copy is.
 *
 * A backup breaks quietly: nobody notices that nothing has been copied for
 * three weeks until something has to be restored. So the server hands the
 * worst definitions first and the screen keeps that order, and the two
 * things that make a copy a safeguard rather than a promise - that it is
 * recent, and that somebody has read it back - are counted side by side.
 *
 * A host with no definition is not a host with nothing to copy; the panel
 * simply does not know whether anything copies it, and that is a third
 * answer with a colour of its own.
 */

type Item = {
  host_id: string;
  hostname: string;
  definition: string;
  tool: string;
  repository?: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  unverified: boolean;
  last_restore_at?: string;
};

type Repository = {
  repository: string;
  hosts: number;
  unverified: number;
  oldest_age_hours?: number;
  budget_key: string;
  capacity?: number;
  used?: number;
  claimants?: number;
};

/** The coverage head every fleet view carries: who was judged, and who was not. */
type Coverage = {
  total_hosts: number;
  evaluated_hosts: number;
  unknown_hosts: number;
  partial?: boolean;
  partial_reason?: string;
};

type Page = Coverage & {
  items: Item[];
  count: number;
  total: number;
  next_cursor?: string;
  counts: Record<string, number>;
  unverified: number;
  never_restored?: number;
  hosts_total: number;
  thresholds: { warning_hours: number; critical_hours: number; verification_days: number };
  repositories?: Repository[];
};

/**
 * The colour of a copy's age. A definition that has never run is as bad as
 * one that stopped running, and a definition nobody could judge is neither
 * of those: silence is not freshness.
 */
export function ageTone(status: string): Tone {
  if (status === "ok") return "ok";
  if (status === "warning") return "warn";
  if (status === "unknown") return "unknown";
  return "error";
}

/** How many days the calendar looks back over. */
const DAYS = 14;

/** How many rows one request asks the server for. */
const PAGE = 100;

export function Backups() {
  const t = useT();
  const [size, setSize] = useState(PAGE);

  const list = useInfiniteQuery({
    queryKey: ["next-backups", size],
    queryFn: ({ pageParam }) => api.get<Page>(
      `/api/v1/backups?limit=${size}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  // The first page carries the counts over every definition in scope; the
  // rows are the pages fetched so far, worst first as the server sorted them.
  const head = list.data?.pages[0];
  const rows = (list.data?.pages ?? []).flatMap((page) => page.items);
  // Nothing read yet is not nothing found, so a count stays undefined until
  // the first page is in and the tile shows a dash rather than a nought.
  const count = (key: string) => (head ? head.counts?.[key] ?? 0 : undefined);
  const never = count("never");
  const stale = count("critical");
  const ageing = count("warning");
  const unverified = head?.unverified;
  const unrestored = head ? head.never_restored ?? 0 : undefined;

  const states: Segment[] = [
    { label: t("Never ran"), value: never, tone: "error" },
    { label: t("Stale"), value: stale, tone: "error" },
    { label: t("Ageing"), value: ageing, tone: "warn" },
    { label: t("Fresh"), value: count("ok"), tone: "ok" },
    { label: t("Not judged"), value: count("unknown"), tone: "unknown" },
  ];

  const thresholds = head?.thresholds;
  const repositories = head?.repositories ?? [];

  // What the loaded definitions are copied with, and how many of them
  // anybody has ever read back. Both are counts over the loaded page and
  // the cards they fill say so.
  const byTool = Object.entries(rows.reduce<Record<string, number>>((tally, one) => {
    const key = one.tool || t("unnamed");
    tally[key] = (tally[key] ?? 0) + 1;
    return tally;
  }, {})).sort((a, b) => b[1] - a[1]);
  const verified = rows.filter((one) => !one.unverified).length;
  const restored = rows.filter((one) => !!one.last_restore_at).length;

  const calendar = lastDays(rows, DAYS);

  return (
    <Board screen={BACKUPS_SCREEN} catalogue={BACKUPS} drawn={{
      never: (
        <Kpi
          icon="backups"
          label={t("Never ran")}
          value={never ?? null}
          tone={never ? "error" : "ok"}
          note={t("defined, but no copy has ever been made")}
        />
      ),
      stale: (
        <Kpi
          icon="schedules"
          label={t("Stale")}
          value={stale ?? null}
          tone={stale ? "error" : "ok"}
          note={thresholds ? t("newest copy older than {n} h", { n: thresholds.critical_hours }) : undefined}
        />
      ),
      unverified: (
        <Kpi
          icon="security"
          label={t("Unverified")}
          value={unverified ?? null}
          tone={unverified ? "warn" : "ok"}
          note={thresholds ? t("nobody has checked them for {n} days", { n: thresholds.verification_days }) : undefined}
        />
      ),
      unrestored: (
        <Kpi
          icon="overview"
          label={t("Never restored")}
          value={unrestored ?? null}
          tone={unrestored ? "unknown" : "ok"}
          note={t("a copy nobody has read back is a promise, not a safeguard")}
        />
      ),
      age: (
        <Card
          title={t("Age of the newest copy")}
          note={head
            ? t("{n} definitions on {hosts} of {total} hosts.", {
                n: head.total, hosts: head.evaluated_hosts, total: head.total_hosts,
              })
            : undefined}
          foot={thresholds
            ? t("Ageing after {warning} h, stale after {critical} h.", {
                warning: thresholds.warning_hours, critical: thresholds.critical_hours,
              })
            : undefined}
        >
          <Band segments={states} testId="backup-states" />
        </Card>
      ),
      coverage: (
        <Card
          title={t("Hosts")}
          note={t("A host with nothing defined is not a host with fresh copies: the panel does not know whether anything copies it.")}
        >
          {head ? (
            <Bars items={[
              { label: t("With a definition"), value: head.evaluated_hosts, tone: "ok" },
              { label: t("Nothing defined"), value: head.unknown_hosts, tone: "unknown" },
            ]} />
          ) : (
            <Empty>{t("Reading backup state…")}</Empty>
          )}
        </Card>
      ),
      calendar: (
        <Card
          title={t("Last {n} days", { n: DAYS })}
          note={t("On how many of the {n} loaded definitions the newest successful copy fell on each day. Several empty days in a row are a schedule that stopped, seen before any copy is old enough to turn red.", { n: rows.length })}
        >
          {rows.length === 0 ? <Empty>{t("Nothing loaded to count.")}</Empty> : (
            <Chart
              labels={calendar.labels}
              series={[{ name: t("Newest copy made"), tone: "ok", values: calendar.values }]}
              everyLabel={2}
              height={130}
            />
          )}
        </Card>
      ),
      repositories: (
        <Card title={t("Repositories")} flush note={t("A backend is as good as its worst copy.")}>
          <Table
            rows={repositories}
            testId="repositories"
            keyOf={(one) => one.repository}
            rowTestId={(one) => `repository-${one.repository}`}
            empty={list.isLoading ? t("Reading backup state…") : t("No definition names a backend yet.")}
            columns={[
              {
                key: "repository",
                head: t("Repository"),
                tight: true,
                cell: (one) => (
                  <TwoLine sub={one.budget_key}><code title={one.repository}>{one.repository}</code></TwoLine>
                ),
              },
              {
                key: "definitions",
                head: t("Definitions"),
                num: true,
                cell: (one) => (
                  <TwoLine sub={one.unverified > 0 ? t("{n} unverified", { n: one.unverified }) : undefined}>
                    {one.hosts}
                  </TwoLine>
                ),
              },
              {
                key: "oldest",
                head: t("Oldest copy"),
                num: true,
                cell: (one) => (
                  // No reading is not an age of nought: a backend nobody
                  // has heard from may hold the oldest copy of all.
                  one.oldest_age_hours === undefined
                    ? <span className="fl-unknown">—</span>
                    : t("{n} h", { n: Math.round(one.oldest_age_hours) })
                ),
              },
              {
                key: "parallel",
                head: t("Parallel writes"),
                num: true,
                cell: (one) => (
                  one.capacity === undefined
                    ? <Pill tone="unknown">{t("no limit set")}</Pill>
                    : (
                      <TwoLine sub={(one.claimants ?? 0) > 0
                        ? t("{n} campaigns want it", { n: one.claimants ?? 0 })
                        : undefined}>
                        {`${one.used ?? 0} / ${one.capacity}`}
                      </TwoLine>
                    )
                ),
              },
            ]}
          />
        </Card>
      ),
      tools: (
        <Card
          title={t("Tools and verification")}
          note={t("Among the {n} definitions loaded here, not the whole fleet.", { n: rows.length })}
        >
          {rows.length === 0 ? <Empty>{t("Nothing loaded to count.")}</Empty> : (
            <>
              <Bars items={byTool.map(([tool, n]) => ({
                label: <span className="fl-mono">{tool}</span>, value: n, tone: "info" as Tone,
              }))} />
              <h3 className="fl-subhead">{t("Verification")}</h3>
              <Bars items={[
                { label: t("verified"), value: verified, tone: "ok" },
                { label: t("not verified"), value: rows.length - verified, tone: "warn" },
                { label: t("restored at least once"), value: restored, tone: "ok" },
                { label: t("never restored"), value: rows.length - restored, tone: "warn" },
              ]} />
            </>
          )}
        </Card>
      ),
      list: (
        <Card
          title={t("Definitions")}
          flush
          tools={
            <Seg
              value={String(size)}
              onChange={(value) => setSize(Number(value))}
              options={[
                { value: "50", label: "50" },
                { value: "100", label: "100" },
                { value: "200", label: "200" },
              ]}
            />
          }
          foot={
            list.hasNextPage ? (
              <button
                type="button"
                className="fl-quiet fl-small"
                onClick={() => list.fetchNextPage()}
                disabled={list.isFetchingNextPage}
                data-testid="more-backups"
              >
                {list.isFetchingNextPage
                  ? t("loading…")
                  : t("Load more ({n} left)", { n: (head?.total ?? 0) - rows.length })}
              </button>
            ) : head ? t("{shown} of {total}, the worst first", { shown: rows.length, total: head.total })
              : undefined
          }
        >
          <Table
            rows={rows}
            testId="backups"
            keyOf={(one) => `${one.host_id}-${one.definition}`}
            rowTestId={(one) => `backup-${one.hostname}-${one.definition}`}
            empty={list.isLoading
              ? t("Reading backup state…")
              : t("No host has a backup definition yet. Open a host and describe what to copy, where to and how long it stays.")}
            columns={[
              {
                key: "age",
                head: t("Age"),
                cell: (one) => (
                  <TwoLine sub={one.last_success_at
                    ? <span title={absoluteTime(one.last_success_at)}>{relativeTime(one.last_success_at)}</span>
                    : <span className="fl-unknown">{t("no copy recorded")}</span>}>
                    <Pill tone={ageTone(one.status)}>{age(t, one)}</Pill>
                  </TwoLine>
                ),
              },
              {
                key: "host",
                head: t("Host"),
                cell: (one) => <Link to={`/hosts/${one.host_id}/backups`}>{one.hostname}</Link>,
              },
              { key: "definition", head: t("Definition"), cell: (one) => one.definition },
              {
                key: "tool",
                head: t("Tool"),
                minor: true,
                cell: (one) => one.tool || <span className="fl-faint">—</span>,
              },
              {
                key: "destination",
                head: t("Destination"),
                minor: true,
                tight: true,
                cell: (one) => (
                  one.repository
                    ? <code title={one.repository}>{one.repository}</code>
                    : <span className="fl-faint">—</span>
                ),
              },
              {
                key: "verified",
                head: t("Verified"),
                cell: (one) => (
                  <TwoLine sub={one.last_restore_at
                    ? t("restored {when}", { when: relativeTime(one.last_restore_at) })
                    : t("never restored")}>
                    {one.unverified
                      ? <Pill tone="warn">{t("not verified")}</Pill>
                      : <Pill tone="ok">{t("verified")}</Pill>}
                  </TwoLine>
                ),
              },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

/** What the age pill says: hours while they are still readable, then days. */
function age(t: Translate, one: Item): string {
  if (one.status === "never") return t("never ran");
  if (one.age_hours === undefined) return t("unknown");
  return one.age_hours < 48
    ? t("{n} h", { n: Math.round(one.age_hours) })
    : t("{n} d", { n: Math.round(one.age_hours / 24) });
}

/**
 * How many of the loaded definitions had their newest successful copy on
 * each of the last days, oldest day first. A definition whose newest copy
 * is older than the window simply does not appear - that is what the age
 * column is for - so an empty calendar means nothing copied recently,
 * which is exactly the thing worth seeing.
 */
export function lastDays(items: Item[], days: number): { labels: string[]; values: number[] } {
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  const values = new Array<number>(days).fill(0);
  for (const one of items) {
    if (!one.last_success_at) continue;
    const day = new Date(one.last_success_at);
    day.setHours(0, 0, 0, 0);
    const back = Math.round((midnight.getTime() - day.getTime()) / 86400000);
    if (back >= 0 && back < days) values[days - 1 - back] += 1;
  }
  const labels = values.map((_, index) => {
    const date = new Date(midnight.getTime() - (days - 1 - index) * 86400000);
    return String(date.getDate());
  });
  return { labels, values };
}

export const BACKUPS_SCREEN = "next_backups";

export const BACKUPS: BoardEntry[] = [
  { key: "never", title: "Never ran", width: 3, height: 1 },
  { key: "stale", title: "Stale", width: 3, height: 1 },
  { key: "unverified", title: "Unverified", width: 3, height: 1 },
  { key: "unrestored", title: "Never restored", width: 3, height: 1 },
  { key: "age", title: "Age of the newest copy", width: 7, height: 2 },
  { key: "coverage", title: "Hosts", width: 5, height: 2 },
  // A chart of a fixed height over a fixed fortnight: it does not grow with the fleet.
  { key: "calendar", title: "Last 14 days", width: 8, height: 2 },
  { key: "tools", title: "Tools and verification", width: 4, height: 2 },
  { key: "repositories", title: "Repositories", width: 12, height: 4 },
  { key: "list", title: "Definitions", width: 12, height: 5 },
];
