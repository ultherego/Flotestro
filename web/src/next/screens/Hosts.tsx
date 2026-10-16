import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { relativeTime, absoluteTime } from "../../lib/format";
import type { FleetActivity, Host } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Bars, Card, Dot, Empty, Find, Grid, HeadActions, Meter, Pill, Problem, Seg, Table, Tag, Tags, type Tone, TwoLine,
} from "../kit";

/**
 * The fleet as a list: what each host is, whether it answers, and what it
 * is carrying that somebody may have to deal with.
 *
 * The narrowing is the server's - the counts beside the filters are taken
 * over the whole fleet the reader may see, not over the page that happens
 * to be loaded, so a filter never lies about how much is behind it.
 */

type Page = { items: Host[]; next_cursor?: string; total?: number };
type Connection = "" | "online" | "stale" | "offline" | "unknown";

export function Hosts() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const connection = (params.get("connection_state") ?? "") as Connection;

  const query = useMemo(() => {
    const out = new URLSearchParams();
    if (connection) out.set("connection_state", connection);
    if (search.trim()) out.set("q", search.trim());
    out.set("limit", "50");
    return out;
  }, [connection, search]);

  const hosts = useInfiniteQuery({
    queryKey: ["hosts", query.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(query);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page>(`/api/v1/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    // A host's state changes through its heartbeat, not only through
    // somebody pressing something here.
    refetchInterval: REFRESH_INTERVAL,
  });

  // The facets are counted in the database over the whole visible fleet, so
  // they do not depend on which page is loaded.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  if (hosts.error) return <Problem>{String(hosts.error)}</Problem>;

  const rows = (hosts.data?.pages ?? []).flatMap((page) => page.items);
  const a = activity.data;
  const count = (state: string) => a?.by_connection_state.find((one) => one.key === state)?.count ?? 0;
  const facet = (key: string) => (key === "" || key === "unknown" ? t("unknown") : key);
  const setConnection = (value: Connection) => {
    const next = new URLSearchParams(params);
    if (value) next.set("connection_state", value); else next.delete("connection_state");
    setParams(next, { replace: true });
  };

  return (
    <>
      <HeadActions><Link to="/next/hosts/new" className="fl-btn">{t("Add host")}</Link></HeadActions>

      <Grid>
        <Card span={9} flush
          title={t("The fleet")}
          tools={
            <>
              <Find value={search} onChange={setSearch} placeholder={t("Search hosts…")} testId="search" />
              <Seg
                value={connection}
                onChange={setConnection}
                options={[
                  { value: "", label: t("All") },
                  { value: "online", label: `${t("Online")} ${count("online")}` },
                  { value: "stale", label: `${t("Stale")} ${count("stale")}` },
                  { value: "offline", label: `${t("Offline")} ${count("offline")}` },
                ]}
              />
            </>
          }
          foot={
            hosts.hasNextPage ? (
              <button type="button" className="fl-quiet fl-small"
                      onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
                {hosts.isFetchingNextPage ? t("Loading…") : t("Load more")}
              </button>
            ) : t("{n} hosts", { n: rows.length })
          }
        >
          <Table
            rows={rows}
            keyOf={(one) => one.id}
            rowTestId={(one) => `host-${one.hostname}`}
            testId="hosts"
            empty={hosts.isLoading ? t("Loading…") : t("No host matches this.")}
            columns={[
              {
                key: "host",
                head: t("Host"),
                cell: (one) => (
                  <TwoLine sub={one.management_address || t("address unknown")}>
                    <Link to={`/next/hosts/${one.id}`}>{one.hostname}</Link>
                  </TwoLine>
                ),
              },
              {
                key: "state",
                head: t("State"),
                cell: (one) => (
                  <Pill tone={stateTone(one.connection_state)} title={one.last_seen_at ? absoluteTime(one.last_seen_at) : undefined}>
                    {t(one.connection_state)}
                  </Pill>
                ),
              },
              {
                key: "seen",
                head: t("Last seen"),
                minor: true,
                cell: (one) => one.last_seen_at
                  ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                  : <span className="fl-faint">{t("never")}</span>,
              },
              {
                key: "system",
                head: t("System"),
                minor: true,
                cell: (one) => (
                  <TwoLine sub={one.agent_version ? `agent ${one.agent_version}` : undefined}>
                    {one.os_distribution || one.os_family || <span className="fl-faint">{t("unknown")}</span>}
                    {one.os_version ? ` ${one.os_version}` : ""}
                  </TwoLine>
                ),
              },
              {
                key: "place",
                head: t("Site / environment"),
                minor: true,
                cell: (one) => (
                  <Tags>
                    <Tag>{one.site}</Tag>
                    <Tag>{one.environment}</Tag>
                  </Tags>
                ),
              },
              {
                key: "updates",
                head: t("Updates"),
                num: true,
                cell: (one) => one.pending_updates === null
                  ? <span className="fl-faint">—</span>
                  : (
                    <Meter
                      share={Math.min(1, (one.pending_updates ?? 0) / 200)}
                      tone={(one.pending_security_updates ?? 0) > 0 ? "warn" : "accent"}
                      text={one.pending_updates}
                    />
                  ),
              },
              {
                key: "trouble",
                head: t("Needs a look"),
                cell: (one) => <Trouble host={one} />,
              },
            ]}
          />
        </Card>

        <Card span={3} title={t("Fleet composition")} note={t("Counted over the whole fleet you can see.")}>
          {a ? (
            <div className="fl-stack">
              <Dimension label={t("Connection")} items={[
                { label: t("Online"), value: count("online"), tone: "ok" },
                { label: t("Stale"), value: count("stale"), tone: "warn" },
                { label: t("Offline"), value: count("offline"), tone: "error" },
                { label: t("Unknown"), value: count("unknown"), tone: "unknown" },
              ]} />
              <Dimension label={t("Systems")} items={a.by_os_family.map((f) => ({ label: facet(f.key), value: f.count, tone: "accent" as Tone }))} />
              <Dimension label={t("Agent builds")} items={a.by_agent_version.map((f) => ({ label: facet(f.key), value: f.count, tone: "neutral" as Tone }))} />
              <Dimension label={t("Sites")} items={a.by_site.map((f) => ({ label: facet(f.key), value: f.count, tone: "info" as Tone }))} />
            </div>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>
      </Grid>
    </>
  );
}

/** What this host is carrying that somebody may have to deal with. */
function Trouble({ host }: { host: Host }) {
  const t = useT();
  const marks: { label: string; tone: Tone }[] = [];
  if (host.package_database_broken) marks.push({ label: t("package database"), tone: "error" });
  if ((host.failed_units ?? 0) > 0) marks.push({ label: t("{n} failed units", { n: host.failed_units ?? 0 }), tone: "error" });
  if (host.reboot_required) marks.push({ label: t("reboot"), tone: "warn" });
  if ((host.pending_security_updates ?? 0) > 0) {
    marks.push({ label: t("{n} security", { n: host.pending_security_updates ?? 0 }), tone: "warn" });
  }
  if (host.maintenance) marks.push({ label: t("maintenance"), tone: "info" });
  if (marks.length === 0) return <span className="fl-faint">—</span>;
  return (
    <Tags>
      {marks.map((mark) => <Pill key={mark.label} tone={mark.tone}>{mark.label}</Pill>)}
    </Tags>
  );
}

/** One dimension of the fleet: a heading, then the bars under it. */
function Dimension({ label, items }: { label: string; items: { label: string; value: number; tone: Tone }[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="fl-subhead">{label}</h3>
      <Bars items={items} />
    </div>
  );
}

function stateTone(state: Host["connection_state"]): Tone {
  return state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
}

/** The dot the list uses where there is no room for the word. */
export { Dot };
