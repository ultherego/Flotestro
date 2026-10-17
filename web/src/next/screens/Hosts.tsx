import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, LIST_PAGE, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { relativeTime, absoluteTime } from "../../lib/format";
import { RELEASE_CHANNELS, refusalName, type FleetActivity, type Host, type Relay, type Whoami } from "../../lib/types";
import { formatSort, parseSort, usePageSize } from "../../components/SortableTable";
import { useTeams } from "../../lib/teams";
import { useT } from "../../i18n";
import {
  Actions, Bars, Bones, Button, C, Card, Check, Dot, Download, Empty, Field, Fields, Find, Form, Grid, HeadActions,
  Meter, Modal, Note, Pill, Problem, RowsPerPage, Seg, Stack, Table, Tag, Tags, Toolbar, TwoLine,
  type Column, type Tone,
} from "../kit";

/**
 * The fleet as a list: what each host is, whether it answers, and what it
 * is carrying that somebody may have to deal with.
 *
 * The narrowing is the server's - every filter on this screen is a query
 * parameter and not a sieve over the page that happens to be loaded, and
 * the counts beside the state filter are taken over the whole fleet the
 * reader may see. A filter set here goes into the address, so a narrowed
 * list is a link somebody else can open.
 *
 * What can be done from here is done to the rows that are ticked, and only
 * by whoever may: the checkboxes belong to the Bulk workspace and are not
 * drawn for a reader who cannot open it, the metadata editor belongs to
 * whoever may write tags or maintenance windows, and the link into
 * enrolment to whoever may order one. Every one of those changes carries a
 * reason into the trail, asked for in the dialog rather than in the list.
 */

type Connection = "" | "online" | "stale" | "offline" | "unknown";

/** The shortest reason the bulk edit is accepted with. */
export const MIN_REASON = 8;

/** The permissions the writes of this screen stand behind. */
const TAG_PERMISSION = "host.tag.write";
const MAINTENANCE_PERMISSION = "host.maintenance.write";
const ENROLL_PERMISSION = "host.enroll.create";
const RELAY_PERMISSION = "host.enroll.read";
const CAMPAIGN_PERMISSION = "campaign.read";

/** The adapters a host can be filtered by; the names the hosts report. */
const CAPABILITIES = [
  "systemd", "packages.apt", "packages.dnf", "packages.pacman", "journald", "docker", "docker.compose",
  "schedules", "network", "dns", "firewall", "storage", "sshd", "kernel", "files.managed",
];

/** What each origin of a management address means, for the chip's tooltip. */
const ADDRESS_SOURCES: Record<string, string> = {
  session: "address seen by the control plane on its end of the connection",
  agent: "address reported by the host itself; it connects through a relay",
  manual: "address set manually by an operator",
};

/** The columns the server can order the list by, as it names them. */
const SORT_COLUMNS = [
  "hostname", "site", "environment", "owner", "lifecycle_state", "connection_state", "agent_version",
  "last_seen_at", "pending_updates", "pending_security_updates", "failed_units",
];

/** The order the server lists in when none is asked for. */
const DEFAULT_SORT = { column: "hostname", descending: false };

/** The shape of a relay identifier, as the server checks it. */
const RELAY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The filters of the list, each under the name it carries in the address and
 * in the query to the server.
 */
type HostFilters = {
  q: string;
  site: string;
  environment: string;
  os_family: string;
  connection_state: string;
  lifecycle_state: string;
  owner: string;
  maintenance: string;
  capability: string;
  /** The mode the host's root helper runs in, or `unknown` when it has not said. */
  helper_mode: string;
  channel: string;
  reboot_required: string;
  security_updates: string;
  identity_domain: string;
  connection_refusal: string;
  tags: string;
  failed_units: string;
  package_db_broken: string;
  sssd_offline: string;
  agent_behind: string;
  relay: string;
  failure_domain: string;
  /**
   * The team the hosts belong to, by identifier, or the word `none` for the
   * hosts nobody has placed in a team.
   */
  team: string;
  sort: string;
};

const EMPTY_FILTERS: HostFilters = {
  q: "", site: "", environment: "", os_family: "", connection_state: "", lifecycle_state: "",
  owner: "", maintenance: "", capability: "", helper_mode: "", channel: "",
  reboot_required: "", security_updates: "",
  identity_domain: "", connection_refusal: "", tags: "", failed_units: "", package_db_broken: "",
  sssd_offline: "", agent_behind: "", relay: "", failure_domain: "", team: "", sort: "",
};

/* The filters that stay in sight: the search, and the two the fleet is most
   often narrowed by. The rest fold - and unfold by themselves the moment any
   of them is set, because a list narrowed by a control nobody can see is a
   list that looks wrong for no reason. */
const ALWAYS_SHOWN: (keyof HostFilters)[] = ["q", "os_family", "connection_state", "sort"];

/** The filters as the address carries them; a name absent from it is empty. */
export function readFilters(params: URLSearchParams): HostFilters {
  const filters = { ...EMPTY_FILTERS };
  for (const key of Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[]) {
    if (key === "tags") continue;
    filters[key] = params.get(key) ?? "";
  }
  filters.tags = params.getAll("tag").join(" ");
  return filters;
}

/**
 * The filters as the address and the server take them: only the ones set,
 * the tags one by one.
 */
export function filterParams(filters: HostFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[]) {
    if (key === "tags") continue;
    const value = filters[key].trim();
    if (value) params.set(key, value);
  }
  for (const tag of filters.tags.split(/\s+/).filter(Boolean)) params.append("tag", tag);
  return params;
}

/** The permissions of the signed-in operator, for the gates of this screen. */
function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

export function Hosts() {
  const t = useT();
  const navigate = useNavigate();
  // The address carries the filters: a tile on the dashboard, a tag on a
  // row and a bookmark all link here with some already set, and every
  // change goes back into the address so the view can be handed on.
  const [address, setAddress] = useSearchParams();
  const [filters, setFilters] = useState<HostFilters>(() => readFilters(address));
  const setFilter = (key: keyof HostFilters, value: string) =>
    setFilters((previous) => ({ ...previous, [key]: value }));
  const written = useRef(address.toString());
  useEffect(() => {
    const next = filterParams(filters).toString();
    if (next !== written.current) {
      written.current = next;
      setAddress(new URLSearchParams(next), { replace: true });
    }
  }, [filters, setAddress]);
  useEffect(() => {
    const current = address.toString();
    if (current !== written.current) {
      written.current = current;
      setFilters(readFilters(address));
    }
  }, [address]);

  // How many of the folded filters are narrowing the list. The block opens
  // on this, so a reader never sees a short list with no visible reason.
  const foldedActive = (Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[])
    .filter((key) => !ALWAYS_SHOWN.includes(key) && filters[key] !== "").length;
  const [unfolded, setUnfolded] = useState(false);
  const showMore = unfolded || foldedActive > 0;

  const permissions = usePermissions();
  const canAdd = permissions.has(ENROLL_PERMISSION);
  // The bulk workspace is where a selection goes; whoever cannot read
  // campaigns has no such workspace and sees no checkboxes.
  const canSelect = permissions.has(CAMPAIGN_PERMISSION);
  // The metadata editor is for whoever may write tags or maintenance
  // windows; the server judges each host on its own anyway.
  const canTag = permissions.has(TAG_PERMISSION);
  const canMaintain = permissions.has(MAINTENANCE_PERMISSION);
  const canSetMetadata = canTag || canMaintain;
  // The relays, for the filter by route: read only by whoever may list
  // them; for the rest the filter is still reachable through the address.
  const canSeeRelays = permissions.has(RELAY_PERMISSION);

  // The rows ticked for what is done to several hosts at once.
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [editing, setEditing] = useState(false);

  // The typed text reaches the server after a pause, not per keystroke.
  const settledSearch = useDebounced(filters.q.trim());
  const settledOwner = useDebounced(filters.owner.trim());
  const settledTags = useDebounced(filters.tags.trim());
  const settledDomain = useDebounced(filters.identity_domain.trim());
  const settledSite = useDebounced(filters.site.trim());
  const settledEnvironment = useDebounced(filters.environment.trim());
  const settledFailureDomain = useDebounced(filters.failure_domain.trim());
  // A relay is asked for by identifier; a text that is not one yet - half
  // typed, or pasted with a stray character - is not sent, because the
  // server would refuse it and the whole list would turn into an error.
  const settledRelay = useDebounced(filters.relay.trim());

  // The order of the list, as the server reads it; a sort naming a column
  // the server has not got is left out rather than sent to be refused.
  const sort = parseSort(filters.sort);
  const sortSent = sort && SORT_COLUMNS.includes(sort.column) ? formatSort(sort) : "";
  const shownSort = sort ?? DEFAULT_SORT;
  const [pageSize, setPageSize] = usePageSize("hosts", LIST_PAGE);

  const narrowing = filterParams({
    ...filters,
    q: settledSearch, owner: settledOwner, tags: settledTags, identity_domain: settledDomain,
    site: settledSite, environment: settledEnvironment, failure_domain: settledFailureDomain,
    relay: RELAY_ID.test(settledRelay) ? settledRelay : "", sort: "",
  });
  // The filter the export asks with, and the list after it: the saved file
  // is what is on the screen, not the first page of everything.
  const query = new URLSearchParams(narrowing);
  if (sortSent) query.set("sort", sortSent);
  query.set("limit", String(pageSize));

  // The selection drops with the narrowing, not with the order or the
  // page size: the rows it named are still on the screen after a sort.
  const narrowingKey = narrowing.toString();
  useEffect(() => {
    setSelected(new Set());
  }, [narrowingKey]);

  const hosts = useInfiniteQuery({
    queryKey: ["hosts", query.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(query);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Host>>(`/api/v1/hosts?${page}`);
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

  const relays = useQuery({
    queryKey: ["relays"],
    queryFn: () => api.get<{ items: Relay[] }>("/api/v1/relays"),
    enabled: canSeeRelays,
    staleTime: 60 * 1000,
  });
  // The teams, for the filter by team.
  const teams = useTeams();

  if (hosts.error) return <Problem>{String(hosts.error)}</Problem>;

  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const a = activity.data;
  const fleetSize = a?.by_connection_state.reduce((sum, one) => sum + one.count, 0);
  const count = (state: string) => a?.by_connection_state.find((one) => one.key === state)?.count ?? 0;
  const facet = (key: string) => (key === "" || key === "unknown" ? t("unknown") : key);
  const facetKeys = (items?: { key: string }[]) => (items ?? []).map((one) => one.key).filter(Boolean);
  // The facets do not count owners, so the suggestions are the owners of
  // the rows on screen: a hint, not the whole list.
  const ownerKeys = [...new Set(rows.map((one) => one.owner).filter((owner): owner is string => Boolean(owner)))].sort();
  // The meter measures each host against the busiest one on the list; a
  // host whose count is unknown does not set the scale.
  const mostUpdates = Math.max(0, ...rows.map((one) => one.pending_updates ?? 0));

  const setConnection = (value: Connection) =>
    setFilters((previous) => ({ ...previous, connection_state: value, connection_refusal: "" }));
  /** The address of this list narrowed to one tag. */
  const tagAddress = (tag: string) => `/hosts?${new URLSearchParams([["tag", tag]])}`;

  // The active filters as chips: what the list is narrowed by, each with
  // its own way off.
  const chipLabels: Record<Exclude<keyof HostFilters, "sort">, string> = {
    q: t("search"), site: t("site"), environment: t("environment"), os_family: t("OS"),
    connection_state: t("state"), lifecycle_state: t("lifecycle"), owner: t("owner"),
    maintenance: t("maintenance"), capability: t("capability"),
    helper_mode: t("helper mode"), channel: t("channel"),
    reboot_required: t("reboot required"), security_updates: t("security updates"),
    identity_domain: t("domain"), connection_refusal: t("refused for"), tags: t("tags"),
    failed_units: t("failed units"), package_db_broken: t("package database broken"),
    sssd_offline: t("SSSD offline"), agent_behind: t("agent behind"), relay: t("relay"),
    failure_domain: t("failure domain"), team: t("team"),
  };
  const chipValue = (key: keyof HostFilters, value: string): string => {
    if (key === "connection_refusal") return t(refusalName(value));
    if (key === "relay") return relays.data?.items.find((one) => one.id === value)?.name ?? value;
    // The chip says which team in words; the server's own word for the
    // other list says what it means rather than repeating "none".
    if (key === "team") {
      if (value === "none") return t("no team");
      return teams.data?.items.find((one) => one.id === value)?.name ?? value;
    }
    return value;
  };
  const activeFilters = (Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[])
    .filter((key): key is Exclude<keyof HostFilters, "sort"> => key !== "sort" && filters[key].trim() !== "");

  const tick = (id: string, on: boolean) => setSelected((current) => {
    const next = new Set(current);
    if (on) next.add(id); else next.delete(id);
    return next;
  });
  // The header box ticks what is loaded, not what matches: a page not yet
  // fetched has hosts nobody has seen, and a campaign must not reach them
  // from a box that looked like "all".
  const allLoadedTicked = rows.length > 0 && rows.every((one) => selected.has(one.id));
  // The editor works on the loaded rows that are ticked: a host ticked and
  // then filtered out of view is not edited unseen.
  const chosen = rows.filter((one) => selected.has(one.id));
  const openInBulk = () => {
    const target = new URLSearchParams();
    for (const id of selected) target.append("host_id", id);
    navigate(`/bulk?${target}`);
  };

  /* The checkbox column exists only for a reader who has somewhere to take
     a selection; for everybody else the list is a list. */
  const pick: Column<Host>[] = canSelect ? [{
    key: "pick",
    head: (
      <input
        type="checkbox"
        aria-label={t("select every loaded host")}
        checked={allLoadedTicked}
        onChange={(event) => setSelected(event.target.checked ? new Set(rows.map((one) => one.id)) : new Set())}
      />
    ),
    cell: (one) => (
      <input
        type="checkbox"
        aria-label={t("select {host}", { host: one.hostname })}
        checked={selected.has(one.id)}
        onChange={(event) => tick(one.id, event.target.checked)}
      />
    ),
  }] : [];

  /** A count the host never reported is a dash, never a nought. */
  const optionalNumber = (value: number | null | undefined) =>
    value === null || value === undefined
      ? <span className="fl-faint">—</span>
      : value > 0 ? <Pill tone="warn">{value}</Pill> : <span>{value}</span>;

  const addHost = <Link to="/hosts/new" className="fl-btn">{t("Add host")}</Link>;

  return (
    <>
      {/* The link is seen by whoever can order an installation; for the
          rest it would lead only to a refusal. */}
      {canAdd && <HeadActions>{addHost}</HeadActions>}

      <Grid>
        <Card span={9} flush
          title={t("The fleet")}
          note={
            <>
              {t("Filters are applied server-side.")}{" "}
              <Refreshed at={hosts.dataUpdatedAt} fetching={hosts.isFetching} onRefresh={() => void hosts.refetch()} />
            </>
          }
          tools={activeFilters.length > 0 ? (
            <span data-testid="active-filters">
              <Tags>
                {activeFilters.map((key) => (
                  <Pill key={key} tone="info" dot={false}>
                    {`${chipLabels[key]} ${chipValue(key, filters[key].trim())}`}
                    <button
                      type="button"
                      className="fl-word"
                      aria-label={t("clear the {name} filter", { name: chipLabels[key] })}
                      data-testid={`clear-${key}`}
                      onClick={() => setFilter(key, "")}
                    >
                      ×
                    </button>
                  </Pill>
                ))}
                <Button kind="quiet" testId="clear-filters" onClick={() => setFilters({ ...EMPTY_FILTERS, sort: filters.sort })}>
                  {t("Clear filters")}
                </Button>
              </Tags>
            </span>
          ) : undefined}
          foot={
            <>
              {/* What is offered for the rows that are ticked. It stands
                  under the list it acts on, and says how many it would
                  reach before it reaches them. */}
              {selected.size > 0 && (
                <Actions>
                  <Note>{t("{n} selected", { n: selected.size })}</Note>
                  <Button testId="open-bulk" onClick={openInBulk}>
                    {t("Open in Bulk workspace ({n})", { n: selected.size })}
                  </Button>
                  {canSetMetadata && (
                    <Button kind="quiet" testId="set-metadata" onClick={() => setEditing(true)}>
                      {t("Set metadata…")}
                    </Button>
                  )}
                  <Button kind="quiet" testId="clear-selection" onClick={() => { setSelected(new Set()); setEditing(false); }}>
                    {t("Clear selection")}
                  </Button>
                </Actions>
              )}
              {/* The next page comes on request: a page that failed to
                  arrive is asked for again by hand, and the count says how
                  much is left. */}
              {hosts.hasNextPage ? (
                <Button kind="quiet" testId="load-more"
                        onClick={() => void hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
                  {hosts.isFetchingNextPage ? t("loading…") : t("Load more ({n} left)", { n: total - rows.length })}
                </Button>
              ) : t("{n} hosts", { n: rows.length })}
            </>
          }
        >
          <Toolbar
            end={
              <>
                {hosts.data && <span className="fl-note">{t("{n} hosts", { n: total })}</span>}
                <RowsPerPage size={pageSize} onSize={setPageSize} />
                <Download path="/api/v1/hosts" params={query} />
              </>
            }
          >
            {/* The box is narrower than the sentence that says what it
                searches; the short placeholder fits and the sentence stays
                for the screen reader. */}
            <Find value={filters.q} onChange={(value) => setFilter("q", value)} placeholder={t("Search hosts…")} testId="search" />
            {/* The systems are the ones the fleet reports, from the facets;
                a family set by a link but absent from the fleet stays
                listed, so the control shows what the list is narrowed by. */}
            <select
              value={filters.os_family}
              aria-label={t("System")}
              data-testid="filter-os-family"
              onChange={(event) => setFilter("os_family", event.target.value)}
            >
              <option value="">{t("OS: any")}</option>
              {[...new Set([...facetKeys(a?.by_os_family), ...(filters.os_family ? [filters.os_family] : [])])].map((family) => (
                <option key={family} value={family}>{family}</option>
              ))}
            </select>
            <Seg
              value={filters.connection_state as Connection}
              onChange={setConnection}
              label={t("Connection")}
              options={[
                { value: "", label: t("All") },
                { value: "online", label: `${t("Online")} ${count("online")}` },
                { value: "stale", label: `${t("Stale")} ${count("stale")}` },
                { value: "offline", label: `${t("Offline")} ${count("offline")}` },
                { value: "unknown", label: `${t("Unknown")} ${count("unknown")}` },
              ]}
            />
            {showMore ? (
              <Button kind="quiet" testId="fold-filters" onClick={() => setUnfolded(false)} disabled={foldedActive > 0}
                      title={t("Every one of these narrows the list on the server.")}>
                {t("Fold away")}
              </Button>
            ) : (
              <Button kind="quiet" testId="more-filters" onClick={() => setUnfolded(true)}>
                {t("More filters")}
              </Button>
            )}
          </Toolbar>

          {showMore && (
            <MoreFilters
              filters={filters} setFilter={setFilter} activity={a}
              teams={teams.data?.items ?? []} relays={relays.data?.items ?? []} canSeeRelays={canSeeRelays} ownerKeys={ownerKeys}
            />
          )}

          {!hosts.isLoading && rows.length === 0 ? (
            <Empty action={canAdd ? addHost : undefined}>{t("No host matches the filters.")}</Empty>
          ) : (
            /* The order is the server's: the list is walked by cursor, so a
               sort done in the browser would only order the page loaded.
               The heading asks for it, and the same heading turns it round. */
            <Table
              rows={rows}
              keyOf={(one) => one.id}
              rowTestId={(one) => `host-${one.hostname}`}
              testId="hosts"
              remember="fl.columns.next-hosts"
              loading={hosts.isLoading}
              sort={{ by: shownSort.column, down: shownSort.descending }}
              onSort={(by) => setFilter("sort", formatSort({
                column: by,
                descending: by === shownSort.column ? !shownSort.descending : false,
              }))}
              columns={[
                ...pick,
                {
                  key: "host",
                  sort: "hostname",
                  head: t("Host"),
                  cell: (one) => (
                    <>
                      <Link to={`/hosts/${one.id}`}>{one.hostname}</Link>
                      {/* A tag leads to every host that carries it, which is
                          what a tag is for. */}
                      {one.tags.length > 0 && (
                        <Tags>
                          {one.tags.map((tag) => (
                            <Tag key={tag} to={tagAddress(tag)} title={t("show every host tagged {tag}", { tag })}>
                              {tag}
                            </Tag>
                          ))}
                        </Tags>
                      )}
                    </>
                  ),
                },
                {
                  key: "state",
                  sort: "connection_state",
                  head: t("State"),
                  /* An offline host with a refusal on record is not merely
                     away: the gateway turned it down, and the reason stands
                     under the badge rather than in a trail nobody reads for
                     a host that looks switched off. */
                  cell: (one) => (
                    <TwoLine
                      sub={one.last_connection_refusal && one.connection_state !== "online"
                        ? t("refused: {reason} {when}", {
                            reason: t(refusalName(one.last_connection_refusal.code)),
                            when: relativeTime(one.last_connection_refusal.at),
                          })
                        : undefined}
                    >
                      <Pill tone={stateTone(one.connection_state)} title={one.last_seen_at ? absoluteTime(one.last_seen_at) : undefined}>
                        {t(one.connection_state)}
                      </Pill>
                    </TwoLine>
                  ),
                },
                {
                  key: "address",
                  head: t("Address"),
                  minor: true,
                  /* The management address - not just any first address of
                     the host - with where it came from: what the panel saw,
                     what the host declared, or what an operator set.
                     Undetermined is shown as undetermined. */
                  cell: (one) => (
                    <span data-testid="host-address">
                      {one.management_address ? (
                        <TwoLine
                          sub={one.management_address_source
                            ? <Pill tone="neutral" dot={false} title={t(ADDRESS_SOURCES[one.management_address_source] ?? "address source")}>
                                {one.management_address_source}
                              </Pill>
                            : undefined}
                        >
                          {one.management_address}
                        </TwoLine>
                      ) : <Pill tone="unknown">{t("unknown")}</Pill>}
                    </span>
                  ),
                },
                {
                  key: "owner",
                  sort: "owner",
                  head: t("Owner"),
                  optional: true,
                  startFolded: true,
                  /* The owner as recorded; a click narrows the list to their
                     hosts, like a tag does. */
                  cell: (one) => (
                    <span data-testid="host-owner">
                      {one.owner ? (
                        <button type="button" className="fl-word"
                                title={t("show every host of {owner}", { owner: one.owner })}
                                onClick={() => setFilter("owner", one.owner ?? "")}>
                          {one.owner}
                        </button>
                      ) : <span className="fl-faint">—</span>}
                    </span>
                  ),
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
                { key: "site", head: t("Site"), sort: "site", cell: (one) => one.site || <span className="fl-faint">—</span> },
                { key: "environment", head: t("Environment"), sort: "environment", cell: (one) => one.environment || <span className="fl-faint">—</span> },
                {
                  key: "lifecycle",
                  sort: "lifecycle_state",
                  head: t("Lifecycle"),
                  optional: true,
                  startFolded: true,
                  cell: (one) => (
                    <button type="button" className="fl-word" title={t("show only these hosts")}
                            onClick={() => setFilter("lifecycle_state", one.lifecycle_state)}>
                      {one.lifecycle_state}
                    </button>
                  ),
                },
                {
                  key: "agent",
                  sort: "agent_version",
                  head: t("Agent"),
                  optional: true,
                  startFolded: true,
                  cell: (one) => one.agent_version || <Pill tone="unknown">{t("unknown")}</Pill>,
                },
                {
                  key: "domain",
                  head: t("Domain"),
                  minor: true,
                  cell: (one) => one.identity?.enrolled ? (
                    <button type="button" className="fl-word" title={t("show every host in this domain")}
                            onClick={() => setFilter("identity_domain", one.identity.domain ?? "")}>
                      {one.identity.domain}
                    </button>
                  ) : <Pill tone="neutral">{t("not in domain")}</Pill>,
                },
                {
                  key: "updates",
                  sort: "pending_updates",
                  head: t("Updates"),
                  num: true,
                  /* The bar is the host's share of the busiest host on the
                     list. An unknown count stays a dash, not an empty bar. */
                  cell: (one) => one.pending_updates === null || one.pending_updates === undefined
                    ? <span className="fl-faint">—</span>
                    : (
                      <span
                        data-testid="host-updates"
                        title={t("{n} pending updates, {security} of them security; the bar is the host's share of the busiest host on the list", {
                          n: one.pending_updates, security: one.pending_security_updates ?? t("an unknown number"),
                        })}
                      >
                        <Meter
                          share={mostUpdates > 0 ? one.pending_updates / mostUpdates : 0}
                          tone={(one.pending_security_updates ?? 0) > 0 ? "error" : one.pending_updates > 0 ? "warn" : "ok"}
                          text={one.pending_updates}
                        />
                      </span>
                    ),
                },
                {
                  key: "security",
                  sort: "pending_security_updates",
                  head: t("Security updates"),
                  num: true,
                  optional: true,
                  startFolded: true,
                  cell: (one) => optionalNumber(one.pending_security_updates),
                },
                {
                  key: "failed_units",
                  sort: "failed_units",
                  head: t("Failed units"),
                  num: true,
                  optional: true,
                  startFolded: true,
                  cell: (one) => optionalNumber(one.failed_units),
                },
                {
                  key: "reboot",
                  head: t("Reboot"),
                  optional: true,
                  startFolded: true,
                  cell: (one) => one.reboot_required === null || one.reboot_required === undefined
                    ? <span className="fl-faint">—</span>
                    : one.reboot_required ? <Pill tone="warn">{t("required")}</Pill> : <span className="fl-faint">{t("no")}</span>,
                },
                {
                  key: "trouble",
                  head: t("Needs a look"),
                  cell: (one) => <Trouble host={one} />,
                },
                {
                  key: "seen",
                  sort: "last_seen_at",
                  head: t("Last seen"),
                  minor: true,
                  cell: (one) => one.last_seen_at
                    ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                    : <span className="fl-faint">{t("never")}</span>,
                },
              ]}
            />
          )}
        </Card>

        <Card
          span={3}
          title={t("Fleet composition")}
          note={fleetSize === undefined
            ? t("Counted in the database over the hosts you can see.")
            : t("{n} hosts you can see", { n: fleetSize })}
        >
          {a ? (
            <Stack>
              <Dimension label={t("Connection")} items={[
                { label: t("Online"), value: count("online"), tone: "ok", onPick: () => setConnection("online") },
                { label: t("Stale"), value: count("stale"), tone: "warn", onPick: () => setConnection("stale") },
                { label: t("Offline"), value: count("offline"), tone: "error", onPick: () => setConnection("offline") },
                { label: t("Unknown"), value: count("unknown"), tone: "unknown", onPick: () => setConnection("unknown") },
              ]} pick={t("show only these hosts")} />
              <Dimension label={t("By system")} pick={t("show only these hosts")} items={(a.by_os_family ?? []).map((f) => (
                { label: facet(f.key), value: f.count, tone: "accent" as Tone, onPick: () => setFilter("os_family", f.key) }
              ))} />
              {/* Two dimensions under two headings: "lab 6, test 6" in one
                  list reads as two sites. */}
              <Dimension label={t("Sites")} pick={t("show only these hosts")} items={(a.by_site ?? []).map((f) => (
                { label: facet(f.key), value: f.count, tone: "info" as Tone, onPick: () => setFilter("site", f.key) }
              ))} />
              <Dimension label={t("Environments")} pick={t("show only these hosts")} items={(a.by_environment ?? []).map((f) => (
                { label: facet(f.key), value: f.count, tone: "ok" as Tone, onPick: () => setFilter("environment", f.key) }
              ))} />
              <Dimension label={t("Agent builds")} items={(a.by_agent_version ?? []).map((f) => (
                { label: facet(f.key), value: f.count, tone: "neutral" as Tone }
              ))} />
              <Dimension label={t("Lifecycle")} pick={t("show only these hosts")} items={(a.by_lifecycle_state ?? []).map((f) => (
                { label: facet(f.key), value: f.count, tone: "info" as Tone, onPick: () => setFilter("lifecycle_state", f.key) }
              ))} />
            </Stack>
          ) : activity.isError ? (
            <Empty>{t("The composition could not be counted.")}</Empty>
          ) : <Bones rows={4} />}
        </Card>

        {editing && chosen.length > 0 && (
          <C span={12}><Metadata
            hosts={chosen}
            canTag={canTag}
            canMaintain={canMaintain}
            onClose={() => setEditing(false)}
          /></C>
        )}
      </Grid>
    </>
  );
}


/* ------------------------------------------- what is set on many at once */

/** The answer for one host: applied, or the code its own route refused with. */
type Outcome = { host_id: string; ok: boolean; code: string; detail?: string };
type BulkAnswer = { results: Outcome[]; applied: number; failed: number };

/** The draft; every field is optional and an untouched one changes nothing. */
type Draft = {
  tagsAdd: string;
  tagsRemove: string;
  owner: string;
  setOwner: boolean;
  failureDomain: string;
  setFailureDomain: boolean;
  site: string;
  environment: string;
  maintenance: "keep" | "open" | "close";
  until: string;
  windowReason: string;
};

const EMPTY: Draft = {
  tagsAdd: "", tagsRemove: "", owner: "", setOwner: false, failureDomain: "", setFailureDomain: false,
  site: "", environment: "", maintenance: "keep", until: "", windowReason: "",
};

/** The tags typed in one box: separated by commas or whitespace. */
export function splitTags(text: string): string[] {
  return text.split(/[\s,]+/).map((tag) => tag.trim()).filter(Boolean);
}

/** A local date-time from the input as an RFC 3339 instant. */
function instantOf(local: string): string {
  return new Date(local).toISOString();
}

/** What the draft would set, in the shape the server reads. */
export function metadataSet(draft: Draft): Record<string, unknown> {
  const set: Record<string, unknown> = {};
  const add = splitTags(draft.tagsAdd);
  const remove = splitTags(draft.tagsRemove);
  if (add.length > 0) set.tags_add = add;
  if (remove.length > 0) set.tags_remove = remove;
  if (draft.setOwner) set.owner = draft.owner.trim();
  if (draft.setFailureDomain) set.failure_domain = draft.failureDomain.trim();
  if (draft.site.trim() !== "") set.site = draft.site.trim();
  if (draft.environment.trim() !== "") set.environment = draft.environment.trim();
  // A window closed is a window set to nothing, which is not the same as a
  // window left alone: the first travels as null, the second not at all.
  if (draft.maintenance === "close") set.maintenance = null;
  // A window with no end is not a window yet: the form asks for one, and
  // nothing is composed from an empty date - new Date("") has no instant.
  if (draft.maintenance === "open" && draft.until !== "") {
    set.maintenance = { until: instantOf(draft.until), reason: draft.windowReason.trim() };
  }
  return set;
}

/**
 * What the panel records about the chosen hosts by hand: their tags, who
 * answers for them, where they stand and whether somebody is working on
 * them. A field left empty changes nothing; every host is judged in its
 * own scope and answered on its own.
 */
function Metadata({ hosts, canTag, canMaintain, onClose }: {
  hosts: Host[];
  canTag: boolean;
  canMaintain: boolean;
  onClose: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [answer, setAnswer] = useState<BulkAnswer | null>(null);
  const change = (delta: Partial<Draft>) => setDraft((previous) => ({ ...previous, ...delta }));
  const byID = new Map(hosts.map((one) => [one.id, one]));

  const submit = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<BulkAnswer>("/api/v1/hosts/bulk-metadata", body),
    onSuccess: (result) => {
      setAnswer(result);
      setMessage("");
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["fleet-activity"] });
      for (const one of hosts) void queryClient.invalidateQueries({ queryKey: ["host", one.id] });
    },
    onError: (error) => {
      setConfirming(false);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const set = metadataSet(draft);
  const windowReady = draft.maintenance !== "open" || (draft.until !== "" && draft.windowReason.trim() !== "");
  const touches = Object.keys(set).length > 0;
  const ready = touches && windowReady;
  const moves = draft.site.trim() !== "" || draft.environment.trim() !== "";

  return (
    <Form
      title={t("Set metadata on {n} hosts", { n: hosts.length })}
      note={t("What the panel records about these hosts by hand. A field left empty changes nothing; every host is judged in its own scope and answered on its own.")}
      tools={<Button kind="quiet" testId="metadata-close" onClick={onClose}>{t("Close")}</Button>}
      actions={
        <Actions>
          <Button
            testId="bulk-apply"
            disabled={!ready || submit.isPending}
            title={ready ? undefined : t("Nothing is set yet, so there is nothing to apply.")}
            onClick={() => { setMessage(""); setConfirming(true); }}
          >
            {t("Apply to {n} hosts…", { n: hosts.length })}
          </Button>
        </Actions>
      }
    >
      <Stack>
      <Fields>
        {canTag && (
          <>
            <Field label={t("Add tags")} hint={t("key or key=value, separated by commas; added to what each host already carries.")}>
              <input
                value={draft.tagsAdd}
                placeholder="patched=2026-09, role=web"
                onChange={(event) => change({ tagsAdd: event.target.value })}
                data-testid="bulk-tags-add"
              />
            </Field>
            <Field label={t("Remove tags")} hint={t("Taken off the hosts that carry them; the others are left as they are.")}>
              <input
                value={draft.tagsRemove}
                placeholder="legacy"
                onChange={(event) => change({ tagsRemove: event.target.value })}
                data-testid="bulk-tags-remove"
              />
            </Field>
            <Field label={t("Owner")} hint={t("Tick to set; empty hands the hosts back to nobody.")}>
              <Check checked={draft.setOwner} onChange={(on) => change({ setOwner: on })}>{t("set the owner")}</Check>
              <input
                value={draft.owner}
                placeholder={t("platform team")}
                onChange={(event) => change({ owner: event.target.value, setOwner: true })}
                data-testid="bulk-owner"
              />
            </Field>
            <Field label={t("Failure domain")} hint={t("Tick to set; empty takes the hosts out from under the domain budgets.")}>
              <Check checked={draft.setFailureDomain} onChange={(on) => change({ setFailureDomain: on })}>
                {t("set the failure domain")}
              </Check>
              <input
                value={draft.failureDomain}
                placeholder={t("rack-12, zone-b")}
                onChange={(event) => change({ failureDomain: event.target.value, setFailureDomain: true })}
                data-testid="bulk-failure-domain"
              />
            </Field>
            <Field label={t("Site")} hint={t("Moves the hosts; empty keeps each host where it stands.")}>
              <input
                value={draft.site}
                onChange={(event) => change({ site: event.target.value })}
                data-testid="bulk-site"
              />
            </Field>
            <Field label={t("Environment")} hint={t("Moves the hosts; empty keeps each host's environment.")}>
              <input
                value={draft.environment}
                onChange={(event) => change({ environment: event.target.value })}
                data-testid="bulk-environment"
              />
            </Field>
          </>
        )}
        {/* A window says somebody is working on these machines: campaigns
            skip them and their alerts stay quiet. It always has an end. */}
        {canMaintain && (
          <>
            <Field label={t("Maintenance window")}>
              <select
                value={draft.maintenance}
                onChange={(event) => change({ maintenance: event.target.value as Draft["maintenance"] })}
                data-testid="bulk-maintenance"
              >
                <option value="keep">{t("leave as it is")}</option>
                <option value="open">{t("open until…")}</option>
                <option value="close">{t("close")}</option>
              </select>
            </Field>
            {draft.maintenance === "open" && (
              <>
                <Field label={t("Until")} hint={t("At most 30 days ahead.")}>
                  <input
                    type="datetime-local"
                    value={draft.until}
                    onChange={(event) => change({ until: event.target.value })}
                    data-testid="bulk-until"
                  />
                </Field>
                <Field label={t("Window reason")} hint={t("What the next person on call will read.")}>
                  <input
                    value={draft.windowReason}
                    onChange={(event) => change({ windowReason: event.target.value })}
                    data-testid="bulk-window-reason"
                  />
                </Field>
              </>
            )}
          </>
        )}
      </Fields>
      {moves && (
        <Note>
          {t("A move changes who may manage the host, which budgets its changes load and which groups it stands in, from the next order on; nothing already planned is re-evaluated.")}
        </Note>
      )}
      {message && <Note>{message}</Note>}

      {answer && (
        <>
          <Note>
            <span data-testid="bulk-summary">
              {t("{applied} applied, {failed} refused.", { applied: answer.applied, failed: answer.failed })}
            </span>
          </Note>
          <Table
            rows={answer.results}
            keyOf={(one) => one.host_id}
            testId="bulk-outcomes"
            rowTestId={(one) => `bulk-outcome-${one.host_id}`}
            columns={[
              { key: "host", head: t("Host"), cell: (one) => {
                const host = byID.get(one.host_id);
                return host ? <Link to={`/hosts/${host.id}`}>{host.hostname}</Link> : one.host_id;
              } },
              { key: "outcome", head: t("Outcome"), cell: (one) => (
                <Pill tone={one.ok ? "ok" : "error"}>{one.ok ? t("applied") : one.code}</Pill>
              ) },
              { key: "detail", head: t("Detail"), minor: true, cell: (one) => one.detail || "—" },
            ]}
          />
        </>
      )}

      {confirming && (
        <Modal
          title={t("Set metadata on {n} hosts", { n: hosts.length })}
          onClose={() => setConfirming(false)}
          actions={
            <>
              <Button kind="quiet" testId="bulk-cancel" onClick={() => setConfirming(false)} disabled={submit.isPending}>
                {t("Cancel")}
              </Button>
              <Button
                testId="bulk-confirm"
                disabled={reason.trim().length < MIN_REASON || submit.isPending}
                onClick={() => submit.mutate({
                  host_ids: hosts.map((one) => one.id),
                  reason: reason.trim(),
                  set,
                })}
              >
                {submit.isPending ? t("Requesting…") : t("Apply to {n} hosts", { n: hosts.length })}
              </Button>
            </>
          }
        >
          <Note>
            {t("{n} hosts are changed, each in its own scope: a host whose change is refused is answered on its own and the others are still applied.", { n: hosts.length })}
          </Note>
          <Tags>
            {hosts.map((one) => <Tag key={one.id}>{one.hostname}</Tag>)}
          </Tags>
          <Fields>
            <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
              <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="bulk-reason" />
            </Field>
          </Fields>
        </Modal>
      )}
      </Stack>
    </Form>
  );
}

/** The filters the bar has no room for. They narrow the list under them, so they stand over its table. */
function MoreFilters({ filters, setFilter, activity, teams, relays, canSeeRelays, ownerKeys }: {
  filters: HostFilters;
  setFilter: (key: keyof HostFilters, value: string) => void;
  activity: FleetActivity | undefined;
  teams: { id: string; name: string }[];
  relays: Relay[];
  canSeeRelays: boolean;
  ownerKeys: string[];
}) {
  const t = useT();
  const facetKeys = (items?: { key: string }[]) => (items ?? []).map((one) => one.key).filter(Boolean);
  return (
    <>
      <Fields>
        {/* The sites, environments and owners are suggested from the
            facets: the fleet's own values, not a list to maintain. */}
        <Field label={t("Site")}>
          <input
            placeholder={t("site")} value={filters.site} list="next-hosts-sites"
            onChange={(event) => setFilter("site", event.target.value)} data-testid="filter-site"
          />
          <datalist id="next-hosts-sites">
            {facetKeys(activity?.by_site).map((key) => <option key={key} value={key} />)}
          </datalist>
        </Field>
        <Field label={t("Environment")}>
          <input
            placeholder={t("environment")} value={filters.environment} list="next-hosts-environments"
            onChange={(event) => setFilter("environment", event.target.value)} data-testid="filter-environment"
          />
          <datalist id="next-hosts-environments">
            {facetKeys(activity?.by_environment).map((key) => <option key={key} value={key} />)}
          </datalist>
        </Field>
        <Field label={t("Owner")}>
          <input
            placeholder={t("owner")} value={filters.owner} list="next-hosts-owners"
            onChange={(event) => setFilter("owner", event.target.value)} data-testid="filter-owner"
          />
          <datalist id="next-hosts-owners">
            {ownerKeys.map((key) => <option key={key} value={key} />)}
          </datalist>
        </Field>
        <Field label={t("Tags")} hint={t("every listed tag has to be on the host")}>
          <input
            placeholder={t("tags, e.g. role=db tier=gold")}
            value={filters.tags}
            onChange={(event) => setFilter("tags", event.target.value)}
            data-testid="filter-tags"
          />
        </Field>
        <Field label={t("Lifecycle")}>
          <select value={filters.lifecycle_state} onChange={(event) => setFilter("lifecycle_state", event.target.value)} data-testid="filter-lifecycle">
            <option value="">{t("lifecycle: any")}</option>
            <option value="active">{t("active")}</option>
            <option value="quarantined">{t("quarantined")}</option>
            <option value="recovery">{t("recovery")}</option>
            <option value="retiring">{t("retiring")}</option>
            <option value="retired">{t("retired")}</option>
          </select>
        </Field>
        <Field label={t("Maintenance")}>
          <select value={filters.maintenance} onChange={(event) => setFilter("maintenance", event.target.value)} data-testid="filter-maintenance">
            <option value="">{t("maintenance: any")}</option>
            <option value="true">{t("in a maintenance window")}</option>
            <option value="false">{t("outside a maintenance window")}</option>
          </select>
        </Field>
        <Field label={t("Capability")}>
          <select value={filters.capability} onChange={(event) => setFilter("capability", event.target.value)} data-testid="filter-capability">
            <option value="">{t("capability: any")}</option>
            {CAPABILITIES.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </Field>
        {/* What the host's helper does with a request carrying no capability of
            the panel. Only enforce refuses one, so the other values are the
            hosts a migration still has to reach. */}
        <Field label={t("Helper mode")}>
          <select value={filters.helper_mode} onChange={(event) => setFilter("helper_mode", event.target.value)} data-testid="filter-helper-mode">
            <option value="">{t("helper mode: any")}</option>
            <option value="enforce">{t("enforce: an unsigned request is refused")}</option>
            <option value="prefer">{t("prefer: an unsigned request is carried out")}</option>
            <option value="observe">{t("observe: nothing is refused")}</option>
            <option value="unknown">{t("unknown: the host has not said")}</option>
          </select>
        </Field>
        <Field label={t("Channel")}>
          <select value={filters.channel} onChange={(event) => setFilter("channel", event.target.value)} data-testid="filter-channel">
            <option value="">{t("channel: any")}</option>
            {RELEASE_CHANNELS.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </Field>
        <Field label={t("Reboot")}>
          <select value={filters.reboot_required} onChange={(event) => setFilter("reboot_required", event.target.value)} data-testid="filter-reboot">
            <option value="">{t("reboot: any")}</option>
            <option value="true">{t("reboot required")}</option>
            <option value="false">{t("no reboot required")}</option>
          </select>
        </Field>
        <Field label={t("Security updates")}>
          <select value={filters.security_updates} onChange={(event) => setFilter("security_updates", event.target.value)} data-testid="filter-security">
            <option value="">{t("security updates: any")}</option>
            <option value="true">{t("security updates waiting")}</option>
            <option value="false">{t("no security updates")}</option>
          </select>
        </Field>
        <Field label={t("Directory domain")} hint={t("the directory domain the host is joined to, e.g. corp.example")}>
          <input
            placeholder={t("directory domain")} value={filters.identity_domain}
            onChange={(event) => setFilter("identity_domain", event.target.value)} data-testid="filter-identity-domain"
          />
        </Field>
        <Field label={t("Failure domain")} hint={t("the rack, zone or cluster an operator placed the host in, e.g. rack-a")}>
          <input
            placeholder={t("failure domain")} value={filters.failure_domain}
            onChange={(event) => setFilter("failure_domain", event.target.value)} data-testid="filter-failure-domain"
          />
        </Field>
        {/* The route: a relay by name for whoever may list them, the
            identifier for the rest. */}
        <Field label={t("Relay")}>
          {canSeeRelays ? (
            <select value={filters.relay} onChange={(event) => setFilter("relay", event.target.value)} data-testid="filter-relay">
              <option value="">{t("relay: any")}</option>
              {(relays).map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
              {filters.relay && !relays.some((one) => one.id === filters.relay) && (
                <option value={filters.relay}>{filters.relay}</option>
              )}
            </select>
          ) : (
            <input
              placeholder={t("relay identifier")} value={filters.relay}
              onChange={(event) => setFilter("relay", event.target.value)} data-testid="filter-relay-id"
            />
          )}
        </Field>
        {/* The team: who the hosts belong to, which is not where they
            stand. The last entry is the list an administrator works
            through after the teams are created - the hosts nobody has
            placed in one, reachable through their site alone. */}
        <Field label={t("Team")} hint={t("the team the hosts belong to; a team is a boundary of authority, not a label")}>
          <select value={filters.team} onChange={(event) => setFilter("team", event.target.value)} data-testid="filter-team">
            <option value="">{t("team: any")}</option>
            {(teams).map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
            <option value="none">{t("no team")}</option>
            {filters.team && filters.team !== "none" && !teams.some((one) => one.id === filters.team) && (
              <option value={filters.team}>{filters.team}</option>
            )}
          </select>
        </Field>
        {/* The "needs attention" boxes: each is the filter a dashboard
            tile links here with, ticked means "only these". */}
        <Field label={t("Needs attention")} wide>
          <Check
            checked={filters.failed_units === "true"}
            onChange={(on) => setFilter("failed_units", on ? "true" : "")}
          >
            <span title={t("hosts with at least one failed unit")}>{t("failed units")}</span>
          </Check>
          <Check
            checked={filters.package_db_broken === "true"}
            onChange={(on) => setFilter("package_db_broken", on ? "true" : "")}
          >
            <span title={t("hosts whose package database the last operation found broken")}>
              {t("package database broken")}
            </span>
          </Check>
          <Check
            checked={filters.sssd_offline === "true"}
            onChange={(on) => setFilter("sssd_offline", on ? "true" : "")}
          >
            <span title={t("domain-joined hosts whose SSSD reports itself offline")}>{t("SSSD offline")}</span>
          </Check>
          <Check
            checked={filters.agent_behind === "true"}
            onChange={(on) => setFilter("agent_behind", on ? "true" : "")}
          >
            <span title={t("hosts whose agent is older than the newest one in the fleet")}>{t("agent behind")}</span>
          </Check>
        </Field>
      </Fields>
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

/**
 * One dimension of the fleet: a heading, then the bars under it. A row that
 * can be narrowed to is a word to press, so the count is one click from the
 * hosts it counted.
 */
function Dimension({ label, items, pick }: {
  label: string;
  items: { label: string; value: number; tone: Tone; onPick?: () => void }[];
  pick?: string;
}) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="fl-subhead">{label}</h3>
      <Bars items={items.map((one) => ({
        label: one.onPick
          ? <button type="button" className="fl-word" title={pick} onClick={one.onPick}>{one.label}</button>
          : one.label,
        value: one.value,
        tone: one.tone,
      }))} />
    </div>
  );
}

/**
 * When the list was last read from the server, with a way to read it again
 * now rather than at the next tick: an operator who has just changed
 * something on a host does not want to wait five seconds to see it.
 */
function Refreshed({ at, fetching, onRefresh }: { at: number; fetching: boolean; onRefresh: () => void }) {
  const t = useT();
  return (
    <span className="fl-note" data-testid="refreshed">
      {at > 0 ? t("refreshed {when}", { when: relativeTime(new Date(at).toISOString()) }) : t("not yet loaded")}
      {" · "}
      <button type="button" className="fl-word" onClick={onRefresh} disabled={fetching} data-testid="refresh-now">
        {fetching ? t("refreshing…") : t("refresh now")}
      </button>
    </span>
  );
}

function stateTone(state: Host["connection_state"]): Tone {
  return state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
}

/** The dot the list uses where there is no room for the word. */
export { Dot };
