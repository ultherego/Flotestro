import { useEffect, useRef, useState, type CSSProperties } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, loadedItems, LIST_PAGE, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { RELEASE_CHANNELS, refusalName, type FleetActivity, type Host, type Relay } from "../lib/types";
import { relativeTime } from "../lib/format";
import { ErrorBox, Time, OptionalFlag, OptionalNumber, Empty, ConnectionState } from "../components/ui";
import { Card, EmptyState, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import {
  ColumnChooser, PageSizeSelect, Td, Th, formatSort, parseSort, useColumns, usePageSize, type ColumnDef, type SortValue,
} from "../components/SortableTable";
import { Breakdown, Meter, StatusBar } from "../components/widgets";
import { HostsMetadata } from "./HostsMetadata";
import { useTeams } from "./Teams";
import { useT } from "../i18n";

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

/**
 * The columns the server can order the list by, as it names them.
 */
const SORT_COLUMNS = [
  "hostname", "site", "environment", "owner", "lifecycle_state", "connection_state", "agent_version",
  "last_seen_at", "pending_updates", "pending_security_updates", "failed_units",
];

/** The order the server lists in when none is asked for. */
const DEFAULT_SORT: SortValue = { column: "hostname", descending: false };

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
  owner: "", maintenance: "", capability: "", channel: "", reboot_required: "", security_updates: "",
  identity_domain: "", connection_refusal: "", tags: "", failed_units: "", package_db_broken: "",
  sssd_offline: "", agent_behind: "", relay: "", failure_domain: "", team: "", sort: "",
};

/**
 * A button that reads as a word in a line rather than as a control: a value
 * in the composition or the cross on a chip narrows or widens the list, and
 * a row of accent buttons would drown the numbers next to them.
 */
const WORD_BUTTON: CSSProperties = {
  background: "none", border: 0, padding: 0, font: "inherit", color: "inherit",
  textDecoration: "underline dotted", cursor: "pointer",
};

/** The shape of a relay identifier, as the server checks it. */
const RELAY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The filters as the address carries them; a name absent from it is empty. */
function readFilters(params: URLSearchParams): HostFilters {
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
function filterParams(filters: HostFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[]) {
    if (key === "tags") continue;
    const value = filters[key].trim();
    if (value) params.set(key, value);
  }
  for (const tag of filters.tags.split(/\s+/).filter(Boolean)) params.append("tag", tag);
  return params;
}

/**
 * The host list with filters executed on the server side.
 */
export function Hosts() {
  const t = useT();
  const permissions = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canAdd = (permissions.data?.permissions ?? []).includes("host.enroll.create");
  // The bulk workspace is where a selection goes; whoever cannot read
  // campaigns has no such workspace and sees no checkboxes.
  const canSelect = (permissions.data?.permissions ?? []).includes("campaign.read");
  // The metadata panel is for whoever may write tags or maintenance
  // windows; the server judges each host on its own anyway.
  const canSetMetadata = ["host.tag.write", "host.maintenance.write"]
    .some((permission) => (permissions.data?.permissions ?? []).includes(permission));
  const [metadataOpen, setMetadataOpen] = useState(false);
  const navigate = useNavigate();
  // The address carries the filters: a tile on the dashboard, a chip on a
  // row and a bookmark all link here with some already set, and every change
  // goes back into the address so the view can be handed on as a link.
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<HostFilters>(() => readFilters(searchParams));
  const setFilter = (key: keyof HostFilters, value: string) =>
    setFilters((previous) => ({ ...previous, [key]: value }));
  const written = useRef(searchParams.toString());
  useEffect(() => {
    const next = filterParams(filters).toString();
    if (next !== written.current) {
      written.current = next;
      setSearchParams(new URLSearchParams(next), { replace: true });
    }
  }, [filters, setSearchParams]);
  useEffect(() => {
    const current = searchParams.toString();
    if (current !== written.current) {
      written.current = current;
      setFilters(readFilters(searchParams));
    }
  }, [searchParams]);
  // The rows ticked for the bulk workspace.
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
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
  const [pageSize, setPageSize] = usePageSize("hosts", LIST_PAGE);
  const narrowing = filterParams({
    ...filters,
    q: settledSearch, owner: settledOwner, tags: settledTags, identity_domain: settledDomain,
    site: settledSite, environment: settledEnvironment, failure_domain: settledFailureDomain,
    relay: RELAY_ID.test(settledRelay) ? settledRelay : "", sort: "",
  });
  const params = new URLSearchParams(narrowing);
  if (sortSent) params.set("sort", sortSent);
  params.set("limit", String(pageSize));
  const filterKey = params.toString();
  // The selection drops with the narrowing, not with the order or the
  // page size: the rows it named are still on the screen after a sort.
  const narrowingKey = narrowing.toString();
  useEffect(() => {
    setSelected(new Set());
  }, [narrowingKey]);

  const hosts = useInfiniteQuery({
    queryKey: ["hosts", filterKey],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Host>>(`/api/v1/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    // The host state changes on its own - through heartbeats, not only
    // through operator actions - so the list refreshes without them.
    refetchInterval: REFRESH_INTERVAL,
  });
  // The facets over the whole visible fleet, counted in the database: the
  // status bar and the composition do not depend on which page is loaded or
  // which filters are set.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  // The relays, for the filter by route: read only by whoever may list
  // them; for the rest the filter is still reachable through the address.
  const canSeeRelays = (permissions.data?.permissions ?? []).includes("host.enroll.read");
  const relays = useQuery({
    queryKey: ["relays"],
    queryFn: () => api.get<{ items: Relay[] }>("/api/v1/relays"),
    enabled: canSeeRelays,
    staleTime: 60 * 1000,
  });
  // The teams, for the filter by team.
  const teams = useTeams();

  // The columns of the table.
  const columns = useColumns("hosts", [
    { key: "host", label: t("Host"), sort: "hostname", fixed: true },
    { key: "state", label: t("State"), sort: "connection_state" },
    { key: "address", label: t("Address"), secondary: true },
    // The owner is empty on most fleets until somebody records it; the
    // column stays off the screen until chosen, and the filter is always
    // there.
    { key: "owner", label: t("Owner"), sort: "owner", secondary: true, hidden: true },
    { key: "system", label: t("System"), secondary: true },
    { key: "site", label: t("Site"), sort: "site" },
    { key: "environment", label: t("Environment"), sort: "environment" },
    { key: "lifecycle", label: t("Lifecycle"), sort: "lifecycle_state", hidden: true },
    { key: "agent", label: t("Agent"), sort: "agent_version", hidden: true },
    { key: "domain", label: t("Domain"), secondary: true },
    { key: "updates", label: t("Updates"), sort: "pending_updates" },
    { key: "security", label: t("Security updates"), sort: "pending_security_updates", className: "num", hidden: true },
    { key: "failed_units", label: t("Failed units"), sort: "failed_units", className: "num" },
    { key: "reboot", label: t("Reboot"), secondary: true },
    { key: "last_seen", label: t("Last seen"), sort: "last_seen_at" },
  ] satisfies ColumnDef[]);
  // A click on a heading asks for the next order of that column; the
  // list's own order is the hostname, so a sort cleared is a sort by name.
  const onSort = (next: SortValue) => setFilter("sort", formatSort(next));
  const shownSort = sort ?? DEFAULT_SORT;

  if (hosts.error) return <ErrorBox error={hosts.error} />;

  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const a = activity.data;
  const fleetSize = a?.by_connection_state.reduce((sum, facet) => sum + facet.count, 0);
  // A state absent from the facets is a state no host is in; the facets
  // themselves absent are a count nobody has yet, and the segment shows a
  // dash.
  const byConnection = (state: string) => (a ? a.by_connection_state.find((f) => f.key === state)?.count ?? 0 : undefined);
  // A row of the composition narrows the list to its value: the count is
  // one click from the hosts it counted.
  const facets = (items: { key: string; count: number }[], key: keyof HostFilters) => items.map((f) => ({
    label: (
      <button type="button" style={WORD_BUTTON} onClick={() => setFilter(key, f.key)} title={t("show only these hosts")}>
        {f.key}
      </button>
    ),
    value: f.count,
  }));
  const facetKeys = (items?: { key: string }[]) => (items ?? []).map((f) => f.key).filter(Boolean);
  // The facets do not count owners, so the suggestions are the owners of
  // the rows on screen: a hint, not the whole list.
  const ownerKeys = [...new Set(rows.map((host) => host.owner).filter((owner): owner is string => Boolean(owner)))].sort();
  // The active filters as chips: what the list is narrowed by, each with its
  // own way off.
  const chipLabels: Record<Exclude<keyof HostFilters, "sort">, string> = {
    q: t("search"), site: t("site"), environment: t("environment"), os_family: t("OS"),
    connection_state: t("state"), lifecycle_state: t("lifecycle"), owner: t("owner"),
    maintenance: t("maintenance"), capability: t("capability"), channel: t("channel"),
    reboot_required: t("reboot required"), security_updates: t("security updates"),
    identity_domain: t("domain"), connection_refusal: t("refused for"), tags: t("tags"),
    failed_units: t("failed units"), package_db_broken: t("package database broken"),
    sssd_offline: t("SSSD offline"), agent_behind: t("agent behind"), relay: t("relay"),
    failure_domain: t("failure domain"), team: t("team"),
  };
  const chipValue = (key: keyof HostFilters, value: string): string => {
    if (key === "connection_refusal") return t(refusalName(value));
    if (key === "relay") return relays.data?.items.find((relay) => relay.id === value)?.name ?? value;
    // The chip says which team in words; the server's own word for the
    // other list says what it means rather than repeating "none".
    if (key === "team") {
      if (value === "none") return t("no team");
      return teams.data?.items.find((team) => team.id === value)?.name ?? value;
    }
    return value;
  };
  const activeFilters = (Object.keys(EMPTY_FILTERS) as (keyof HostFilters)[])
    .filter((key): key is Exclude<keyof HostFilters, "sort"> => key !== "sort" && filters[key].trim() !== "");
  // The meter measures each host against the busiest one on the list; a
  // host whose count is unknown does not set the scale.
  const mostUpdates = Math.max(0, ...rows.map((host) => host.pending_updates ?? 0));

  const toggle = (id: string, on: boolean) => {
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(id); else next.delete(id);
      return next;
    });
  };
  // The header box ticks what is loaded, not what matches: a page not yet
  // fetched has hosts nobody has seen, and a campaign must not reach them
  // from a box that looked like "all".
  const allLoadedSelected = rows.length > 0 && rows.every((host) => selected.has(host.id));
  const openInBulk = () => {
    const address = new URLSearchParams();
    for (const id of selected) address.append("host_id", id);
    navigate(`/bulk?${address}`);
  };

  return (
    <>
      {/* The link is seen by whoever can order an installation; for the
          rest it would lead only to a refusal. The server decides what is
          allowed anyway. */}
      <PageHeader
        title={t("Hosts")}
        description={<>{t("Filters are applied server-side.")} <Refreshed at={hosts.dataUpdatedAt} fetching={hosts.isFetching} onRefresh={() => hosts.refetch()} /></>}
        actions={canAdd && <Link to="/hosts/new" className="button primary">{t("Add host")}</Link>}
      />

      <div className="widgets">
        <Card
          className="span-12"
          title={t("Connection")}
          description={fleetSize === undefined ? t("Counted in the database over the hosts you can see.") : t("{n} hosts you can see", { n: fleetSize })}
        >
          <StatusBar segments={[
            { label: t("Online"), value: byConnection("online"), tone: "ok", to: "/hosts?connection_state=online" },
            { label: t("Stale"), value: byConnection("stale"), tone: "warn", to: "/hosts?connection_state=stale" },
            { label: t("Offline"), value: byConnection("offline"), tone: "error", to: "/hosts?connection_state=offline" },
            { label: t("Unknown"), value: byConnection("unknown"), tone: "unknown", to: "/hosts?connection_state=unknown" },
          ]} />
        </Card>

        <Card className="span-9" flush>
          <Toolbar end={<>
            {hosts.data && <span>{t("{n} hosts", { n: total })}</span>}
            <PageSizeSelect value={pageSize} onChange={setPageSize} />
            <ColumnChooser columns={columns} />
            <ExportButton path="/api/v1/hosts" params={params} />
          </>}>
            {/* The box is narrower than the sentence that says what it
                searches; the short placeholder fits and the sentence stays
                on hover and for the screen reader. */}
            <input
              placeholder={t("Search hosts…")}
              title={t("Search hostname, address, machine ID or owner")}
              aria-label={t("Search hostname, address, machine ID or owner")}
              value={filters.q}
              onChange={(e) => setFilter("q", e.target.value)}
            />
            {/* The sites, environments and owners are suggested from the
                facets: the fleet's own values, not a list to maintain. */}
            <input placeholder={t("site")} value={filters.site} list="hosts-sites" onChange={(e) => setFilter("site", e.target.value)} />
            <datalist id="hosts-sites">{facetKeys(a?.by_site).map((key) => <option key={key} value={key} />)}</datalist>
            <input placeholder={t("environment")} value={filters.environment} list="hosts-environments" onChange={(e) => setFilter("environment", e.target.value)} />
            <datalist id="hosts-environments">{facetKeys(a?.by_environment).map((key) => <option key={key} value={key} />)}</datalist>
            <input placeholder={t("owner")} value={filters.owner} list="hosts-owners" onChange={(e) => setFilter("owner", e.target.value)} />
            <datalist id="hosts-owners">{ownerKeys.map((key) => <option key={key} value={key} />)}</datalist>
            <input
              placeholder={t("tags, e.g. role=db tier=gold")}
              title={t("every listed tag has to be on the host")}
              value={filters.tags}
              onChange={(e) => setFilter("tags", e.target.value)}
            />
            {/* The systems are the ones the fleet reports, from the facets;
                a family set by a link but absent from the fleet stays
                listed, so the control shows what the list is narrowed by. */}
            <select value={filters.os_family} onChange={(e) => setFilter("os_family", e.target.value)}>
              <option value="">{t("OS: any")}</option>
              {[...new Set([...facetKeys(a?.by_os_family), ...(filters.os_family ? [filters.os_family] : [])])].map((family) => (
                <option key={family} value={family}>{family}</option>
              ))}
            </select>
            <select value={filters.connection_state} onChange={(e) => setFilters((previous) => ({ ...previous, connection_state: e.target.value, connection_refusal: "" }))}>
              <option value="">{t("state: any")}</option>
              <option value="online">{t("online")}</option>
              <option value="offline">{t("offline")}</option>
              <option value="stale">{t("stale")}</option>
              <option value="unknown">{t("unknown")}</option>
            </select>
            <select value={filters.lifecycle_state} onChange={(e) => setFilter("lifecycle_state", e.target.value)}>
              <option value="">{t("lifecycle: any")}</option>
              <option value="active">{t("active")}</option>
              <option value="quarantined">{t("quarantined")}</option>
              <option value="recovery">{t("recovery")}</option>
              <option value="retiring">{t("retiring")}</option>
              <option value="retired">{t("retired")}</option>
            </select>
            <select value={filters.maintenance} onChange={(e) => setFilter("maintenance", e.target.value)}>
              <option value="">{t("maintenance: any")}</option>
              <option value="true">{t("in a maintenance window")}</option>
              <option value="false">{t("outside a maintenance window")}</option>
            </select>
            <select value={filters.capability} onChange={(e) => setFilter("capability", e.target.value)}>
              <option value="">{t("capability: any")}</option>
              {CAPABILITIES.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
            <select value={filters.channel} onChange={(e) => setFilter("channel", e.target.value)}>
              <option value="">{t("channel: any")}</option>
              {RELEASE_CHANNELS.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
            <select value={filters.reboot_required} onChange={(e) => setFilter("reboot_required", e.target.value)} data-testid="filter-reboot">
              <option value="">{t("reboot: any")}</option>
              <option value="true">{t("reboot required")}</option>
              <option value="false">{t("no reboot required")}</option>
            </select>
            <select value={filters.security_updates} onChange={(e) => setFilter("security_updates", e.target.value)} data-testid="filter-security">
              <option value="">{t("security updates: any")}</option>
              <option value="true">{t("security updates waiting")}</option>
              <option value="false">{t("no security updates")}</option>
            </select>
            <input
              placeholder={t("directory domain")}
              title={t("the directory domain the host is joined to, e.g. corp.example")}
              value={filters.identity_domain}
              onChange={(e) => setFilter("identity_domain", e.target.value)}
            />
            <input
              placeholder={t("failure domain")}
              title={t("the rack, zone or cluster an operator placed the host in, e.g. rack-a")}
              value={filters.failure_domain}
              onChange={(e) => setFilter("failure_domain", e.target.value)}
            />
            {/* The route: a relay by name for whoever may list them, the
                identifier for the rest. */}
            {canSeeRelays ? (
              <select value={filters.relay} onChange={(e) => setFilter("relay", e.target.value)} data-testid="filter-relay">
                <option value="">{t("relay: any")}</option>
                {(relays.data?.items ?? []).map((relay) => <option key={relay.id} value={relay.id}>{relay.name}</option>)}
                {filters.relay && !relays.data?.items.some((relay) => relay.id === filters.relay) && (
                  <option value={filters.relay}>{filters.relay}</option>
                )}
              </select>
            ) : (
              <input placeholder={t("relay identifier")} value={filters.relay} onChange={(e) => setFilter("relay", e.target.value)} />
            )}
            {/* The team: who the hosts belong to, which is not where they
                stand. The last entry is the list an administrator works
                through after the teams are created - the hosts nobody has
                placed in one, reachable through their site alone. */}
            <select
              value={filters.team}
              onChange={(e) => setFilter("team", e.target.value)}
              title={t("the team the hosts belong to; a team is a boundary of authority, not a label")}
              data-testid="filter-team"
            >
              <option value="">{t("team: any")}</option>
              {(teams.data?.items ?? []).map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
              <option value="none">{t("no team")}</option>
              {filters.team && filters.team !== "none" && !teams.data?.items.some((team) => team.id === filters.team) && (
                <option value={filters.team}>{filters.team}</option>
              )}
            </select>
            {/* The "needs attention" boxes: each is the filter a dashboard
                tile links here with, ticked means "only these". */}
            <label className="toggle" title={t("hosts with at least one failed unit")}>
              <input type="checkbox" checked={filters.failed_units === "true"} onChange={(e) => setFilter("failed_units", e.target.checked ? "true" : "")} data-testid="filter-failed-units" />
              {t("failed units")}
            </label>
            <label className="toggle" title={t("hosts whose package database the last operation found broken")}>
              <input type="checkbox" checked={filters.package_db_broken === "true"} onChange={(e) => setFilter("package_db_broken", e.target.checked ? "true" : "")} data-testid="filter-package-db" />
              {t("package database broken")}
            </label>
            <label className="toggle" title={t("domain-joined hosts whose SSSD reports itself offline")}>
              <input type="checkbox" checked={filters.sssd_offline === "true"} onChange={(e) => setFilter("sssd_offline", e.target.checked ? "true" : "")} data-testid="filter-sssd" />
              {t("SSSD offline")}
            </label>
            <label className="toggle" title={t("hosts whose agent is older than the newest one in the fleet")}>
              <input type="checkbox" checked={filters.agent_behind === "true"} onChange={(e) => setFilter("agent_behind", e.target.checked ? "true" : "")} data-testid="filter-agent-behind" />
              {t("agent behind")}
            </label>
          </Toolbar>
          {activeFilters.length > 0 && (
            <div className="filters" style={{ padding: "0 16px", marginBottom: 12 }} data-testid="active-filters">
              {activeFilters.map((key) => (
                <span key={key} className="chip">
                  <span className="chip-tag">{chipLabels[key]}</span>
                  {chipValue(key, filters[key].trim())}
                  <button
                    type="button"
                    style={{ ...WORD_BUTTON, textDecoration: "none" }}
                    aria-label={t("clear the {name} filter", { name: chipLabels[key] })}
                    onClick={() => setFilter(key, "")}
                  >
                    ×
                  </button>
                </span>
              ))}
              <button type="button" className="secondary" onClick={() => setFilters({ ...EMPTY_FILTERS, sort: filters.sort })} data-testid="clear-filters">
                {t("Clear filters")}
              </button>
            </div>
          )}

          {hosts.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : rows.length === 0 ? (
            <EmptyState action={canAdd && <Link to="/hosts/new" className="button">{t("Add host")}</Link>}>
              {t("No host matches the filters.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  {canSelect && (
                    <th style={{ width: 28 }}>
                      <input
                        type="checkbox"
                        aria-label={t("select every loaded host")}
                        checked={allLoadedSelected}
                        onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((host) => host.id)) : new Set())}
                      />
                    </th>
                  )}
                  {columns.visible.map((column) => (
                    <Th key={column.key} columns={columns} name={column.key} sort={shownSort} onSort={onSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((host) => (
                  <tr key={host.id}>
                    {canSelect && (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={t("select {host}", { host: host.hostname })}
                          checked={selected.has(host.id)}
                          onChange={(e) => toggle(host.id, e.target.checked)}
                        />
                      </td>
                    )}
                    {/* The name and, under it, the tags. The address has a
                        column of its own, with its origin. */}
                    <Td columns={columns} name="host">
                      <div className="fp-host-cell">
                        <Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link>
                        {/* The tags as chips; a chip narrows the list to
                            its tag, so a role is one click from "every
                            host with this role". */}
                        {host.tags.length > 0 && (
                          <span className="fp-host-tags" style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {host.tags.map((tag) => (
                              <button
                                key={tag}
                                type="button"
                                className="badge"
                                onClick={() => setFilter("tags", tag)}
                                title={t("show every host tagged {tag}", { tag })}
                              >
                                {tag}
                              </button>
                            ))}
                          </span>
                        )}
                      </div>
                    </Td>
                    {/* An offline host with a refusal on record is not
                        merely away: the gateway turned it down, and the
                        reason stands under the badge rather than in a
                        trail nobody reads for a host that looks switched
                        off. */}
                    <Td columns={columns} name="state">
                      <ConnectionState state={host.connection_state} />
                      {host.last_connection_refusal && host.connection_state !== "online" && (
                        <div className="source" title={host.last_connection_refusal.detail}>
                          {t("refused: {reason} {when}", {
                            reason: t(refusalName(host.last_connection_refusal.code)),
                            when: relativeTime(host.last_connection_refusal.at),
                          })}
                        </div>
                      )}
                    </Td>
                    {/* The management address - not just any first address
                        of the host - with where it came from: what the panel
                        saw, what the host declared, or what an operator set.
                        Undetermined is shown as undetermined. */}
                    <Td columns={columns} name="address" data-testid="host-address">
                      {host.management_address ? (
                        <span className="fp-host-cell">
                          <span className="fp-host-address">{host.management_address}</span>
                          <span>
                            <span className="badge" title={t(ADDRESS_SOURCES[host.management_address_source ?? ""] ?? "address source")}>
                              {host.management_address_source}
                            </span>
                          </span>
                        </span>
                      ) : <span className="badge unknown">{t("unknown")}</span>}
                    </Td>
                    {/* The owner as recorded; a click narrows the list to
                        their hosts, like a tag chip does. */}
                    <Td columns={columns} name="owner" data-testid="host-owner">
                      {host.owner
                        ? <button type="button" style={WORD_BUTTON} onClick={() => setFilter("owner", host.owner ?? "")} title={t("show every host of {owner}", { owner: host.owner })}>{host.owner}</button>
                        : <span className="source">—</span>}
                    </Td>
                    <Td columns={columns} name="system">{host.os_distribution || host.os_family || "—"} {host.os_version}</Td>
                    <Td columns={columns} name="site">{host.site}</Td>
                    <Td columns={columns} name="environment">{host.environment}</Td>
                    {/* The lifecycle and the agent build are off the screen
                        until chosen: a click narrows the list to the state,
                        the way the composition widget does. */}
                    <Td columns={columns} name="lifecycle">
                      <button type="button" style={WORD_BUTTON} onClick={() => setFilter("lifecycle_state", host.lifecycle_state)} title={t("show only these hosts")}>
                        {host.lifecycle_state}
                      </button>
                    </Td>
                    <Td columns={columns} name="agent">{host.agent_version || <span className="badge unknown">{t("unknown")}</span>}</Td>
                    <Td columns={columns} name="domain">
                      {host.identity.enrolled
                        ? <button type="button" style={WORD_BUTTON} onClick={() => setFilter("identity_domain", host.identity.domain ?? "")} title={t("show every host in this domain")}>{host.identity.domain}</button>
                        : <span className="badge">{t("not in domain")}</span>}
                    </Td>
                    {/* The bar is the host's share of the busiest host on the
                        list; the security part is named, because it is the
                        part that cannot wait. An unknown count stays a badge,
                        not an empty bar. */}
                    <Td
                      columns={columns}
                      name="updates"
                      className="fp-meter-cell"
                      data-testid="host-updates"
                      title={host.pending_updates === null ? undefined : t("{n} pending updates, {security} of them security; the bar is the host's share of the busiest host on the list", {
                        n: host.pending_updates, security: host.pending_security_updates ?? t("an unknown number"),
                      })}
                    >
                      {host.pending_updates === null ? (
                        <OptionalNumber value={host.pending_updates} warnFrom={1} />
                      ) : (
                        <>
                          <Meter
                            value={host.pending_updates}
                            max={mostUpdates}
                            tone={(host.pending_security_updates ?? 0) > 0 ? "error" : host.pending_updates > 0 ? "warn" : "ok"}
                          />
                          {(host.pending_security_updates ?? 0) > 0 && (
                            <span className="fp-security">{t("{n} security", { n: host.pending_security_updates ?? 0 })}</span>
                          )}
                        </>
                      )}
                    </Td>
                    <Td columns={columns} name="security"><OptionalNumber value={host.pending_security_updates} warnFrom={1} /></Td>
                    <Td columns={columns} name="failed_units"><OptionalNumber value={host.failed_units} warnFrom={1} /></Td>
                    <Td columns={columns} name="reboot"><OptionalFlag value={host.reboot_required} /></Td>
                    <Td columns={columns} name="last_seen"><Time value={host.last_seen_at} /></Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {/* The next page comes on request: a page that failed to arrive is
              asked for again by hand, and the count says how much is left. */}
          {hosts.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
                {t("Load more ({n} left)", { n: total - rows.length })}
              </button>
            </p>
          )}
          {/* The selection travels to the bulk workspace as its target list.
              The bar sticks to the bottom of the view, so a selection made
              two hundred rows up is one click away without scrolling back. */}
          {selected.size > 0 && (
            <div
              data-testid="selection-bar"
              style={{
                position: "sticky", bottom: 0, zIndex: 4,
                display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
                padding: "10px 16px", background: "var(--bg-panel)", borderTop: "1px solid var(--border)",
              }}
            >
              <span>{t("{n} selected", { n: selected.size })}</span>
              <button type="button" className="primary" onClick={openInBulk}>
                {t("Open in Bulk workspace ({n})", { n: selected.size })}
              </button>
              {canSetMetadata && (
                <button type="button" className="secondary" onClick={() => setMetadataOpen(true)} data-testid="set-metadata">
                  {t("Set metadata…")}
                </button>
              )}
              <button type="button" className="secondary" onClick={() => { setSelected(new Set()); setMetadataOpen(false); }}>{t("Clear selection")}</button>
            </div>
          )}
          {/* The panel edits the loaded rows that are ticked: a host ticked
              and then filtered out of view is not edited unseen. */}
          {metadataOpen && selected.size > 0 && (
            <HostsMetadata
              hosts={rows.filter((host) => selected.has(host.id))}
              permissions={permissions.data?.permissions ?? []}
              onClose={() => setMetadataOpen(false)}
            />
          )}
        </Card>

        <Card className="span-3" title={t("Fleet composition")} description={t("By system, site, environment, agent build and lifecycle.")}>
          {a ? (
            <>
              <h4 className="widget-subhead">{t("By system")}</h4>
              <Breakdown items={facets(a.by_os_family, "os_family")} />
              {/* Two dimensions under two headings: "lab 6, test 6" in
                  one list reads as two sites. */}
              <h4 className="widget-subhead">{t("Sites")}</h4>
              <Breakdown tone="ok" items={facets(a.by_site, "site")} />
              <h4 className="widget-subhead">{t("Environments")}</h4>
              <Breakdown tone="ok" items={facets(a.by_environment, "environment")} />
              <h4 className="widget-subhead">{t("Agent builds")}</h4>
              <Breakdown tone="neutral" items={a.by_agent_version.map((f) => ({ label: f.key, value: f.count }))} />
              <h4 className="widget-subhead">{t("Lifecycle")}</h4>
              <Breakdown tone="info" items={facets(a.by_lifecycle_state, "lifecycle_state")} />
            </>
          ) : activity.isError ? (
            <p className="fp-blank">{t("The composition could not be counted.")}</p>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>
      </div>
    </>
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
    <span className="source" data-testid="refreshed">
      {at > 0 ? t("refreshed {when}", { when: relativeTime(new Date(at).toISOString()) }) : t("not yet loaded")}
      {" · "}
      <button type="button" style={WORD_BUTTON} onClick={onRefresh} disabled={fetching}>
        {fetching ? t("refreshing…") : t("refresh now")}
      </button>
    </span>
  );
}
