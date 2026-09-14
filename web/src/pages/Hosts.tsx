import { useEffect, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, loadedItems, LIST_PAGE, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import type { FleetActivity, Host } from "../lib/types";
import { ErrorBox, Time, OptionalFlag, OptionalNumber, Empty, ConnectionState } from "../components/ui";
import { Card, EmptyState, PageHeader, Toolbar } from "../components/layout";
import { Breakdown, Meter, StatusBar } from "../components/widgets";
import { useT } from "../i18n";

/** The adapters a host can be filtered by; the names the hosts report. */
const CAPABILITIES = [
  "systemd", "packages.apt", "packages.dnf", "packages.pacman", "journald", "docker", "docker.compose",
  "schedules", "network", "dns", "firewall", "storage", "sshd", "kernel", "files.managed",
];

/**
 * The host list with filters executed on the server side. The panel never
 * fetches the whole fleet into the browser memory to filter it: the search,
 * the filters and the paging all happen in the database, and the screen
 * grows page by page with the cursor the server hands back.
 */
export function Hosts() {
  const t = useT();
  const permissions = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canAdd = (permissions.data?.permissions ?? []).includes("host.enroll.create");
  // A tile on the dashboard links here with a filter already set; the
  // address only seeds the filters, the operator changes them freely.
  const [initial] = useSearchParams();
  const [search, setSearch] = useState(initial.get("q") ?? "");
  const [site, setSite] = useState(initial.get("site") ?? "");
  const [environment, setEnvironment] = useState(initial.get("environment") ?? "");
  const [osFamily, setOsFamily] = useState(initial.get("os_family") ?? "");
  const [connectionState, setConnectionState] = useState(initial.get("connection_state") ?? "");
  const [lifecycleState, setLifecycleState] = useState(initial.get("lifecycle_state") ?? "");
  const [owner, setOwner] = useState(initial.get("owner") ?? "");
  const [maintenance, setMaintenance] = useState(initial.get("maintenance") ?? "");
  const [capability, setCapability] = useState(initial.get("capability") ?? "");
  // Tags typed as words: every one of them has to be on the host. A chip
  // on a row links here with the tag filled in.
  const [tags, setTags] = useState(initial.getAll("tag").join(" "));
  // A segment of the status bar above the list links here with a state;
  // the page is already open then, so the address is read again on every
  // arrival, not only on the first.
  const location = useLocation();
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const wanted = params.get("connection_state");
    if (wanted !== null) setConnectionState(wanted);
    const wantedTags = params.getAll("tag");
    if (wantedTags.length > 0) setTags(wantedTags.join(" "));
  }, [location.key, location.search]);
  // The typed text reaches the server after a pause, not per keystroke.
  const settledSearch = useDebounced(search.trim());
  const settledOwner = useDebounced(owner.trim());
  const settledTags = useDebounced(tags.trim());

  const params = new URLSearchParams();
  if (settledSearch) params.set("q", settledSearch);
  if (site) params.set("site", site);
  if (environment) params.set("environment", environment);
  if (osFamily) params.set("os_family", osFamily);
  if (connectionState) params.set("connection_state", connectionState);
  if (lifecycleState) params.set("lifecycle_state", lifecycleState);
  if (settledOwner) params.set("owner", settledOwner);
  if (maintenance) params.set("maintenance", maintenance);
  if (capability) params.set("capability", capability);
  for (const tag of settledTags.split(/\s+/).filter(Boolean)) params.append("tag", tag);
  params.set("limit", String(LIST_PAGE));

  const hosts = useInfiniteQuery({
    queryKey: ["hosts", params.toString()],
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
  // status bar and the composition do not depend on which page is loaded
  // or which filters are set.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  if (hosts.error) return <ErrorBox error={hosts.error} />;

  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const a = activity.data;
  const fleetSize = a?.by_connection_state.reduce((sum, facet) => sum + facet.count, 0);
  // A state absent from the facets is a state no host is in; the facets
  // themselves absent are a count nobody has yet, and the segment shows
  // a dash.
  const byConnection = (state: string) => (a ? a.by_connection_state.find((f) => f.key === state)?.count ?? 0 : undefined);
  const facets = (items: { key: string; count: number }[]) => items.map((f) => ({ label: f.key, value: f.count }));
  // The meter measures each host against the busiest one on the list; a
  // host whose count is unknown does not set the scale.
  const mostUpdates = Math.max(0, ...rows.map((host) => host.pending_updates ?? 0));

  return (
    <>
      {/* The link is seen by whoever can order an installation; for the
          rest it would lead only to a refusal. The server decides what is
          allowed anyway. */}
      <PageHeader
        title={t("Hosts")}
        description={t("Filters are applied server-side.")}
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
          <Toolbar end={hosts.data && <span>{t("{n} hosts", { n: total })}</span>}>
            <input
              placeholder={t("Search hostname, address, machine ID or owner")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <input placeholder={t("site")} value={site} onChange={(e) => setSite(e.target.value)} />
            <input placeholder={t("environment")} value={environment} onChange={(e) => setEnvironment(e.target.value)} />
            <input placeholder={t("owner")} value={owner} onChange={(e) => setOwner(e.target.value)} />
            <input
              placeholder={t("tags, e.g. role=db tier=gold")}
              title={t("every listed tag has to be on the host")}
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
            <select value={osFamily} onChange={(e) => setOsFamily(e.target.value)}>
              <option value="">{t("OS: any")}</option>
              <option value="debian">debian</option>
              <option value="rhel">rhel</option>
            </select>
            <select value={connectionState} onChange={(e) => setConnectionState(e.target.value)}>
              <option value="">{t("state: any")}</option>
              <option value="online">{t("online")}</option>
              <option value="offline">{t("offline")}</option>
              <option value="stale">{t("stale")}</option>
              <option value="unknown">{t("unknown")}</option>
            </select>
            <select value={lifecycleState} onChange={(e) => setLifecycleState(e.target.value)}>
              <option value="">{t("lifecycle: any")}</option>
              <option value="active">{t("active")}</option>
              <option value="quarantined">{t("quarantined")}</option>
              <option value="recovery">{t("recovery")}</option>
              <option value="retiring">{t("retiring")}</option>
              <option value="retired">{t("retired")}</option>
            </select>
            <select value={maintenance} onChange={(e) => setMaintenance(e.target.value)}>
              <option value="">{t("maintenance: any")}</option>
              <option value="true">{t("in a maintenance window")}</option>
              <option value="false">{t("outside a maintenance window")}</option>
            </select>
            <select value={capability} onChange={(e) => setCapability(e.target.value)}>
              <option value="">{t("capability: any")}</option>
              {CAPABILITIES.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </Toolbar>

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
                  <th>{t("Host")}</th><th>{t("State")}</th><th>{t("System")}</th><th>{t("Site")}</th>
                  <th>{t("Environment")}</th><th>{t("Domain")}</th><th>{t("Updates")}</th>
                  <th className="num">{t("Failed units")}</th><th>{t("Reboot")}</th><th>{t("Last seen")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((host) => (
                  <tr key={host.id}>
                    {/* The name and, under it, the management address - not
                        just any first address of the host. Undetermined is
                        shown as undetermined. */}
                    <td>
                      <div className="fp-host-cell">
                        <Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link>
                        {host.management_address
                          ? <span className="fp-host-address" title={t("source: {source}", { source: host.management_address_source ?? "" })}>{host.management_address}</span>
                          : <span><span className="badge unknown">{t("unknown")}</span></span>}
                        {/* The tags as chips; a chip narrows the list to
                            its tag, so a role is one click from "every
                            host with this role". */}
                        {host.tags.length > 0 && (
                          <span className="fp-host-tags" style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {host.tags.map((tag) => (
                              <Link
                                key={tag}
                                className="badge"
                                to={`/hosts?tag=${encodeURIComponent(tag)}`}
                                title={t("show every host tagged {tag}", { tag })}
                              >
                                {tag}
                              </Link>
                            ))}
                          </span>
                        )}
                      </div>
                    </td>
                    <td><ConnectionState state={host.connection_state} /></td>
                    <td>{host.os_distribution || host.os_family || "—"} {host.os_version}</td>
                    <td>{host.site}</td>
                    <td>{host.environment}</td>
                    <td>{host.identity.enrolled ? host.identity.domain : <span className="badge">{t("not in domain")}</span>}</td>
                    {/* The bar is the host's share of the busiest host on the
                        list; the security part is named, because it is the
                        part that cannot wait. An unknown count stays a badge,
                        not an empty bar. */}
                    <td className="fp-meter-cell" data-testid="host-updates">
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
                    </td>
                    <td className="num"><OptionalNumber value={host.failed_units} warnFrom={1} /></td>
                    <td><OptionalFlag value={host.reboot_required} /></td>
                    <td><Time value={host.last_seen_at} /></td>
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
        </Card>

        <Card className="span-3" title={t("Fleet composition")} description={t("By system and by agent build.")}>
          {a ? (
            <>
              <h4 className="widget-subhead">{t("By system")}</h4>
              <Breakdown items={facets(a.by_os_family)} />
              <h4 className="widget-subhead">{t("Sites and environments")}</h4>
              <Breakdown tone="ok" items={[...facets(a.by_site), ...facets(a.by_environment)]} />
              <h4 className="widget-subhead">{t("Agent builds")}</h4>
              <Breakdown tone="neutral" items={facets(a.by_agent_version)} />
              <h4 className="widget-subhead">{t("Lifecycle")}</h4>
              <Breakdown tone="info" items={facets(a.by_lifecycle_state)} />
            </>
          ) : activity.isError ? (
            <p className="fp-blank">{t("The composition could not be counted.")}</p>
          ) : <Empty>{t("Loading…")}</Empty>}
        </Card>
      </div>
    </>
  );
}
