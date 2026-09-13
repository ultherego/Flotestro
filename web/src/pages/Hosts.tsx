import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, loadedItems, LIST_PAGE, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import type { Host } from "../lib/types";
import { ErrorBox, Time, OptionalFlag, OptionalNumber, Empty, ConnectionState } from "../components/ui";
import { Card, EmptyState, PageHeader, Toolbar } from "../components/layout";
import { useT } from "../i18n";

/** The adapters a host can be filtered by; the names the hosts report. */
const CAPABILITIES = [
  "systemd", "packages.apt", "packages.dnf", "journald", "docker", "docker.compose",
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
  // The typed text reaches the server after a pause, not per keystroke.
  const settledSearch = useDebounced(search.trim());
  const settledOwner = useDebounced(owner.trim());

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

  if (hosts.error) return <ErrorBox error={hosts.error} />;

  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;

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

      <Card flush>
        <Toolbar end={hosts.data && <span>{t("{n} hosts", { n: total })}</span>}>
          <input
            placeholder={t("Search hostname, address, machine ID or owner")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <input placeholder={t("site")} value={site} onChange={(e) => setSite(e.target.value)} />
          <input placeholder={t("environment")} value={environment} onChange={(e) => setEnvironment(e.target.value)} />
          <input placeholder={t("owner")} value={owner} onChange={(e) => setOwner(e.target.value)} />
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
                <th>{t("Host")}</th><th>{t("State")}</th><th>{t("Management address")}</th><th>{t("System")}</th><th>{t("Site")}</th>
                <th>{t("Environment")}</th><th>{t("Domain")}</th><th className="num">{t("Updates")}</th>
                <th className="num">{t("Failed units")}</th><th>{t("Reboot")}</th><th>{t("Last seen")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((host) => (
                <tr key={host.id}>
                  <td><Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link></td>
                  <td><ConnectionState state={host.connection_state} /></td>
                  {/* The management address, not just any first address of the
                      host. Undetermined is shown as undetermined. */}
                  <td>
                    {host.management_address
                      ? <span className="list-address" title={t("source: {source}", { source: host.management_address_source ?? "" })}>{host.management_address}</span>
                      : <span className="badge unknown">{t("unknown")}</span>}
                  </td>
                  <td>{host.os_distribution || host.os_family || "—"} {host.os_version}</td>
                  <td>{host.site}</td>
                  <td>{host.environment}</td>
                  <td>{host.identity.enrolled ? host.identity.domain : <span className="badge">{t("not in domain")}</span>}</td>
                  <td className="num"><OptionalNumber value={host.pending_updates} warnFrom={1} /></td>
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
    </>
  );
}
