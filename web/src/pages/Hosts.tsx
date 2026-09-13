import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { REFRESH_INTERVAL } from "../lib/stream";
import { api, type Collection } from "../lib/api";
import type { Host } from "../lib/types";
import { ErrorBox, Time, OptionalFlag, OptionalNumber, Empty, ConnectionState } from "../components/ui";
import { useT } from "../i18n";

/**
 * The host list with filters executed on the server side. The panel never
 * fetches the whole fleet into the browser memory to filter it.
 */
export function Hosts() {
  const t = useT();
  const permissions = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canAdd = (permissions.data?.permissions ?? []).includes("host.enroll.create");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [osFamily, setOsFamily] = useState("");
  const [connectionState, setConnectionState] = useState("");

  const params = new URLSearchParams();
  if (site) params.set("site", site);
  if (environment) params.set("environment", environment);
  if (osFamily) params.set("os_family", osFamily);
  if (connectionState) params.set("connection_state", connectionState);
  params.set("limit", "200");

  const { data, error, isLoading } = useQuery({
    queryKey: ["hosts", params.toString()],
    queryFn: () => api.get<Collection<Host>>(`/api/v1/hosts?${params}`),
    // The host state changes on its own - through heartbeats, not only
    // through operator actions - so the list refreshes without them.
    refetchInterval: REFRESH_INTERVAL,
  });

  if (error) return <ErrorBox error={error} />;

  return (
    <>
      <div className="header-with-action">
        <h1>{t("Hosts")}</h1>
        {/* The link is seen by whoever can order an installation; for the
            rest it would lead only to a refusal. The server decides what is
            allowed anyway. */}
        {canAdd && <Link to="/hosts/new" className="button">{t("Add host")}</Link>}
      </div>
      <p className="subtitle">{t("Filters are applied server-side.")}</p>

      <div className="filters">
        <input placeholder={t("site")} value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder={t("environment")} value={environment} onChange={(e) => setEnvironment(e.target.value)} />
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
      </div>

      {isLoading ? (
        <Empty>{t("Loading…")}</Empty>
      ) : !data?.items.length ? (
        <Empty>{t("No host matches the filters.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Host")}</th><th>{t("State")}</th><th>{t("Management address")}</th><th>{t("System")}</th><th>{t("Site")}</th>
              <th>{t("Environment")}</th><th>{t("Domain")}</th><th>{t("Updates")}</th>
              <th>{t("Failed units")}</th><th>{t("Reboot")}</th><th>{t("Last seen")}</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((host) => (
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
                <td><OptionalNumber value={host.pending_updates} warnFrom={1} /></td>
                <td><OptionalNumber value={host.failed_units} warnFrom={1} /></td>
                <td><OptionalFlag value={host.reboot_required} /></td>
                <td><Time value={host.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
