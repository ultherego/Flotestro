import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ODSTEP_ODSWIEZANIA } from "../lib/strumien";
import { api, type Collection } from "../lib/api";
import type { Host } from "../lib/types";
import { Blad, Czas, FlagaOpcjonalna, LiczbaOpcjonalna, Pusto, StanPolaczenia } from "../components/ui";

/**
 * Lista hostow z filtrami wykonywanymi po stronie serwera. Panel nigdy nie
 * pobiera calej floty do pamieci przegladarki, zeby ja przefiltrowac.
 */
export function Hosty() {
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [osFamily, setOsFamily] = useState("");
  const [connectionState, setConnectionState] = useState("");

  const parametry = new URLSearchParams();
  if (site) parametry.set("site", site);
  if (environment) parametry.set("environment", environment);
  if (osFamily) parametry.set("os_family", osFamily);
  if (connectionState) parametry.set("connection_state", connectionState);
  parametry.set("limit", "200");

  const { data, error, isLoading } = useQuery({
    queryKey: ["hosts", parametry.toString()],
    queryFn: () => api.get<Collection<Host>>(`/api/v1/hosts?${parametry}`),
    // Stan hostow zmienia sie sam z siebie - przez heartbeaty, nie tylko
    // przez operacje operatora - wiec lista odswieza sie bez jego udzialu.
    refetchInterval: ODSTEP_ODSWIEZANIA,
  });

  if (error) return <Blad error={error} />;

  return (
    <>
      <h1>Hosts</h1>
      <p className="podtytul">Filters are applied server-side.</p>

      <div className="filtry">
        <input placeholder="site" value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder="environment" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        <select value={osFamily} onChange={(e) => setOsFamily(e.target.value)}>
          <option value="">OS: any</option>
          <option value="debian">debian</option>
          <option value="rhel">rhel</option>
        </select>
        <select value={connectionState} onChange={(e) => setConnectionState(e.target.value)}>
          <option value="">state: any</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="stale">stale</option>
          <option value="unknown">unknown</option>
        </select>
      </div>

      {isLoading ? (
        <Pusto>Loading…</Pusto>
      ) : !data?.items.length ? (
        <Pusto>No host matches the filters.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th><th>State</th><th>Management address</th><th>System</th><th>Site</th>
              <th>Environment</th><th>Domain</th><th>Updates</th>
              <th>Failed units</th><th>Reboot</th><th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((host) => (
              <tr key={host.id}>
                <td><Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link></td>
                <td><StanPolaczenia stan={host.connection_state} /></td>
                {/* Adres zarzadzania, a nie pierwszy adres hosta z brzegu.
                    Nieustalony jest pokazany jako nieustalony. */}
                <td>
                  {host.management_address
                    ? <span className="adres-listy" title={`source: ${host.management_address_source}`}>{host.management_address}</span>
                    : <span className="znacznik nieznany">unknown</span>}
                </td>
                <td>{host.os_distribution || host.os_family || "—"} {host.os_version}</td>
                <td>{host.site}</td>
                <td>{host.environment}</td>
                <td>{host.identity.enrolled ? host.identity.domain : <span className="znacznik">not in domain</span>}</td>
                <td><LiczbaOpcjonalna wartosc={host.pending_updates} ostrzegajOd={1} /></td>
                <td><LiczbaOpcjonalna wartosc={host.failed_units} ostrzegajOd={1} /></td>
                <td><FlagaOpcjonalna wartosc={host.reboot_required} /></td>
                <td><Czas wartosc={host.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
