import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
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
  });

  if (error) return <Blad error={error} />;

  return (
    <>
      <h1>Hosty</h1>
      <p className="podtytul">Filtry sa wykonywane po stronie serwera.</p>

      <div className="filtry">
        <input placeholder="lokalizacja" value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder="srodowisko" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        <select value={osFamily} onChange={(e) => setOsFamily(e.target.value)}>
          <option value="">system: dowolny</option>
          <option value="debian">debian</option>
          <option value="rhel">rhel</option>
        </select>
        <select value={connectionState} onChange={(e) => setConnectionState(e.target.value)}>
          <option value="">stan: dowolny</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="stale">stale</option>
          <option value="unknown">unknown</option>
        </select>
      </div>

      {isLoading ? (
        <Pusto>Wczytywanie…</Pusto>
      ) : !data?.items.length ? (
        <Pusto>Zaden host nie pasuje do filtrow.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th><th>Stan</th><th>System</th><th>Lokalizacja</th>
              <th>Srodowisko</th><th>Domena</th><th>Aktualizacje</th>
              <th>Jednostki w bledzie</th><th>Restart</th><th>Ostatnio widziany</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((host) => (
              <tr key={host.id}>
                <td><Link to={`/hosty/${host.id}`}>{host.hostname}</Link></td>
                <td><StanPolaczenia stan={host.connection_state} /></td>
                <td>{host.os_distribution || host.os_family || "—"} {host.os_version}</td>
                <td>{host.site}</td>
                <td>{host.environment}</td>
                <td>{host.identity.enrolled ? host.identity.domain : <span className="znacznik">poza domena</span>}</td>
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
