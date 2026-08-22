import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { AuditEvent, Campaign, FleetSummary, Host } from "../lib/types";
import { Blad, Czas, Pusto, StanZadania } from "../components/ui";

/**
 * Pulpit pokazuje wylacznie dane wymagajace decyzji. Nie jest sciana
 * dekoracyjnych wykresow: kazdy kafelek prowadzi do konkretnego dzialania.
 */
export function Pulpit() {
  const podsumowanie = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<FleetSummary>("/api/v1/fleet/summary"),
  });
  const hosty = useQuery({
    queryKey: ["hosts"],
    queryFn: () => api.get<Collection<Host>>("/api/v1/hosts?limit=500"),
  });
  const kampanie = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=20"),
  });
  const audyt = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?limit=50"),
  });

  if (podsumowanie.error) return <Blad error={podsumowanie.error} />;
  const s = podsumowanie.data;

  const wymagajaUwagi = (hosty.data?.items ?? []).filter(
    (host) =>
      host.connection_state !== "online" ||
      host.reboot_required === true ||
      (host.failed_units ?? 0) > 0 ||
      host.package_database_broken ||
      (host.identity.enrolled && host.identity.sssd_online === false),
  );

  const aktywneKampanie = (kampanie.data?.items ?? []).filter((kampania) =>
    ["canary", "running", "paused", "awaiting_approval"].includes(kampania.state),
  );

  const odmowy = (audyt.data?.items ?? []).filter((zdarzenie) => zdarzenie.outcome === "denied");

  return (
    <>
      <h1>Fleet dashboard</h1>
      <p className="podtytul">Only what needs a decision.</p>

      <div className="kafelki">
        <Kafelek etykieta="Hosts" wartosc={s?.hosts} />
        <Kafelek etykieta="Online" wartosc={s?.online} />
        <Kafelek etykieta="Offline" wartosc={s?.offline} alarm={(s?.offline ?? 0) > 0} />
        <Kafelek etykieta="Active sessions" wartosc={s?.active_sessions} />
        <Kafelek etykieta="Reboot required" wartosc={s?.reboot_required} uwaga={(s?.reboot_required ?? 0) > 0} />
        <Kafelek etykieta="With failed units" wartosc={s?.with_failed_units} uwaga={(s?.with_failed_units ?? 0) > 0} />
        <Kafelek etykieta="Security updates" wartosc={s?.hosts_with_security_updates} uwaga={(s?.hosts_with_security_updates ?? 0) > 0} />
        <Kafelek etykieta="Quarantined" wartosc={s?.quarantined_hosts} alarm={(s?.quarantined_hosts ?? 0) > 0} />
      </div>

      <h2>Hosts needing attention</h2>
      {wymagajaUwagi.length === 0 ? (
        <Pusto>No host needs attention.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th><th>State</th><th>Reason</th><th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {wymagajaUwagi.map((host) => (
              <tr key={host.id}>
                <td><Link to={`/hosts/${host.id}`}>{host.hostname}</Link></td>
                <td><span className="znacznik">{host.connection_state}</span></td>
                <td>{powodyUwagi(host).join(", ")}</td>
                <td><Czas wartosc={host.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Campaigns in progress</h2>
      {aktywneKampanie.length === 0 ? (
        <Pusto>No campaigns need attention.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>State</th><th>Operation</th><th>Pause reason</th></tr>
          </thead>
          <tbody>
            {aktywneKampanie.map((kampania) => (
              <tr key={kampania.id}>
                <td><Link to={`/campaigns/${kampania.id}`}>{kampania.name}</Link></td>
                <td><StanZadania stan={kampania.state} /></td>
                <td>{kampania.action_type}</td>
                <td>{kampania.pause_reason || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Recent access denials</h2>
      {odmowy.length === 0 ? (
        <Pusto>No denials in recent events.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Operation</th><th>Reason</th></tr></thead>
          <tbody>
            {odmowy.slice(0, 10).map((zdarzenie) => (
              <tr key={zdarzenie.id}>
                <td><Czas wartosc={zdarzenie.occurred_at} /></td>
                <td>{zdarzenie.actor_id}</td>
                <td>{zdarzenie.action}</td>
                <td>{String(zdarzenie.detail?.reason ?? "")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function powodyUwagi(host: Host): string[] {
  const powody: string[] = [];
  if (host.connection_state !== "online") powody.push("no connection");
  if (host.reboot_required) powody.push("wymaga restartu");
  if ((host.failed_units ?? 0) > 0) powody.push(`${host.failed_units} jednostek w bledzie`);
  if (host.package_database_broken) powody.push("package database needs repair");
  if (host.identity.enrolled && host.identity.sssd_online === false) powody.push("SSSD offline");
  return powody;
}

function Kafelek({
  etykieta, wartosc, uwaga, alarm,
}: { etykieta: string; wartosc?: number; uwaga?: boolean; alarm?: boolean }) {
  const klasa = alarm ? "kafelek blad" : uwaga ? "kafelek uwaga" : "kafelek";
  return (
    <div className={klasa}>
      <div className="etykieta">{etykieta}</div>
      <div className="wartosc">{wartosc ?? "—"}</div>
    </div>
  );
}
