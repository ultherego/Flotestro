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
      <h1>Pulpit floty</h1>
      <p className="podtytul">Tylko to, co wymaga decyzji.</p>

      <div className="kafelki">
        <Kafelek etykieta="Hosty" wartosc={s?.hosts} />
        <Kafelek etykieta="Online" wartosc={s?.online} />
        <Kafelek etykieta="Offline" wartosc={s?.offline} alarm={(s?.offline ?? 0) > 0} />
        <Kafelek etykieta="Aktywne sesje" wartosc={s?.active_sessions} />
        <Kafelek etykieta="Wymaga restartu" wartosc={s?.reboot_required} uwaga={(s?.reboot_required ?? 0) > 0} />
        <Kafelek etykieta="Z jednostkami w bledzie" wartosc={s?.with_failed_units} uwaga={(s?.with_failed_units ?? 0) > 0} />
        <Kafelek etykieta="Aktualizacje bezpieczenstwa" wartosc={s?.hosts_with_security_updates} uwaga={(s?.hosts_with_security_updates ?? 0) > 0} />
        <Kafelek etykieta="Kwarantanna" wartosc={s?.quarantined_hosts} alarm={(s?.quarantined_hosts ?? 0) > 0} />
      </div>

      <h2>Hosty wymagajace uwagi</h2>
      {wymagajaUwagi.length === 0 ? (
        <Pusto>Zaden host nie wymaga uwagi.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th><th>Stan</th><th>Powod</th><th>Ostatnio widziany</th>
            </tr>
          </thead>
          <tbody>
            {wymagajaUwagi.map((host) => (
              <tr key={host.id}>
                <td><Link to={`/hosty/${host.id}`}>{host.hostname}</Link></td>
                <td><span className="znacznik">{host.connection_state}</span></td>
                <td>{powodyUwagi(host).join(", ")}</td>
                <td><Czas wartosc={host.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Kampanie w toku</h2>
      {aktywneKampanie.length === 0 ? (
        <Pusto>Brak kampanii wymagajacych uwagi.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Nazwa</th><th>Stan</th><th>Operacja</th><th>Powod wstrzymania</th></tr>
          </thead>
          <tbody>
            {aktywneKampanie.map((kampania) => (
              <tr key={kampania.id}>
                <td><Link to={`/kampanie/${kampania.id}`}>{kampania.name}</Link></td>
                <td><StanZadania stan={kampania.state} /></td>
                <td>{kampania.action_type}</td>
                <td>{kampania.pause_reason || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Ostatnie odmowy dostepu</h2>
      {odmowy.length === 0 ? (
        <Pusto>Brak odmow w ostatnich zdarzeniach.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Czas</th><th>Kto</th><th>Operacja</th><th>Powod</th></tr></thead>
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
  if (host.connection_state !== "online") powody.push("brak lacznosci");
  if (host.reboot_required) powody.push("wymaga restartu");
  if ((host.failed_units ?? 0) > 0) powody.push(`${host.failed_units} jednostek w bledzie`);
  if (host.package_database_broken) powody.push("uszkodzona baza pakietow");
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
