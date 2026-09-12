import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type Pozycja = {
  host_id: string;
  hostname: string;
  definition: string;
  tool: string;
  repository?: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  unverified: boolean;
  last_restore_at?: string;
};

type Widok = {
  items: Pozycja[];
  counts: Record<string, number>;
  unverified: number;
  never_restored?: number;
  hosts_total: number;
  thresholds: { warning_hours: number; critical_hours: number; verification_days: number };
  repositories?: Repozytorium[];
};

type Repozytorium = {
  repository: string;
  hosts: number;
  unverified: number;
  oldest_age_hours?: number;
  budget_key: string;
  capacity?: number;
  used?: number;
  claimants?: number;
};

function znacznik(stan: string, wiek?: number) {
  const klasa =
    stan === "ok" ? "ok" : stan === "warning" ? "uwaga" : stan === "unknown" ? "nieznany" : "blad";
  const opis =
    stan === "never"
      ? "no backup"
      : wiek === undefined
        ? stan
        : wiek < 48
          ? `${Math.round(wiek)} h`
          : `${Math.round(wiek / 24)} d`;
  return <span className={`znacznik ${klasa}`}>{opis}</span>;
}

/**
 * Kopie zapasowe floty.
 *
 * Backup psuje sie cicho: nikt nie zauwaza, ze od trzech tygodni nie ma nowej
 * kopii, dopoki nie trzeba jej odtworzyc. Dlatego widok floty jest tu trybem
 * podstawowym, a najgorsze wiersze stoja na gorze.
 */
export function KopieFloty() {
  const { data, error } = useQuery({
    queryKey: ["backups", "fleet"],
    queryFn: () => api.get<Widok>("/api/v1/backups"),
  });

  if (error) return <Blad error={error} />;
  if (!data) return <Pusto>Reading backup state…</Pusto>;
  const liczby = data.counts ?? {};

  return (
    <>
      <h1>Backups</h1>
      <p className="podtytul">
        What is copied, where to and how old the newest copy is. Warning after{" "}
        {data.thresholds.warning_hours} h, urgent after {data.thresholds.critical_hours} h.
        A copy nobody has ever read back is a promise, not a safeguard — that is
        what the verification column says, with a {data.thresholds.verification_days}-day limit.
      </p>

      <div className="filtry">
        <span className="znacznik blad">{liczby.never ?? 0} never ran</span>
        <span className="znacznik blad">{liczby.critical ?? 0} stale</span>
        <span className="znacznik uwaga">{liczby.warning ?? 0} ageing</span>
        <span className="znacznik ok">{liczby.ok ?? 0} fresh</span>
        <span className="znacznik uwaga">{data.unverified} unverified</span>
        {/* Kopia, ktorej nikt nigdy nie odtworzyl, jest nadzieja, a nie
            kopia. Panel nie zmusza do proby - ma powiedziec, ze jej nie bylo. */}
        <span className="znacznik nieznany">{data.never_restored ?? 0} never restored</span>
        <span className="zrodlo">{data.hosts_total} hosts visible</span>
      </div>

      <Repozytoria repozytoria={data.repositories ?? []} />

      {!data.items.length ? (
        <Pusto>
          No host has a backup definition yet. Open a host and describe what to
          copy, where to and how long it stays.
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Age</th><th>Host</th><th>Definition</th><th>Tool</th>
              <th>Destination</th><th>Verified</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((pozycja) => (
              <tr key={`${pozycja.host_id}-${pozycja.definition}`}>
                <td>
                  {znacznik(pozycja.status, pozycja.age_hours)}
                  {pozycja.last_success_at && (
                    <div className="zrodlo"><Czas wartosc={pozycja.last_success_at} /></div>
                  )}
                </td>
                <td>
                  <Link to={`/hosts/${pozycja.host_id}/backups`}>{pozycja.hostname}</Link>
                </td>
                <td>{pozycja.definition}</td>
                <td className="zrodlo">{pozycja.tool}</td>
                <td className="zrodlo">{pozycja.repository}</td>
                <td>
                  {pozycja.unverified ? (
                    <span className="znacznik uwaga">not verified</span>
                  ) : (
                    <span className="znacznik ok">verified</span>
                  )}
                  <div className="zrodlo">
                    {pozycja.last_restore_at ? (
                      <>restored <Czas wartosc={pozycja.last_restore_at} /></>
                    ) : (
                      "never restored"
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/**
 * Backendy, do ktorych pisze flota.
 *
 * Lista kopii mowi, ktory host ma stara kopie. Nie mowi, ktory backend jest
 * waskim gardlem - a to on decyduje, ile kopii idzie naraz. Pojemnosc
 * nieustawiona jest tu brakiem polityki, a nie zerem: wtedy nic nie
 * ogranicza rownoleglosci i lepiej, zeby to bylo widac.
 */
function Repozytoria({ repozytoria }: { repozytoria: Repozytorium[] }) {
  if (!repozytoria.length) return null;
  return (
    <section style={{ marginTop: 16 }}>
      <h2>Repositories</h2>
      <table>
        <thead>
          <tr><th>Repository</th><th>Hosts</th><th>Oldest backup</th><th>Parallel writes</th></tr>
        </thead>
        <tbody>
          {repozytoria.map((pozycja) => (
            <tr key={pozycja.repository}>
              <td>
                {pozycja.repository}
                <div className="zrodlo">{pozycja.budget_key}</div>
              </td>
              <td>
                {pozycja.hosts}
                {pozycja.unverified > 0 && (
                  <div className="zrodlo">{pozycja.unverified} unverified</div>
                )}
              </td>
              <td>
                {pozycja.oldest_age_hours === undefined
                  ? "—"
                  : `${Math.round(pozycja.oldest_age_hours)} h`}
              </td>
              <td>
                {pozycja.capacity === undefined ? (
                  <span className="znacznik nieznany">no limit set</span>
                ) : (
                  <>
                    {pozycja.used ?? 0} / {pozycja.capacity}
                    {(pozycja.claimants ?? 0) > 0 && (
                      <div className="zrodlo">{pozycja.claimants} campaigns want it</div>
                    )}
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
