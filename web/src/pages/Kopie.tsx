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
};

type Widok = {
  items: Pozycja[];
  counts: Record<string, number>;
  unverified: number;
  hosts_total: number;
  thresholds: { warning_hours: number; critical_hours: number; verification_days: number };
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
        <span className="zrodlo">{data.hosts_total} hosts visible</span>
      </div>

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
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
