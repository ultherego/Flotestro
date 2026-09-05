import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type Pozycja = {
  host_id: string;
  hostname: string;
  path: string;
  subject?: string;
  issuer?: string;
  not_after?: string;
  days_to_expiry?: number;
  status: string;
  renewal: string;
  owner_service?: string;
  unavailable_reason?: string;
};

type Widok = {
  items: Pozycja[];
  counts: Record<string, number>;
  truncated: boolean;
  hosts_total: number;
  hosts_without_certificates: number;
  thresholds: { critical_days: number; warning_days: number };
};

function znacznik(stan: string, dni?: number) {
  const klasa =
    stan === "valid" ? "ok" : stan === "expired" || stan === "critical" ? "blad"
      : stan === "warning" ? "uwaga" : "nieznany";
  const opis =
    stan === "expired"
      ? dni === undefined ? "expired" : `expired ${Math.abs(dni)} d ago`
      : stan === "unknown" ? "unknown"
        : dni === undefined ? stan : `${dni} d`;
  return <span className={`znacznik ${klasa}`}>{opis}</span>;
}

/**
 * Terminy certyfikatow calej floty.
 *
 * Certyfikat wygasa cicho i zawsze w najgorszym momencie. Jedyna obrona jest
 * lista, na ktorej wszystkie terminy stoja obok siebie, posortowane od
 * najblizszego - i na ktorej widac, czy cokolwiek te certyfikaty odnowi.
 */
export function CertyfikatyFloty() {
  const { data, error } = useQuery({
    queryKey: ["certificates", "fleet"],
    queryFn: () => api.get<Widok>("/api/v1/certificates"),
  });

  if (error) return <Blad error={error} />;
  if (!data) return <Pusto>Reading certificates…</Pusto>;

  const liczby = data.counts ?? {};
  return (
    <>
      <h1>Certificates</h1>
      <p className="podtytul">
        Expiry dates from the paths the panel watches and from everything
        certmonger tracks. Warning at {data.thresholds.warning_days} days,
        urgent at {data.thresholds.critical_days}. A host that reports no
        certificate is not a host without them — it is a host nobody has
        pointed at a path yet.
      </p>

      <div className="filtry">
        <span className="znacznik blad">{liczby.expired ?? 0} expired</span>
        <span className="znacznik blad">{liczby.critical ?? 0} urgent</span>
        <span className="znacznik uwaga">{liczby.warning ?? 0} expiring</span>
        <span className="znacznik nieznany">{liczby.unknown ?? 0} unknown</span>
        <span className="znacznik ok">{liczby.valid ?? 0} valid</span>
        <span className="zrodlo">
          {data.hosts_without_certificates} of {data.hosts_total} hosts report none
        </span>
      </div>

      {!data.items.length ? (
        <Pusto>
          No host reports a certificate yet. Open a host, watch a path and scan it.
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Expires</th><th>Host</th><th>Path</th><th>Subject</th>
              <th>Issuer</th><th>Renewal</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((pozycja) => (
              <tr key={`${pozycja.host_id}-${pozycja.path}`}>
                <td>
                  {znacznik(pozycja.status, pozycja.days_to_expiry)}
                  {pozycja.not_after && (
                    <div className="zrodlo"><Czas wartosc={pozycja.not_after} /></div>
                  )}
                </td>
                <td>
                  <Link to={`/hosts/${pozycja.host_id}/certificates`}>{pozycja.hostname}</Link>
                </td>
                <td className="zrodlo">
                  {pozycja.path}
                  {pozycja.owner_service && <div>{pozycja.owner_service}</div>}
                </td>
                <td>
                  {pozycja.unavailable_reason ? (
                    <span className="znacznik nieznany">{pozycja.unavailable_reason}</span>
                  ) : (
                    pozycja.subject
                  )}
                </td>
                <td className="zrodlo">{pozycja.issuer}</td>
                <td>
                  {/* "Reczne" jest ustaleniem, "nieznane" brakiem odpowiedzi -
                      i te dwie rzeczy nie moga wygladac tak samo. */}
                  {pozycja.renewal === "tracked" ? (
                    <span className="znacznik ok">certmonger</span>
                  ) : pozycja.renewal === "manual" ? (
                    <span className="znacznik uwaga">manual</span>
                  ) : (
                    <span className="znacznik nieznany">unknown</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {data.truncated && (
        <p className="zrodlo">
          Only the closest {data.items.length} certificates are listed. The
          counts above cover all of them.
        </p>
      )}
    </>
  );
}
