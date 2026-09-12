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
  // Os waznosci: ile certyfikatow konczy sie w ktorym oknie czasu.
  timeline?: { reason: string; count: number }[];
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

      <OsWaznosci os={data.timeline ?? []} />

      <Zaufanie />

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

type WidokZaufania = {
  items: {
    fingerprint_sha256?: string;
    subject?: string;
    anchor_id?: string;
    not_after?: string;
    hosts: number;
    sample?: string[];
    unavailable_reason?: string;
  }[];
  hosts_total: number;
  hosts_unknown: number;
  hosts_without_trust_store?: { reason: string; count: number }[];
};

/**
 * Urzedy, ktorym ufa flota.
 *
 * To jest ekran rotacji: w jej trakcie czesc hostow ufa staremu i nowemu
 * urzedowi naraz, i dopiero ten widok mowi, czy mozna juz wycofac stary.
 * Pokazujemy wylacznie kotwice zalozone przez panel - magazyn ma setki
 * urzedow dystrybucji i one nie sa tu zadna informacja.
 */
function Zaufanie() {
  const { data } = useQuery({
    queryKey: ["certificates", "trust"],
    queryFn: () => api.get<WidokZaufania>("/api/v1/certificates/trust"),
  });
  if (!data) return null;
  const bezMagazynu = data.hosts_without_trust_store ?? [];
  return (
    <section style={{ marginTop: 16 }}>
      <h2>Trusted authorities</h2>
      <p className="podtytul">
        Anchors the panel put on hosts. During a rotation a host trusts both the
        old and the new authority; the old one may only be withdrawn once nothing
        signs with it any more.
      </p>
      {!data.items.length ? (
        <Pusto>No panel-managed authority on any host.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Authority</th><th>Hosts</th><th>Valid until</th><th>Fingerprint</th></tr>
          </thead>
          <tbody>
            {data.items.map((kotwica) => (
              <tr key={(kotwica.fingerprint_sha256 || kotwica.anchor_id) ?? ""}>
                <td>
                  {kotwica.subject || kotwica.anchor_id || "—"}
                  {kotwica.unavailable_reason && (
                    <div className="zrodlo">{kotwica.unavailable_reason}</div>
                  )}
                </td>
                <td>
                  {kotwica.hosts} of {data.hosts_total}
                  <div className="zrodlo">{(kotwica.sample ?? []).join(", ")}</div>
                </td>
                <td>{kotwica.not_after ? <Czas wartosc={kotwica.not_after} /> : "—"}</td>
                <td className="zrodlo">{(kotwica.fingerprint_sha256 ?? "").slice(0, 16) || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="zrodlo">
        {data.hosts_unknown} hosts have not reported a trust store yet
        {bezMagazynu.map((grupa) => `; ${grupa.count}: ${grupa.reason}`).join("")}
      </div>
    </section>
  );
}

/**
 * Os waznosci certyfikatow floty.
 *
 * Lista posortowana po terminie mowi, co pali sie teraz. Os mowi, kiedy
 * bedzie nastepna fala - a to ona decyduje, czy rotacje planuje sie na ten
 * tydzien, czy na kwartal.
 */
function OsWaznosci({ os }: { os: { reason: string; count: number }[] }) {
  if (!os.length) return null;
  const razem = os.reduce((suma, okno) => suma + okno.count, 0);
  if (razem === 0) return null;
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 12 }}>
      {os.map((okno) => (
        <div key={okno.reason}>
          <strong>{okno.count}</strong>
          <div className="zrodlo">{okno.reason}</div>
        </div>
      ))}
    </div>
  );
}
