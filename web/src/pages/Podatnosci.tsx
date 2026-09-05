import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type Pozycja = {
  host_id: string;
  hostname?: string;
  distribution?: string;
  release?: string;
  provider?: string;
  packages_total: number;
  packages_covered: number;
  affected: number;
  affected_fixable: number;
  affected_no_fix: number;
  unknown: number;
  coverage_reason?: string;
  coverage_percent: number;
  evaluated_at?: string;
};

type Zrodlo = {
  provider: string;
  digest: string;
  advisories: number;
  releases?: string[];
  fetched_at: string;
  stale: boolean;
  error?: string;
};

type Widok = {
  items: Pozycja[];
  affected: number;
  affected_fixable: number;
  affected_no_fix: number;
  unknown: number;
  hosts_total: number;
  hosts_assessed: number;
  hosts_without_assessment: number;
  coverage_reasons: Record<string, number>;
  sources: Zrodlo[];
  max_snapshot_age_hours: number;
};

const powody: Record<string, string> = {
  feed_missing: "no feed for the distribution",
  feed_stale: "feed older than policy",
  release_unsupported: "release not covered",
  package_list_missing: "no package list yet",
  package_list_stale: "package list out of date",
  distribution_eol: "release past end of life",
};

/**
 * Podatnosci floty.
 *
 * Ekran ma dwie liczby, nie jedna: ile podatnosci i jaka czesc floty w ogole
 * dalo sie ocenic. Bez tej drugiej pierwsza jest obietnica, a nie wynikiem -
 * host, ktorego feed nie obejmuje, ma tak samo zero jak host czysty.
 */
export function PodatnosciFloty() {
  const { data, error } = useQuery({
    queryKey: ["vulnerabilities", "fleet"],
    queryFn: () => api.get<Widok>("/api/v1/vulnerabilities"),
    retry: false,
  });

  if (error) return <Blad error={error} />;
  if (!data) return <Pusto>Reading assessments…</Pusto>;

  return (
    <>
      <h1>Vulnerabilities</h1>
      <p className="podtytul">
        Decided by each distribution's own security tracker, because fixes are
        backported: a version that looks vulnerable upstream may already carry
        the patch. Upstream feeds can add descriptions and scores later, but
        they never overrule the vendor.
      </p>

      <div className="filtry">
        <span className="znacznik blad">{data.affected_fixable} fixable</span>
        <span className="znacznik uwaga">{data.affected_no_fix} no vendor fix</span>
        <span className="znacznik nieznany">{data.unknown} not established</span>
        <span className={`znacznik ${data.hosts_without_assessment ? "uwaga" : "ok"}`}>
          {data.hosts_assessed}/{data.hosts_total} hosts fully assessed
        </span>
      </div>

      {Object.keys(data.coverage_reasons ?? {}).length > 0 && (
        <p className="ostrzezenie">
          <span>
            Incomplete coverage:{" "}
            {Object.entries(data.coverage_reasons)
              .map(([kod, ile]) => `${ile} × ${powody[kod] ?? kod}`)
              .join(", ")}
            . Those hosts show zero findings because nothing could be decided,
            not because they are clean.
          </span>
        </p>
      )}

      <h2>Security data</h2>
      {!data.sources.length ? (
        <Pusto>No feed has been fetched yet.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Provider</th><th>Advisories</th><th>Releases</th><th>Fetched</th><th>State</th></tr>
          </thead>
          <tbody>
            {data.sources.map((zrodlo) => (
              <tr key={zrodlo.provider}>
                <td>{zrodlo.provider}</td>
                <td>{zrodlo.advisories}</td>
                <td className="zrodlo">{(zrodlo.releases ?? []).join(", ")}</td>
                <td><Czas wartosc={zrodlo.fetched_at} /></td>
                <td>
                  {zrodlo.error ? (
                    <span className="znacznik blad">{zrodlo.error.slice(0, 80)}</span>
                  ) : zrodlo.stale ? (
                    <span className="znacznik uwaga">
                      older than {data.max_snapshot_age_hours} h
                    </span>
                  ) : (
                    <span className="znacznik ok">fresh</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Hosts</h2>
      {!data.items.length ? (
        <Pusto>No host has been assessed yet.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th><th>Distribution</th><th>Fixable</th><th>No fix</th>
              <th>Not established</th><th>Coverage</th><th>Assessed</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((pozycja) => (
              <tr key={pozycja.host_id}>
                <td>
                  <Link to={`/hosts/${pozycja.host_id}/vulnerabilities`}>
                    {pozycja.hostname || pozycja.host_id.slice(0, 8)}
                  </Link>
                </td>
                <td className="zrodlo">{pozycja.distribution} {pozycja.release}</td>
                <td>
                  {pozycja.affected_fixable > 0
                    ? <span className="znacznik blad">{pozycja.affected_fixable}</span>
                    : <span className="znacznik ok">0</span>}
                </td>
                <td>{pozycja.affected_no_fix}</td>
                <td>{pozycja.unknown}</td>
                <td>
                  {pozycja.coverage_reason ? (
                    <span className="znacznik nieznany">
                      {powody[pozycja.coverage_reason] ?? pozycja.coverage_reason}
                    </span>
                  ) : (
                    <span className={`znacznik ${pozycja.coverage_percent >= 99 ? "ok" : "uwaga"}`}>
                      {Math.round(pozycja.coverage_percent)}% of {pozycja.packages_total}
                    </span>
                  )}
                </td>
                <td><Czas wartosc={pozycja.evaluated_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
