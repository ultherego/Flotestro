import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type Item = {
  host_id: string;
  hostname?: string;
  distribution?: string;
  release?: string;
  provider?: string;
  packages_total: number;
  packages_covered: number;
  affected: number;
  affected_with_vendor_fix: number;
  affected_no_fix: number;
  unknown: number;
  affected_packages: number;
  unique_advisories: number;
  unique_cves: number;
  coverage_reason?: string;
  advisories_reason?: string;
  coverage_percent: number;
  fully_assessed: boolean;
  evaluated_at?: string;
};

type Source = {
  provider: string;
  digest: string;
  advisories: number;
  releases?: string[];
  fetched_at: string;
  stale: boolean;
  error?: string;
};

type View = {
  items: Item[];
  affected: number;
  affected_with_vendor_fix: number;
  affected_no_fix: number;
  unknown: number;
  unique_cves: number;
  unique_advisories: number;
  affected_package_instances: number;
  hosts_affected: number;
  hosts_total: number;
  hosts_assessed: number;
  hosts_without_assessment: number;
  coverage_reasons: Record<string, number>;
  sources: Source[];
  max_snapshot_age_hours: number;
};

/** The coverage reasons the panel can name; unknown codes are shown as-is. */
export const COVERAGE_REASONS: Record<string, string> = {
  feed_missing: "no feed for the distribution",
  feed_stale: "feed older than policy",
  release_unsupported: "release not covered",
  package_list_missing: "no package list yet",
  package_list_stale: "package list out of date",
  distribution_eol: "release past end of life",
  package_origin_unknown: "packages from outside the distribution",
  host_advisories_missing: "repository metadata not read yet",
  host_advisories_unreadable: "repository metadata could not be read",
  host_advisories_stale: "vendor advisories past the refresh policy",
};

/**
 * Fleet vulnerabilities.
 *
 * The screen has two numbers, not one: how many vulnerabilities and what
 * part of the fleet could be assessed at all. Without the second the first
 * is a promise, not a result - a host the feed does not cover has the same
 * zero as a clean host.
 */
export function FleetVulnerabilities() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["vulnerabilities", "fleet"],
    queryFn: () => api.get<View>("/api/v1/vulnerabilities"),
    retry: false,
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Reading assessments…")}</Empty>;

  const reason = (code: string) => (COVERAGE_REASONS[code] ? t(COVERAGE_REASONS[code]) : code);

  return (
    <>
      <h1>{t("Vulnerabilities")}</h1>
      <p className="subtitle">
        {t("Decided by each distribution's own security tracker, because fixes are backported: a version that looks vulnerable upstream may already carry the patch. Upstream feeds can add descriptions and scores later, but they never overrule the vendor.")}
      </p>

      <div className="filters">
        <span className="badge error">{t("{n} with a vendor fix", { n: data.affected_with_vendor_fix })}</span>
        <span className="badge warn">{t("{n} no vendor fix", { n: data.affected_no_fix })}</span>
        <span className="badge unknown">{t("{n} not established", { n: data.unknown })}</span>
        <span className={`badge ${data.hosts_assessed < data.hosts_total ? "warn" : "ok"}`}>
          {t("{assessed}/{total} hosts fully assessed", { assessed: data.hosts_assessed, total: data.hosts_total })}
        </span>
      </div>
      {/* Four numbers, because they are four different questions. The same
          CVE on twenty hosts is one vendor matter and twenty machines to
          move - a single "findings" number says neither. */}
      <p className="source">
        {t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move · {hosts} hosts affected.", {
          cves: data.unique_cves, advisories: data.unique_advisories,
          packages: data.affected_package_instances, hosts: data.hosts_affected,
        })}
      </p>

      {Object.keys(data.coverage_reasons ?? {}).length > 0 && (
        <p className="warning">
          <span>
            {t("Incomplete coverage: {reasons}. Those hosts show zero findings because nothing could be decided, not because they are clean.", {
              reasons: Object.entries(data.coverage_reasons)
                .map(([code, count]) => `${count} × ${reason(code)}`)
                .join(", "),
            })}
          </span>
        </p>
      )}

      <h2>{t("Security data")}</h2>
      {!data.sources.length ? (
        <Empty>{t("No feed has been fetched yet.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Provider")}</th><th>{t("Advisories")}</th><th>{t("Releases")}</th><th>{t("Fetched")}</th><th>{t("State")}</th></tr>
          </thead>
          <tbody>
            {data.sources.map((source) => (
              <tr key={source.provider}>
                <td>{source.provider}</td>
                <td>{source.advisories}</td>
                <td className="source">{(source.releases ?? []).join(", ")}</td>
                <td><Time value={source.fetched_at} /></td>
                <td>
                  {source.error ? (
                    <span className="badge error">{source.error.slice(0, 80)}</span>
                  ) : source.stale ? (
                    <span className="badge warn">
                      {t("older than {n} h", { n: data.max_snapshot_age_hours })}
                    </span>
                  ) : (
                    <span className="badge ok">{t("fresh")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Hosts")}</h2>
      {!data.items.length ? (
        <Empty>{t("No host has been assessed yet.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Host")}</th><th>{t("Distribution")}</th><th>{t("Vendor fix")}</th><th>{t("No fix")}</th>
              <th>{t("Not established")}</th><th>{t("Coverage")}</th><th>{t("Assessed")}</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item) => (
              <tr key={item.host_id}>
                <td>
                  <Link to={`/hosts/${item.host_id}/vulnerabilities`}>
                    {item.hostname || item.host_id.slice(0, 8)}
                  </Link>
                </td>
                <td className="source">{item.distribution} {item.release}</td>
                <td>
                  {item.affected_with_vendor_fix > 0
                    ? <span className="badge error">{item.affected_with_vendor_fix}</span>
                    : <span className="badge ok">0</span>}
                </td>
                <td>{item.affected_no_fix}</td>
                <td>{item.unknown}</td>
                <td>
                  {item.coverage_reason ? (
                    <span className="badge unknown">
                      {reason(item.coverage_reason)}
                    </span>
                  ) : (
                    // Rounding to a whole number turned 99.7% into "100%":
                    // "everything checked" where dozens of packages stayed
                    // outside the assessment.
                    <span className={`badge ${item.fully_assessed ? "ok" : "warn"}`}>
                      {t("{percent}% of {total}", { percent: item.coverage_percent.toFixed(1), total: item.packages_total })}
                    </span>
                  )}
                </td>
                <td><Time value={item.evaluated_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
