import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, LIST_PAGE, loadedItems } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { Breakdown, Meter, StatusBar, type WidgetTone } from "../components/widgets";
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
  by_severity?: Record<string, number>;
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

/** The fleet answer: the summary numbers over the whole visible fleet and
 *  one page of the host table. The summary does not change with the table
 *  filters - a filter changes what is listed, not how bad the fleet is. */
type View = {
  items: Item[];
  count: number;
  total: number;
  offset: number;
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

/** One CVE across the fleet. */
export type CVERow = {
  cve: string;
  severity: string;
  vendor_severity?: string;
  cvss_score?: number;
  cvss_severity?: string;
  hosts: number;
  hosts_with_vendor_fix: number;
  packages: string[];
  first_seen: string;
};

type CVEPage = { items: CVERow[]; count: number; total: number; limit: number; offset: number };

/** The coverage reasons the panel can name; unknown codes are shown as-is. */
export const COVERAGE_REASONS: Record<string, string> = {
  feed_missing: "no feed for the distribution",
  family_unsupported: "no vulnerability feed for this family",
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

/** The canonical severities the server groups by, the worst first. Every
 *  vendor has its own words for them; the server translates and keeps the
 *  vendor's word next to the rung. */
export const SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unrated"] as const;

/** The tone of a severity badge: the two top rungs are red, the middle one
 *  amber, the rest plain. An unrated finding is not harmless - it is one
 *  the vendor has not weighed - so it wears the unknown tone. */
export function severityTone(severity?: string): WidgetTone {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warn";
    case "low":
    case "negligible":
      return "neutral";
    default:
      return "unknown";
  }
}

/** The badge class for a severity: the tone, or nothing for a plain badge. */
function severityClass(severity?: string): string {
  const tone = severityTone(severity);
  return tone === "neutral" ? "badge" : `badge ${tone}`;
}

/** The filters of the two tables, as the address carries them. */
export type FleetFilters = {
  view: "hosts" | "cves";
  q: string;
  severity: string;
  fixable: boolean;
  sort: string;
};

/** The address of one page of the fleet list for the current filters.
 *
 *  Both tables page by offset: the server sorts the whole visible fleet in
 *  memory for the host table and by a grouped query for the CVE table, so a
 *  key-set cursor would buy nothing over a plain offset. */
export function fleetListAddress(filters: FleetFilters, offset: number, limit = LIST_PAGE): string {
  const params = new URLSearchParams();
  if (filters.q.trim()) params.set("q", filters.q.trim());
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.view === "cves") {
    if (filters.fixable) params.set("fixable", "true");
  } else if (filters.sort) {
    params.set("sort", filters.sort);
  }
  params.set("limit", String(limit));
  if (offset > 0) params.set("offset", String(offset));
  const path = filters.view === "cves" ? "/api/v1/vulnerabilities/cves" : "/api/v1/vulnerabilities";
  return `${path}?${params}`;
}

/** The first few package names of a CVE row and how many more there are.
 *  A kernel CVE names forty binary packages; the row shows a handful and
 *  the page shows them all. */
export function packagesPreview(packages: string[], shown = 4): { shown: string[]; more: number } {
  return { shown: packages.slice(0, shown), more: Math.max(0, packages.length - shown) };
}

/**
 * Fleet vulnerabilities.
 *
 * The screen has two numbers, not one: how many vulnerabilities and what
 * part of the fleet could be assessed at all. Without the second the first
 * is a promise, not a result - a host the feed does not cover has the same
 * zero as a clean host.
 *
 * Below the numbers the same findings are read two ways: by host, which
 * answers "which machine is in the worst shape", and by CVE, which answers
 * "which vulnerability touches the most of the fleet" - the question an
 * operator asks when a number from the news lands on the desk.
 */
export function FleetVulnerabilities() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useState<FleetFilters>({
    view: params.get("view") === "cves" ? "cves" : "hosts",
    q: params.get("q") ?? "",
    severity: params.get("severity") ?? "",
    fixable: params.get("fixable") === "true",
    sort: params.get("sort") ?? "",
  });
  const settledQuery = useDebounced(filters.q.trim());
  const change = (next: Partial<FleetFilters>) => {
    const merged = { ...filters, ...next };
    setFilters(merged);
    // The address keeps the view and the filters, so a link to "the
    // critical CVEs" opens on the critical CVEs.
    const address = new URLSearchParams();
    if (merged.view === "cves") address.set("view", "cves");
    if (merged.q) address.set("q", merged.q);
    if (merged.severity) address.set("severity", merged.severity);
    if (merged.fixable) address.set("fixable", "true");
    if (merged.sort) address.set("sort", merged.sort);
    setParams(address, { replace: true });
  };

  // The summary and the ten worst hosts come from one unfiltered read; the
  // tables have reads of their own, so a search does not move the numbers
  // above it.
  const summary = useQuery({
    queryKey: ["vulnerabilities", "fleet", "summary"],
    queryFn: () => api.get<View>("/api/v1/vulnerabilities?sort=fixable&limit=10"),
    retry: false,
  });
  const hostFilters = { ...filters, view: "hosts" as const, q: settledQuery };
  const hostTable = useInfiniteQuery({
    queryKey: ["vulnerabilities", "fleet", "hosts", settledQuery, filters.severity, filters.sort],
    queryFn: ({ pageParam }) => api.get<View>(fleetListAddress(hostFilters, pageParam)),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.offset + last.count < last.total ? last.offset + last.count : undefined),
    enabled: filters.view === "hosts",
    retry: false,
  });
  const cveFilters = { ...filters, view: "cves" as const, q: settledQuery };
  const cveTable = useInfiniteQuery({
    queryKey: ["vulnerabilities", "fleet", "cves", settledQuery, filters.severity, filters.fixable],
    queryFn: ({ pageParam }) => api.get<CVEPage>(fleetListAddress(cveFilters, pageParam, 50)),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.offset + last.count < last.total ? last.offset + last.count : undefined),
    enabled: filters.view === "cves",
    retry: false,
  });

  if (summary.error) return <ErrorBox error={summary.error} />;
  const data = summary.data;
  if (!data) return <Empty>{t("Reading assessments…")}</Empty>;

  const reason = (code: string) => (COVERAGE_REASONS[code] ? t(COVERAGE_REASONS[code]) : code);

  const fullyAssessed = data.hosts_assessed >= data.hosts_total;
  // A host the feed covers only in part - a package from outside the
  // distribution, a family without a feed - is neither fully assessed nor
  // unassessed; it is the rest of the fleet.
  const partlyAssessed = Math.max(0, data.hosts_total - data.hosts_assessed - data.hosts_without_assessment);
  // The hosts with the most open findings, the gravest first, as the
  // server sorted them: a host with a vendor fix waiting outranks one with
  // more findings and nothing to apply. A host that could not be assessed
  // is not on this list - its zero is not a result.
  const affectedHosts = data.items.filter((item) => !item.coverage_reason && item.affected > 0);
  const hostTone = (item: Item): WidgetTone => (item.affected_with_vendor_fix > 0 ? "error" : "warn");

  const hostRows = loadedItems<Item>(hostTable.data);
  const hostTotal = hostTable.data?.pages[0]?.total ?? 0;
  const cveRows = loadedItems<CVERow>(cveTable.data);
  const cveTotal = cveTable.data?.pages[0]?.total ?? 0;

  return (
    <>
      <PageHeader
        title={t("Vulnerabilities")}
        description={t("Decided by each distribution's own security tracker, because fixes are backported: a version that looks vulnerable upstream may already carry the patch. Upstream feeds can add descriptions and scores later, but they never overrule the vendor.")}
      />

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

      {/* Two bars, because they are different questions. The first says
          how much is open, by what can be done about it; the second says
          what part of the fleet could be assessed at all. Under the first
          stands how big the work is - the same CVE on twenty hosts is one
          vendor matter and twenty machines to move, and a single
          "findings" number says neither. */}
      <div className="widgets">
        <Card className="span-8" title={t("Findings")} description={t("By what the vendor offers for them.")}>
          <StatusBar segments={[
            { label: t("Vendor fix"), value: data.affected_with_vendor_fix, tone: "error" },
            { label: t("No fix"), value: data.affected_no_fix, tone: "warn" },
            { label: t("Not established"), value: data.unknown, tone: "unknown" },
          ]} />
          <p className="fp-note">
            {t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move · {hosts} hosts affected.", {
              cves: data.unique_cves, advisories: data.unique_advisories,
              packages: data.affected_package_instances, hosts: data.hosts_affected,
            })}
          </p>
        </Card>

        {/* The three segments are the whole fleet, host by host: fully
            assessed, assessed with packages the feed does not cover, and
            never assessed. The affected hosts are named under the findings;
            an affected host is also an assessed one, so it is not a fourth
            segment of the same bar. */}
        <Card
          className="span-4"
          title={t("Assessed")}
          description={t("{n} of {total} hosts fully assessed", { n: data.hosts_assessed, total: data.hosts_total })}
        >
          <StatusBar segments={[
            { label: t("Fully assessed"), value: data.hosts_assessed, tone: fullyAssessed ? "ok" : "warn" },
            { label: t("Not fully assessed"), value: partlyAssessed, tone: "warn" },
            { label: t("Never assessed"), value: data.hosts_without_assessment, tone: "unknown" },
          ]} />
        </Card>

        <Card className="span-8" title={t("Security data")} flush>
          {!data.sources.length ? (
            <Empty>{t("No feed has been fetched yet.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Provider")}</th><th className="num">{t("Advisories")}</th><th>{t("Releases")}</th><th>{t("Fetched")}</th><th>{t("State")}</th></tr>
              </thead>
              <tbody>
                {data.sources.map((source) => (
                  <tr key={source.provider}>
                    <td>{source.provider}</td>
                    <td className="num">{source.advisories}</td>
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
        </Card>

        <Card className="span-4" title={t("By host")} description={t("Hosts with open findings, the ones with a vendor fix first.")}>
          {affectedHosts.length === 0 ? (
            <p className="fp-blank">{data.hosts_assessed > 0 ? t("No assessed host has an open finding.") : t("No host has been assessed yet.")}</p>
          ) : (
            <div className="fp-links">
              <Breakdown items={affectedHosts.map((item) => ({
                label: <Link to={`/hosts/${item.host_id}/vulnerabilities`}>{item.hostname || item.host_id.slice(0, 8)}</Link>,
                value: item.affected,
                tone: hostTone(item),
              }))} />
            </div>
          )}
        </Card>

        <Card
          className="span-12"
          title={filters.view === "cves" ? t("By CVE") : t("Hosts")}
          description={filters.view === "cves"
            ? t("One row per CVE across the hosts you can see, the gravest and the most widespread first. The host count is the number of machines to move; the fix count says on how many of them the vendor has released one.")
            : undefined}
          flush
        >
          <Toolbar
            end={
              <>
                {filters.view === "cves"
                  ? cveTable.data && <span>{t("{n} CVEs", { n: cveTotal })}</span>
                  : hostTable.data && <span>{t("{n} hosts", { n: hostTotal })}</span>}
                {/* The file carries the host view: the CSV of the fleet
                    is one row per host, whatever the toggle shows. */}
                {filters.view === "hosts" && (
                  <ExportButton path="/api/v1/vulnerabilities"
                    params={new URLSearchParams(fleetListAddress(hostFilters, 0).split("?")[1])} />
                )}
              </>
            }
          >
            {/* The same findings, grouped the other way round: a toggle,
                not two pages, because the numbers above them are shared. */}
            <div className="segmented" role="group" data-testid="view-toggle">
              <button className={filters.view === "hosts" ? "active" : ""} onClick={() => change({ view: "hosts" })}>{t("By host")}</button>
              <button className={filters.view === "cves" ? "active" : ""} onClick={() => change({ view: "cves" })}>{t("By CVE")}</button>
            </div>
            <input
              placeholder={filters.view === "cves" ? t("CVE number or package name") : t("Search hostname")}
              aria-label={filters.view === "cves" ? t("CVE number or package name") : t("Search hostname")}
              value={filters.q}
              onChange={(e) => change({ q: e.target.value })}
            />
            <select value={filters.severity} onChange={(e) => change({ severity: e.target.value })} aria-label={t("Severity")}>
              <option value="">{t("any severity")}</option>
              {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
            </select>
            {filters.view === "cves" ? (
              <label className="toggle">
                <input type="checkbox" checked={filters.fixable} onChange={(e) => change({ fixable: e.target.checked })} />{" "}
                {t("vendor fix available")}
              </label>
            ) : (
              <select value={filters.sort} onChange={(e) => change({ sort: e.target.value })} aria-label={t("Sort")}>
                <option value="">{t("most open findings first")}</option>
                <option value="fixable">{t("most vendor fixes first")}</option>
                <option value="hostname">{t("by hostname")}</option>
              </select>
            )}
          </Toolbar>

          {filters.view === "cves" ? (
            cveTable.error ? (
              <ErrorBox error={cveTable.error} />
            ) : !cveTable.data ? (
              <Empty>{t("Reading assessments…")}</Empty>
            ) : !cveRows.length ? (
              <Empty>{settledQuery || filters.severity || filters.fixable ? t("No CVE matches these filters.") : t("No assessed host has an open finding.")}</Empty>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>CVE</th><th>{t("Severity")}</th><th className="num">CVSS</th>
                    <th className="num">{t("Hosts")}</th><th className="num">{t("Vendor fix")}</th>
                    <th>{t("Packages")}</th><th>{t("First seen")}</th>
                  </tr>
                </thead>
                <tbody>
                  {cveRows.map((row) => {
                    const preview = packagesPreview(row.packages);
                    return (
                      <tr key={row.cve}>
                        <td><Link className="mono" to={`/vulnerabilities/${row.cve}`}>{row.cve}</Link></td>
                        <td>
                          <span className={severityClass(row.severity)} title={row.vendor_severity}>{row.severity}</span>
                        </td>
                        {/* The upstream score stands next to the vendor's
                            rating, never instead of it. */}
                        <td className="num" title={row.cvss_severity}>{row.cvss_score === undefined ? "—" : row.cvss_score.toFixed(1)}</td>
                        <td className="num">{row.hosts}</td>
                        <td className="num">
                          {row.hosts_with_vendor_fix > 0
                            ? <span className="badge ok">{t("{n} of {total}", { n: row.hosts_with_vendor_fix, total: row.hosts })}</span>
                            : <span className="badge warn">{t("none")}</span>}
                        </td>
                        <td>
                          <span className="mono">{preview.shown.join(", ")}</span>
                          {preview.more > 0 && <span className="source"> {t("+{n} more", { n: preview.more })}</span>}
                        </td>
                        <td><Time value={row.first_seen} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )
          ) : hostTable.error ? (
            <ErrorBox error={hostTable.error} />
          ) : !hostTable.data ? (
            <Empty>{t("Reading assessments…")}</Empty>
          ) : !hostRows.length ? (
            <Empty>{settledQuery || filters.severity ? t("No host matches these filters.") : t("No host has been assessed yet.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Host")}</th><th>{t("Distribution")}</th><th className="num">{t("Open findings")}</th>
                  <th className="num">{t("Vendor fix")}</th><th className="num">{t("No fix")}</th>
                  <th className="num">{t("Not established")}</th>
                  <th title={t("The share of the installed packages the vendor's tracker could say something about.")}>{t("Coverage")}</th>
                  <th>{t("Assessed")}</th>
                </tr>
              </thead>
              <tbody>
                {hostRows.map((item) => (
                  <tr key={item.host_id}>
                    <td>
                      <Link to={`/hosts/${item.host_id}/vulnerabilities`}>
                        {item.hostname || item.host_id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="source">{item.distribution} {item.release}</td>
                    {/* The open findings by severity, the worst rung first:
                        "3 critical" says more than a sum. */}
                    <td className="num">
                      {item.affected}
                      {item.affected > 0 && item.by_severity && (
                        <div className="source">
                          {SEVERITIES.filter((severity) => (item.by_severity?.[severity] ?? 0) > 0)
                            .map((severity) => `${item.by_severity?.[severity]} ${severity}`).join(" · ")}
                        </div>
                      )}
                    </td>
                    <td className="num">
                      {item.affected_with_vendor_fix > 0
                        ? <span className="badge error">{item.affected_with_vendor_fix}</span>
                        : <span className="badge ok">0</span>}
                    </td>
                    <td className="num">{item.affected_no_fix}</td>
                    <td className="num">{item.unknown}</td>
                    <td className={item.coverage_reason ? undefined : "fp-meter-cell"} title={item.coverage_reason ? undefined : t("{percent}% of the {total} installed packages were matched against the tracker.", { percent: item.coverage_percent.toFixed(1), total: item.packages_total })}>
                      {item.coverage_reason ? (
                        <span className="badge unknown">
                          {reason(item.coverage_reason)}
                        </span>
                      ) : (
                        // Rounding to a whole number turned 99.7% into "100%":
                        // "everything checked" where dozens of packages stayed
                        // outside the assessment. The bar shows the share, the
                        // badge the exact figure.
                        <Meter
                          value={item.coverage_percent}
                          max={100}
                          tone={item.fully_assessed ? "ok" : "warn"}
                          text={
                            <span className={`badge ${item.fully_assessed ? "ok" : "warn"}`}>
                              {t("{percent}% of {total}", { percent: item.coverage_percent.toFixed(1), total: item.packages_total })}
                            </span>
                          }
                        />
                      )}
                    </td>
                    <td><Time value={item.evaluated_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {/* The next page comes on request, and the count says how much
              is left. */}
          {filters.view === "cves" && cveTable.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => cveTable.fetchNextPage()} disabled={cveTable.isFetchingNextPage}>
                {t("Load more ({n} left)", { n: cveTotal - cveRows.length })}
              </button>
            </p>
          )}
          {filters.view === "hosts" && hostTable.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => hostTable.fetchNextPage()} disabled={hostTable.isFetchingNextPage}>
                {t("Load more ({n} left)", { n: hostTotal - hostRows.length })}
              </button>
            </p>
          )}
        </Card>
      </div>
    </>
  );
}
