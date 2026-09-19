import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { Breakdown, Meter } from "../../components/widgets";
import {
  Fact, Facts, Foot, Message, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere, useHost,
} from "./shared";
import { bulkPrefill } from "../Bulk";
import { useT } from "../../i18n";

type Finding = {
  provider: string;
  advisory_id: string;
  cve_ids?: string[];
  source_package?: string;
  binary_package?: string;
  architecture?: string;
  installed_version?: string;
  comparison_version?: string;
  comparison_basis?: string;
  fixed_version?: string;
  state: string;
  reason_code?: string;
  vendor_fix: string;
  repository_candidate: string;
  transaction: string;
  package_origin?: string;
  vendor_severity?: string;
  comparator_version?: string;
  evaluated_at: string;
};

type AssessmentState = {
  distribution?: string;
  release?: string;
  provider?: string;
  snapshot_digest?: string;
  inventory_digest?: string;
  advisory_digest?: string;
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
  evaluated_at?: string;
};

type PackageListState = {
  digest?: string;
  package_count: number;
  collected_at?: string;
  unavailable_reason?: string;
};

type AdvisoryState = {
  digest?: string;
  advisory_count: number;
  collected_at?: string;
  unavailable_reason?: string;
};

type Snapshot = {
  provider: string;
  digest: string;
  advisory_count: number;
  releases?: string[];
  fetched_at: string;
  error?: string;
};

/** Enrichment: the CVSS score and the description from the upstream database.
 *
 *  It stands next to the finding, not inside it. Whether the package is
 *  vulnerable and what closes it is said only by the distribution vendor -
 *  this is just the answer to "how dangerous is the vulnerability itself".
 *  A missing entry is normal. */
type CVEDetails = {
  cve: string;
  source: string;
  cvss_score?: number;
  cvss_severity?: string;
  cvss_vector?: string;
  cvss_version?: string;
  summary?: string;
};

type Report = {
  host_id: string;
  state: AssessmentState;
  findings: Finding[];
  package_state: PackageListState;
  advisory_state: AdvisoryState;
  snapshot?: Snapshot;
  snapshot_stale: boolean;
  coverage_percent: number;
  fully_assessed: boolean;
  cve_details?: Record<string, CVEDetails>;
};

/** The highest CVSS score among the CVEs of one finding.
 *
 *  One finding sometimes carries several CVEs, and the most dangerous of
 *  them decides how urgent the matter is. */
function highestScore(
  finding: Finding,
  details?: Record<string, CVEDetails>,
): CVEDetails | undefined {
  if (!details) return undefined;
  let best: CVEDetails | undefined;
  for (const id of finding.cve_ids ?? []) {
    const entry = details[id];
    if (entry?.cvss_score === undefined) continue;
    if (best?.cvss_score === undefined || entry.cvss_score > best.cvss_score) {
      best = entry;
    }
  }
  return best;
}

/** How many findings the table shows before asking; the page grows by
 *  this much per click. The counts above the table cover every finding
 *  either way. */
export const FINDINGS_PAGE = 300;

/** The name the operator sees on the host: the binary package, or the
 *  source one where the vendor names no binary. */
function packageName(finding: Pick<Finding, "binary_package" | "source_package">): string {
  return finding.binary_package || finding.source_package || "";
}

/** Whether a finding matches the search: a CVE number, an advisory or a
 *  package name, by prefix and case-insensitively. */
export function findingMatches(finding: Pick<Finding, "advisory_id" | "cve_ids" | "binary_package" | "source_package">, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const candidates = [finding.advisory_id, finding.binary_package ?? "", finding.source_package ?? "", ...(finding.cve_ids ?? [])];
  return candidates.some((candidate) => candidate.toLowerCase().startsWith(needle));
}

/** The canonical rung of a vendor severity, so one filter fits every
 *  vendor's words: Red Hat's "important" is high and its "moderate" is
 *  medium. An unrated finding is one the vendor has not weighed. */
export function severityRung(severity?: string): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical": return "critical";
    case "high": case "important": return "high";
    case "medium": case "moderate": return "medium";
    case "low": return "low";
    case "negligible": case "unimportant": return "negligible";
    default: return "unrated";
  }
}

/**
 * The address of the Bulk workspace with a package upgrade of this host
 * written in: one package from a finding's row, or every package with a
 * vendor fix from "Patch all fixable".
 */
export function patchAddress(host: { id: string; hostname?: string }, findings: Pick<Finding, "state" | "vendor_fix" | "binary_package" | "source_package">[]): string | null {
  const packages: string[] = [];
  for (const finding of findings) {
    if (finding.state !== "affected" || finding.vendor_fix !== "known") continue;
    const name = packageName(finding);
    if (name && !packages.includes(name)) packages.push(name);
  }
  if (packages.length === 0) return null;
  const label = host.hostname || host.id.slice(0, 8);
  const name = packages.length === 1 ? `Patch ${packages[0]} on ${label}` : `Patch ${packages.length} packages on ${label}`;
  return bulkPrefill("packages.upgrade", name, { package_upgrade: { packages: packages.sort() } }, undefined, [host.id]);
}

/** The reasons an assessment is incomplete - in the operator's language, not codes. */
const REASONS: Record<string, string> = {
  feed_missing: "no security feed for this distribution",
  family_unsupported: "no vulnerability feed for this family",
  feed_stale: "the feed is older than the policy allows",
  release_unsupported: "this release is not covered by the feed",
  package_origin_unknown: "the package does not come from the distribution",
  source_package_unknown: "the source package is unknown",
  vendor_investigating: "the vendor has not decided yet",
  version_unparseable: "the version cannot be compared",
  distribution_eol: "this release is past end of life",
  package_list_missing: "the panel has not collected the package list yet",
  package_list_stale: "the package list is older than what the host reports",
  host_advisories_missing: "the panel has not read this host's repository metadata yet",
  host_advisories_unreadable: "this host's repository metadata could not be read",
  host_advisories_stale: "the vendor advisories are older than the refresh policy",
};

function SeverityBadge({ severity }: { severity?: string }) {
  const t = useT();
  const cls =
    severity === "critical" ? "error" : severity === "high" ? "error"
      : severity === "medium" ? "warn" : severity === "low" || severity === "unimportant" ? "" : "unknown";
  return <span className={`badge ${cls}`}>{severity || t("unrated")}</span>;
}

/**
 * The host's vulnerabilities.
 */
export function Vulnerabilities() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<"fixable" | "no-fix" | "unknown">("fixable");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [shown, setShown] = useState(FINDINGS_PAGE);
  const [message, setMessage] = useState("");

  const report = useQuery({
    queryKey: ["vulnerabilities", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/vulnerabilities`),
    retry: false,
  });

  const reread = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.list", payload: {},
      }),
    onSuccess: (job) => {
      setMessage(t("Job {id} reads the package list; the assessment follows.", { id: job.id.slice(0, 8) }));
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const reason = (code?: string) => (code ? (REASONS[code] ? t(REASONS[code]) : code) : "");

  if (report.error) return <ErrorBox error={report.error} />;
  const data = report.data;
  const state = data?.state;
  const findings = data?.findings ?? [];

  // The affected findings by the vendor's severity and by package.
  const assessed = !!data && !!state && (state.packages_covered > 0 || !state.coverage_reason);
  const affected = assessed ? findings.filter((finding) => finding.state === "affected") : undefined;
  const severities = ["critical", "high", "medium", "low"];
  const packages = Object.entries((affected ?? []).reduce<Record<string, number>>((acc, finding) => {
    const name = finding.binary_package || finding.source_package || "?";
    acc[name] = (acc[name] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const coverage = data?.coverage_percent;

  const visible = findings.filter((finding) => {
    if (!findingMatches(finding, search)) return false;
    if (severity && severityRung(finding.vendor_severity) !== severity) return false;
    if (filter === "unknown") return finding.state === "unknown";
    if (filter === "no-fix") return finding.state === "affected" && !finding.fixed_version;
    return finding.state === "affected" && !!finding.fixed_version;
  });
  const narrowed = (next: () => void) => {
    // A new search starts the page over: the rows the operator loaded
    // for the previous one are not the rows of this one.
    setShown(FINDINGS_PAGE);
    next();
  };
  const patchAll = patchAddress(host, findings);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Vulnerabilities")}
        description={t("What the distribution's own security tracker says about the packages on this host. Fixes are backported, so upstream version ranges cannot answer this question — only the vendor can. Where the vendor says nothing, the panel says \"not known\", never \"clean\".")}
        actions={
          <>
            {/* The order goes through the Bulk workspace: a package upgrade
                is planned on the host and approved there, and the panel
                never installs anything from a tab. */}
            {patchAll ? (
              <Link className="button" to={patchAll}>{t("Patch all fixable")}</Link>
            ) : (
              <button
                disabled
                title={assessed
                  ? t("No finding on this host has a vendor fix to install.")
                  : t("Nothing was assessed on this host yet, so there is nothing to patch from here.")}
              >
                {t("Patch all fixable")}
              </button>
            )}
            <button disabled={reread.isPending || host.connection_state !== "online"}
                    onClick={() => reread.mutate()}>
              {t("Re-read packages")}
            </button>
          </>
        }
      />
      <p className="hm-freshness">
        <span>
          {!data
            ? t("Loading…")
            : !assessed
              ? t("Not assessed: no count here is known until a feed covers this host.")
              : t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move. One advisory carries several CVEs and touches several packages, so these never add up — and each answers a different question.", {
                  cves: state?.unique_cves ?? 0, advisories: state?.unique_advisories ?? 0, packages: state?.affected_packages ?? 0,
                })}
        </span>
      </p>
      <Message text={message} />

      {state?.coverage_reason && (
        <p className="warning">
          <span>
            {t("This assessment is incomplete: {reason}. Zero findings here does not mean the host is clean.", { reason: reason(state.coverage_reason) })}
          </span>
        </p>
      )}
      {data?.snapshot_stale && data.snapshot && (
        <p className="warning">
          <span>
            {t("The security data was last fetched")} <Time value={data.snapshot.fetched_at} /> — {t("older than the policy allows. The assessment still uses it, because yesterday's data beats none.")}
          </span>
        </p>
      )}

      <Widgets>
      {/* The finding counts stand next to the coverage, because without it
          they mean nothing: a host the feed does not cover and a host
          without vulnerabilities both show zero. */}
      <Summary
        title={t("Affected packages by severity")}
        description={t("As the distribution vendor rates them; a package without a rating is unrated, not harmless.")}
        span={8}
        segments={[
          ...severities.map((severity) => ({
            label: severity,
            value: countWhere(affected, (f) => f.vendor_severity === severity),
            tone: severity === "critical" || severity === "high" ? "error" as const : severity === "medium" ? "warn" as const : "neutral" as const,
          })),
          { label: t("unrated"), value: countWhere(affected, (f) => !severities.includes(f.vendor_severity ?? "")), tone: "unknown" },
          { label: t("not established"), value: assessed ? state?.unknown : undefined, tone: "unknown" },
        ]}
      />
      <Section title={t("Coverage")} span={4} flush>
        <Facts>
          {/* Coverage rounded to a whole number turned 99.7% into "100%" -
              "everything checked" where dozens of packages stayed outside
              the assessment. A complete assessment has its own explicit
              answer here. */}
          <Fact label={t("Coverage")} wide>
            {coverage === undefined ? "—" : (
              <Meter
                value={coverage}
                max={100}
                tone={data?.fully_assessed ? "ok" : "warn"}
                text={t("{percent}% of packages covered", { percent: coverage.toFixed(1) })}
              />
            )}
          </Fact>
          <Fact label={t("By vendor fix")} wide>
            {!state ? "—" : !assessed ? (
              <span className="source">{t("nothing assessed")}</span>
            ) : (
              <Breakdown
                items={[
                  { label: t("With a vendor fix"), value: state.affected_with_vendor_fix, tone: "error" },
                  { label: t("No fix from vendor"), value: state.affected_no_fix, tone: "warn" },
                  { label: t("Not established"), value: state.unknown, tone: "unknown" },
                ]}
              />
            )}
          </Fact>
        </Facts>
      </Section>

      <Section
        title={t("Findings")}
        count={assessed ? visible.length : undefined}
        span={12}
        tools={
          <span className="hm-choices">
            <input
              placeholder={t("CVE, advisory or package")}
              value={search}
              onChange={(e) => narrowed(() => setSearch(e.target.value))}
            />
            <select value={severity} onChange={(e) => narrowed(() => setSeverity(e.target.value))}>
              <option value="">{t("any severity")}</option>
              {["critical", "high", "medium", "low", "negligible", "unrated"].map((rung) => (
                <option key={rung} value={rung}>{t(rung)}</option>
              ))}
            </select>
            {(["fixable", "no-fix", "unknown"] as const).map((key) => (
              <button key={key} className={filter === key ? "" : "secondary"} onClick={() => narrowed(() => setFilter(key))}>
                {key === "fixable" ? t("Fixable") : key === "no-fix" ? t("No fix") : t("Not established")}
              </button>
            ))}
          </span>
        }
        flush
      >
        {!visible.length ? (
          <Empty>
            {data && !assessed
              ? t("Nothing was assessed: {reason}. The list is empty because nothing was checked, not because nothing was found.", { reason: reason(state?.coverage_reason) })
              : search.trim() || severity
              ? t("No finding matches these filters.")
              : filter === "fixable"
              ? t("Nothing here can be closed by installing an update.")
              : filter === "no-fix"
                ? t("The vendor has published a fix for everything it knows about here.")
                : t("Everything on this host could be decided one way or the other.")}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Severity")}</th><th className="hm-num">CVSS</th><th>{t("Advisory")}</th><th>{t("Package")}</th>
                <th>{t("Installed")}</th><th>{t("Compared")}</th><th>{t("Fixed in")}</th>
                <th>{t("Vendor fix")}</th><th>{t("In repositories")}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {visible.slice(0, shown).map((finding, index) => (
                <tr key={`${finding.advisory_id}-${finding.binary_package}-${finding.installed_version}-${index}`}>
                  <td><SeverityBadge severity={finding.vendor_severity} /></td>
                  {/* The upstream score stands next to the vendor severity,
                      not instead of it: the vendor knows its distribution,
                      CVSS speaks about the vulnerability itself. When there
                      is no enrichment the column is empty and the assessment
                      does not change. */}
                  <td className="hm-num source" title={highestScore(finding, data?.cve_details)?.cvss_vector}>
                    {highestScore(finding, data?.cve_details)?.cvss_score?.toFixed(1) ?? "—"}
                  </td>
                  <td>
                    <span className="hm-mono hm-primary">{finding.advisory_id}</span>
                    {/* Every CVE leads to its fleet page: the same number
                        on twenty hosts is one matter, and that page names
                        the twenty. */}
                    {finding.cve_ids?.length ? (
                      <div className="source hm-mono">
                        {finding.cve_ids.map((id, position) => (
                          <span key={id}>{position > 0 && ", "}<Link to={`/vulnerabilities/${id}`}>{id}</Link></span>
                        ))}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <span className="hm-mono">{finding.binary_package}</span>
                    {finding.source_package && finding.source_package !== finding.binary_package && (
                      <div className="source">{t("source")}: {finding.source_package}</div>
                    )}
                  </td>
                  <td className="source hm-mono">{finding.installed_version}</td>
                  {/* Debian decides by source package, and the binary version
                      is sometimes from another numbering. We show both so it
                      is visible what was really compared. */}
                  <td className="source hm-mono">
                    {finding.comparison_version || "—"}
                    {finding.comparison_basis && (
                      <div className="source">{finding.comparison_basis}</div>
                    )}
                  </td>
                  <td className="source hm-mono">
                    {finding.fixed_version || <span className="badge warn">{t("no fix")}</span>}
                  </td>
                  <td>
                    {finding.state === "unknown" ? (
                      <span className="badge unknown">{reason(finding.reason_code)}</span>
                    ) : finding.vendor_fix === "known" ? (
                      <span className="badge ok">{t("published")}</span>
                    ) : finding.vendor_fix === "unavailable" ? (
                      <span className="badge warn">{t("none")}</span>
                    ) : (
                      <span className="badge unknown">{t("not known")}</span>
                    )}
                  </td>
                  <td>
                    {/* The third axis - whether the transaction goes through -
                        belongs to the package plan, so the panel does not
                        promise it here. */}
                    {finding.repository_candidate === "visible" ? (
                      <span className="badge ok">{t("visible here")}</span>
                    ) : finding.repository_candidate === "absent" ? (
                      <span className="badge warn">{t("not offered")}</span>
                    ) : (
                      <span className="badge">{t("plan an update to find out")}</span>
                    )}
                  </td>
                  <td>
                    {(() => {
                      const patch = patchAddress(host, [finding]);
                      return patch ? <Link className="button" to={patch}>{t("Patch")}</Link> : null;
                    })()}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {visible.length > shown && (
          <Foot>
            <span>{t("Showing the first {shown} of {n}. The counts above cover all of them.", { shown, n: visible.length })}</span>
            <button className="secondary" onClick={() => setShown((previous) => previous + FINDINGS_PAGE)}>
              {t("Load more ({n} left)", { n: visible.length - shown })}
            </button>
          </Foot>
        )}
      </Section>

      <Section title={t("Most affected packages")} span={4} description={t("Findings per package; one advisory can touch several.")}>
        {!data ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : affected === undefined ? (
          <p className="source" style={{ margin: 0 }}>{t("Not assessed: no package on this host was checked against a feed.")}</p>
        ) : !packages.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No package on this host is known to be affected.")}</p>
        ) : (
          <Breakdown items={packages.map(([name, count]) => ({ label: <span className="hm-mono">{name}</span>, value: count, tone: "warn" as const }))} />
        )}
      </Section>

      <Section title={t("What decided this")} span={8} flush>
        <Facts>
          <Fact label={t("Distribution")}>{state?.distribution} {state?.release}</Fact>
          <Fact label={t("Security data")}>
            {data?.snapshot
              ? <>
                  {data.snapshot.provider} · {t("{n} advisories", { n: data.snapshot.advisory_count })} ·{" "}
                  {t("fetched")} <Time value={data.snapshot.fetched_at} />
                  <div className="source hm-mono">{data.snapshot.digest.slice(0, 16)}</div>
                </>
              : <span className="badge unknown">{t("none")}</span>}
          </Fact>
          <Fact label={t("Package list")}>
            {t("{n} packages", { n: data?.package_state.package_count ?? 0 })},{" "}
            {t("read")} <Time value={data?.package_state.collected_at} />
            {data?.package_state.unavailable_reason && (
              <div className="source">{data.package_state.unavailable_reason}</div>
            )}
          </Fact>
          <Fact label={t("Vendor advisories")}>
            {data?.advisory_state.collected_at ? (
              <>
                {t("{n} advisories", { n: data.advisory_state.advisory_count })},{" "}
                {t("read")} <Time value={data.advisory_state.collected_at} />
              </>
            ) : (
              <span className="badge unknown">{t("not read yet")}</span>
            )}
            {data?.advisory_state.unavailable_reason && (
              <div className="source">{reason(data.advisory_state.unavailable_reason)}</div>
            )}
          </Fact>
          <Fact label={t("Assessed")}>
            <Time value={state?.evaluated_at} />
            {findings[0]?.comparator_version && (
              <div className="source">{t("version rules")}: {findings[0].comparator_version}</div>
            )}
          </Fact>
        </Facts>
      </Section>
      </Widgets>
    </ModulePage>
  );
}
