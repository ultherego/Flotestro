import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import {
  Fact, Facts, Foot, Message, ModuleHeader, ModulePage, Section, Stat, Stats, Table, useHost,
} from "./shared";
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

/** The reasons an assessment is incomplete - in the operator's language, not codes. */
const REASONS: Record<string, string> = {
  feed_missing: "no security feed for this distribution",
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
 *
 * The distribution vendor's tracker decides: it knows which version carries
 * the fix, because fixes are backported and by upstream numbering look
 * vulnerable. The panel guesses nothing - the finding count stands next to
 * the coverage here, because without it it means nothing: a host the feed
 * does not cover and a host without vulnerabilities both show zero.
 */
export function Vulnerabilities() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<"fixable" | "no-fix" | "unknown">("fixable");
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

  const visible = findings.filter((finding) => {
    if (filter === "unknown") return finding.state === "unknown";
    if (filter === "no-fix") return finding.state === "affected" && !finding.fixed_version;
    return finding.state === "affected" && !!finding.fixed_version;
  });

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Vulnerabilities")}
        description={t("What the distribution's own security tracker says about the packages on this host. Fixes are backported, so upstream version ranges cannot answer this question — only the vendor can. Where the vendor says nothing, the panel says \"not known\", never \"clean\".")}
        actions={
          <button disabled={reread.isPending || host.connection_state !== "online"}
                  onClick={() => reread.mutate()}>
            {t("Re-read packages")}
          </button>
        }
      />
      <p className="hm-freshness">
        <span>
          {t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move. One advisory carries several CVEs and touches several packages, so these never add up — and each answers a different question.", {
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

      {/* The finding counts stand next to the coverage, because without it
          they mean nothing: a host the feed does not cover and a host
          without vulnerabilities both show zero. */}
      <Stats>
        <Stat
          label={t("With a vendor fix")}
          value={state?.affected_with_vendor_fix ?? 0}
          tone={(state?.affected_with_vendor_fix ?? 0) > 0 ? "error" : undefined}
        />
        <Stat
          label={t("No fix from vendor")}
          value={state?.affected_no_fix ?? 0}
          tone={(state?.affected_no_fix ?? 0) > 0 ? "warn" : undefined}
        />
        <Stat
          label={t("Not established")}
          value={state?.unknown ?? 0}
          tone={(state?.unknown ?? 0) > 0 ? "unknown" : undefined}
        />
        {/* Coverage rounded to a whole number turned 99.7% into "100%" -
            "everything checked" where dozens of packages stayed outside
            the assessment. A complete assessment has its own explicit
            answer here. */}
        <Stat
          label={t("Coverage")}
          value={`${(data?.coverage_percent ?? 0).toFixed(1)}%`}
          hint={t("{percent}% of packages covered", { percent: (data?.coverage_percent ?? 0).toFixed(1) })}
          tone={data?.fully_assessed ? "ok" : "warn"}
        />
      </Stats>

      <Section
        title={t("Findings")}
        count={visible.length}
        tools={
          <span className="hm-choices">
            {(["fixable", "no-fix", "unknown"] as const).map((key) => (
              <button key={key} className={filter === key ? "" : "secondary"} onClick={() => setFilter(key)}>
                {key === "fixable" ? t("Fixable") : key === "no-fix" ? t("No fix") : t("Not established")}
              </button>
            ))}
          </span>
        }
        flush
      >
        {!visible.length ? (
          <Empty>
            {filter === "fixable"
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
                <th>{t("Vendor fix")}</th><th>{t("In repositories")}</th>
              </tr>
            </thead>
            <tbody>
              {visible.slice(0, 300).map((finding, index) => (
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
                    {finding.cve_ids?.length ? (
                      <div className="source hm-mono">{finding.cve_ids.join(", ")}</div>
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
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {visible.length > 300 && (
          <Foot>
            <span>{t("Showing the first 300 of {n}. The counts above cover all of them.", { n: visible.length })}</span>
          </Foot>
        )}
      </Section>

      <Section title={t("What decided this")} flush>
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
    </ModulePage>
  );
}
