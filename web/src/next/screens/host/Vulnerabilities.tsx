import { useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, Job } from "../../../lib/types";
import { bulkPrefill } from "../../../lib/orders";
import { useT } from "../../../i18n";
import {
  Actions, Band, Banner, Bars, Bones, Button, C, Card, Empty, Fact, Facts, Find, Grid, HeadActions,
  Meter, Note, Pill, Problem, Seg, Table, Tabs, Toolbar, useTab, TwoLine, type Segment, type Tone,
} from "../../kit";

/**
 * What the distribution's own security tracker says about the packages on
 * this machine.
 *
 * Fixes are backported, so an upstream version range cannot answer the
 * question - only the vendor can. Where the vendor says nothing the module
 * says *not known*, never *clean*, and where no feed covers the host at all
 * every count here is an em dash: a host nobody assessed and a host with
 * nothing wrong are different answers.
 */

/** The one order this module places; refused, it leaves a read of what was last seen. */
const VULNERABILITY_READS = ["packages.list"];

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
  /** Set when the last pass could not be computed: the numbers above are the ones from before it. */
  evaluation_failed_reason?: string;
  evaluation_failed_source?: string;
  evaluation_failed_at?: string;
  last_successful_at?: string;
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

/**
 * Enrichment: the CVSS score and the description from the upstream database.
 *
 * It stands next to the finding, not inside it. Whether the package is
 * vulnerable and what closes it is said only by the distribution vendor;
 * this is just the answer to "how dangerous is the vulnerability itself".
 */
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

/**
 * The highest CVSS score among the CVEs of one finding: one finding
 * sometimes carries several, and the most dangerous of them decides how
 * urgent the matter is.
 */
export function highestScore(finding: Finding, details?: Record<string, CVEDetails>): CVEDetails | undefined {
  if (!details) return undefined;
  let best: CVEDetails | undefined;
  for (const id of finding.cve_ids ?? []) {
    const entry = details[id];
    if (entry?.cvss_score === undefined) continue;
    if (best?.cvss_score === undefined || entry.cvss_score > best.cvss_score) best = entry;
  }
  return best;
}

/**
 * How many findings the table shows before asking; the page grows by this
 * much per click. The counts above the table cover every finding either way.
 */
export const FINDINGS_PAGE = 300;

/** The name the operator sees: the binary package, or the source one where the vendor names no binary. */
function packageName(finding: Pick<Finding, "binary_package" | "source_package">): string {
  return finding.binary_package || finding.source_package || "";
}

/** Whether a finding matches the search: a CVE, an advisory or a package, by prefix. */
export function findingMatches(
  finding: Pick<Finding, "advisory_id" | "cve_ids" | "binary_package" | "source_package">,
  query: string,
): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const candidates = [
    finding.advisory_id, finding.binary_package ?? "", finding.source_package ?? "", ...(finding.cve_ids ?? []),
  ];
  return candidates.some((candidate) => candidate.toLowerCase().startsWith(needle));
}

/**
 * The canonical rung of a vendor severity, so one filter fits every vendor's
 * words: Red Hat's "important" is high and its "moderate" is medium. An
 * unrated finding is one the vendor has not weighed.
 */
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
 * vendor fix from "Patch all fixable". It is the new panel's own workspace.
 */
export function patchAddress(
  host: { id: string; hostname?: string },
  findings: Pick<Finding, "state" | "vendor_fix" | "binary_package" | "source_package">[],
): string | null {
  const packages: string[] = [];
  for (const finding of findings) {
    if (finding.state !== "affected" || finding.vendor_fix !== "known") continue;
    const name = packageName(finding);
    if (name && !packages.includes(name)) packages.push(name);
  }
  if (packages.length === 0) return null;
  const label = host.hostname || host.id.slice(0, 8);
  const name = packages.length === 1
    ? `Patch ${packages[0]} on ${label}`
    : `Patch ${packages.length} packages on ${label}`;
  return bulkPrefill("packages.upgrade", name, { package_upgrade: { packages: packages.sort() } }, undefined, [host.id]);
}

/** The reasons an assessment is incomplete - in the operator's language, not codes. */
const REASONS: Record<string, string> = {
  feed_missing: "no security feed for this distribution",
  family_unsupported: "this system family is not supported",
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
  const tone: Tone =
    severity === "critical" || severity === "high" ? "error"
      : severity === "medium" ? "warn"
        : severity === "low" || severity === "unimportant" ? "neutral" : "unknown";
  return <Pill tone={tone}>{severity || t("unrated")}</Pill>;
}

/* ------------------------------------------------------------- the gates */

function Guard({ action, host, explain = false, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (verdict.pending || !explain) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

/* ------------------------------------------------------------ the module */

/** The sub-tabs: the findings, the packages they fall on, and how far the assessment reaches. */
const VULNERABILITY_TABS = ["findings", "packages", "coverage"] as const;

export function Vulnerabilities({ host }: { host: Host }) {
  const t = useT();
  const [tab, goTab] = useTab(VULNERABILITY_TABS);
  const navigate = useNavigate();
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
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action: "packages.list", payload: {} }),
    onSuccess: (job) => {
      setMessage(t("Job {id} reads the package list; the assessment follows.", { id: job.id.slice(0, 8) }));
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const reason = (code?: string) => (code ? (REASONS[code] ? t(REASONS[code]) : code) : "");

  if (report.error) return <Problem>{String(report.error)}</Problem>;

  const data = report.data;
  const state = data?.state;
  const findings = data?.findings ?? [];

  // Nothing is a count until a feed covered this host: the affected list is
  // undefined rather than empty, and every figure drawn from it is a dash.
  const assessed = !!data && !!state && (state.packages_covered > 0 || !state.coverage_reason);
  const affected = assessed ? findings.filter((finding) => finding.state === "affected") : undefined;
  const severities = ["critical", "high", "medium", "low"];
  const packages = Object.entries((affected ?? []).reduce<Record<string, number>>((into, finding) => {
    const name = finding.binary_package || finding.source_package || "?";
    into[name] = (into[name] ?? 0) + 1;
    return into;
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
    // A new search starts the page over: the rows the operator loaded for
    // the previous one are not the rows of this one.
    setShown(FINDINGS_PAGE);
    next();
  };
  const patchAll = patchAddress(host, findings);

  const bySeverity: Segment[] = [
    ...severities.map((rung) => ({
      label: rung,
      value: affected === undefined ? undefined : affected.filter((one) => one.vendor_severity === rung).length,
      tone: (rung === "critical" || rung === "high" ? "error" : rung === "medium" ? "warn" : "neutral") as Tone,
    })),
    {
      label: t("unrated"),
      value: affected === undefined
        ? undefined
        : affected.filter((one) => !severities.includes(one.vendor_severity ?? "")).length,
      tone: "unknown",
    },
    { label: t("not established"), value: assessed ? state?.unknown : undefined, tone: "unknown" },
  ];

  return (
    <>
      <HeadActions>
        {/* The order goes through the Bulk workspace: a package upgrade is
            planned on the host and approved there, and the panel never
            installs anything from a module. */}
        <Button
          kind="quiet"
          disabled={!patchAll}
          title={patchAll
            ? undefined
            : assessed
              ? t("No finding on this host has a vendor fix to install.")
              : t("Nothing was assessed on this host yet, so there is nothing to patch from here.")}
          testId="patch-all"
          onClick={() => { if (patchAll) navigate(patchAll); }}
        >
          {t("Patch all fixable")}
        </Button>
        <Guard action="packages.list" host={host.id} explain>
          <Button
            kind="quiet"
            disabled={reread.isPending || host.connection_state !== "online"}
            onClick={() => reread.mutate()}
            testId="reread"
          >
            {t("Re-read packages")}
          </Button>
        </Guard>
      </HeadActions>

      <ReadOnlyNotice host={host.id} actions={VULNERABILITY_READS} />
      {message && <Banner tone="info">{message}</Banner>}
      {state?.evaluation_failed_reason && (
        <Banner tone="error">
          {t("The last assessment of this host could not be computed: reading {source} failed. What is below was computed {when} and has not been refreshed since.", {
            source: state.evaluation_failed_source ?? "",
            when: relativeTime(state.last_successful_at ?? state.evaluated_at),
          })}
        </Banner>
      )}
      {state?.coverage_reason && (
        <Banner tone="warn">
          {t("This assessment is incomplete: {reason}. Zero findings here does not mean the host is clean.", { reason: reason(state.coverage_reason) })}
        </Banner>
      )}
      {data?.snapshot_stale && data.snapshot && (
        <Banner tone="warn">
          {t("The security data was last fetched {when} — older than the policy allows. The assessment still uses it, because yesterday's data beats none.", {
            when: relativeTime(data.snapshot.fetched_at),
          })}
        </Banner>
      )}

      {/* The severity band is the measurement and stays above the tabs;
          the one order the screen places - patch what has a fix - belongs
          to the screen and stands in its heading. */}
      <Grid>
        <C span={12}>
          <Card
            title={t("Affected packages by severity")}
            note={t("As the distribution vendor rates them; a package without a rating is unrated, not harmless.")}
            foot={!data
              ? undefined
              : !assessed
                ? t("Not assessed: no count here is known until a feed covers this host.")
                : t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move. One advisory carries several CVEs and touches several packages, so these never add up — and each answers a different question.", {
                    cves: state?.unique_cves ?? 0,
                    advisories: state?.unique_advisories ?? 0,
                    packages: state?.affected_packages ?? 0,
                  })}
          >
            {!data ? <Bones rows={2} height={18} /> : <Band segments={bySeverity} testId="by-severity" />}
          </Card>
        </C>
      </Grid>

      <Tabs
        value={tab}
        onChange={goTab}
        tabs={[
          { value: "findings", label: t("Findings") },
          { value: "packages", label: t("Packages") },
          { value: "coverage", label: t("Coverage") },
        ]}
      />

      {tab === "coverage" && (
      <Grid>
        <C span={4}>
          <Card title={t("Coverage")}>
            <Facts>
              {/* Coverage rounded to a whole number turned 99.7% into "100%" -
                  "everything checked" where dozens of packages stayed outside
                  the assessment. The reading keeps its tenth. */}
              <Fact label={t("Coverage")}>
                {coverage === undefined ? "—" : (
                  <Meter
                    share={coverage / 100}
                    tone={data?.fully_assessed ? "ok" : "warn"}
                    text={t("{percent}% of packages covered", { percent: coverage.toFixed(1) })}
                  />
                )}
              </Fact>
              <Fact label={t("By vendor fix")}>
                {!state ? "—" : !assessed ? (
                  <Note>{t("nothing assessed")}</Note>
                ) : (
                  <Bars items={[
                    { label: t("With a vendor fix"), value: state.affected_with_vendor_fix, tone: "error" as Tone },
                    { label: t("No fix from vendor"), value: state.affected_no_fix, tone: "warn" as Tone },
                    { label: t("Not established"), value: state.unknown, tone: "unknown" as Tone },
                  ]} />
                )}
              </Fact>
            </Facts>
          </Card>
        </C>
        <C span={8}>
          <Card title={t("What decided this")}>
            <Facts>
              <Fact label={t("Distribution")}>
                {state?.distribution ? `${state.distribution} ${state.release ?? ""}`.trim() : "—"}
              </Fact>
              <Fact label={t("Security data")}>
                {data?.snapshot ? (
                  <TwoLine sub={data.snapshot.digest.slice(0, 16)}>
                    <span title={absoluteTime(data.snapshot.fetched_at)}>
                      {t("{provider} · {n} advisories · fetched {when}", {
                        provider: data.snapshot.provider,
                        n: data.snapshot.advisory_count,
                        when: relativeTime(data.snapshot.fetched_at),
                      })}
                    </span>
                  </TwoLine>
                ) : <Pill tone="unknown">{t("none")}</Pill>}
              </Fact>
              <Fact label={t("Package list")}>
                <TwoLine sub={data?.package_state.unavailable_reason || undefined}>
                  <span title={absoluteTime(data?.package_state.collected_at)}>
                    {t("{n} packages, read {when}", {
                      n: data?.package_state.package_count ?? 0,
                      when: relativeTime(data?.package_state.collected_at),
                    })}
                  </span>
                </TwoLine>
              </Fact>
              <Fact label={t("Vendor advisories")}>
                <TwoLine sub={data?.advisory_state.unavailable_reason ? reason(data.advisory_state.unavailable_reason) : undefined}>
                  {data?.advisory_state.collected_at
                    ? (
                      <span title={absoluteTime(data.advisory_state.collected_at)}>
                        {t("{n} advisories, read {when}", {
                          n: data.advisory_state.advisory_count,
                          when: relativeTime(data.advisory_state.collected_at),
                        })}
                      </span>
                    )
                    : <Pill tone="unknown">{t("not read yet")}</Pill>}
                </TwoLine>
              </Fact>
              <Fact label={t("Assessed")}>
                <TwoLine sub={findings[0]?.comparator_version
                  ? t("version rules: {rules}", { rules: findings[0].comparator_version })
                  : undefined}
                >
                  {state?.evaluated_at
                    ? <span title={absoluteTime(state.evaluated_at)}>{relativeTime(state.evaluated_at)}</span>
                    : <Pill tone="unknown">{t("never")}</Pill>}
                </TwoLine>
              </Fact>
            </Facts>
            <Actions>
              <Link to={`/hosts/${host.id}/packages`}>{t("The packages on this host")}</Link>
            </Actions>
          </Card>
        </C>
      </Grid>
      )}

      {tab === "packages" && (
      <Grid>
        <C span={12}>
          <Card title={t("Most affected packages")} note={t("Findings per package; one advisory can touch several.")}>
            {!data ? (
              <Bones rows={4} />
            ) : affected === undefined ? (
              <Empty icon="vulnerabilities">{t("Not assessed: no package on this host was checked against a feed.")}</Empty>
            ) : !packages.length ? (
              <Empty>{t("No package on this host is known to be affected.")}</Empty>
            ) : (
              <Bars items={packages.map(([name, count]) => ({ label: name, value: count, tone: "warn" as Tone }))} />
            )}
          </Card>
        </C>
      </Grid>
      )}

      {tab === "findings" && (
      <Grid>
        <C span={12}>
          <Card
            title={t("Findings")}
            note={assessed ? t("{n} shown", { n: visible.length }) : undefined}
            foot={visible.length > shown
              ? (
                <>
                  <span>{t("Showing the first {shown} of {n}. The counts above cover all of them.", { shown, n: visible.length })}</span>
                  <Button kind="quiet" onClick={() => setShown((previous) => previous + FINDINGS_PAGE)} testId="load-more">
                    {t("Load more ({n} left)", { n: visible.length - shown })}
                  </Button>
                </>
              )
              : undefined}
            flush
          >
            <Toolbar
              end={
                <Seg
                  value={filter}
                  onChange={(value) => narrowed(() => setFilter(value))}
                  label={t("Which findings")}
                  options={[
                    { value: "fixable", label: t("Fixable") },
                    { value: "no-fix", label: t("No fix") },
                    { value: "unknown", label: t("Not established") },
                  ]}
                />
              }
            >
              <Find
                value={search}
                onChange={(value) => narrowed(() => setSearch(value))}
                placeholder={t("CVE, advisory or package")}
                testId="search"
              />
              <select
                value={severity}
                onChange={(event) => narrowed(() => setSeverity(event.target.value))}
                aria-label={t("Severity")}
                data-testid="severity"
              >
                <option value="">{t("any severity")}</option>
                {["critical", "high", "medium", "low", "negligible", "unrated"].map((rung) => (
                  <option key={rung} value={rung}>{t(rung)}</option>
                ))}
              </select>
            </Toolbar>
            <Table
              rows={visible.slice(0, shown)}
              keyOf={(finding, index) => `${finding.advisory_id}-${finding.binary_package}-${finding.installed_version}-${index}`}
              loading={report.isLoading}
              testId="findings"
              empty={data && !assessed
                ? t("Nothing was assessed: {reason}. The list is empty because nothing was checked, not because nothing was found.", { reason: reason(state?.coverage_reason) })
                : search.trim() || severity
                  ? t("No finding matches these filters.")
                  : filter === "fixable"
                    ? t("Nothing here can be closed by installing an update.")
                    : filter === "no-fix"
                      ? t("The vendor has published a fix for everything it knows about here.")
                      : t("Everything on this host could be decided one way or the other.")}
              columns={[
                { key: "severity", head: t("Severity"), cell: (one) => <SeverityBadge severity={one.vendor_severity} /> },
                // The upstream score stands next to the vendor severity, not
                // instead of it: the vendor knows its distribution, CVSS
                // speaks about the vulnerability itself.
                {
                  key: "cvss",
                  head: "CVSS",
                  num: true,
                  cell: (one) => (
                    <span title={highestScore(one, data?.cve_details)?.cvss_vector}>
                      {highestScore(one, data?.cve_details)?.cvss_score?.toFixed(1) ?? "—"}
                    </span>
                  ),
                },
                {
                  key: "advisory",
                  head: t("Advisory"),
                  cell: (one) => (
                    <TwoLine
                      sub={one.cve_ids?.length
                        // Every CVE leads to its fleet page: the same number
                        // on twenty hosts is one matter, and that page names
                        // the twenty.
                        ? one.cve_ids.map((id, position) => (
                            <span key={id}>
                              {position > 0 && ", "}
                              <Link to={`/vulnerabilities/${id}`}>{id}</Link>
                            </span>
                          ))
                        : undefined}
                    >
                      {one.advisory_id}
                    </TwoLine>
                  ),
                },
                {
                  key: "package",
                  head: t("Package"),
                  cell: (one) => (
                    <TwoLine
                      sub={one.source_package && one.source_package !== one.binary_package
                        ? t("source: {name}", { name: one.source_package })
                        : undefined}
                    >
                      {one.binary_package}
                    </TwoLine>
                  ),
                },
                { key: "installed", head: t("Installed"), tight: true, cell: (one) => one.installed_version },
                // Debian decides by source package, and the binary version is
                // sometimes from another numbering: both are shown so it is
                // visible what was really compared.
                {
                  key: "compared",
                  head: t("Compared"),
                  minor: true,
                  cell: (one) => (
                    <TwoLine sub={one.comparison_basis || undefined}>{one.comparison_version || "—"}</TwoLine>
                  ),
                },
                {
                  key: "fixed",
                  head: t("Fixed in"),
                  tight: true,
                  cell: (one) => one.fixed_version || <Pill tone="warn">{t("no fix")}</Pill>,
                },
                {
                  key: "vendor",
                  head: t("Vendor fix"),
                  cell: (one) => one.state === "unknown"
                    ? <Pill tone="unknown">{reason(one.reason_code)}</Pill>
                    : one.vendor_fix === "known"
                      ? <Pill tone="ok">{t("published")}</Pill>
                      : one.vendor_fix === "unavailable"
                        ? <Pill tone="warn">{t("none")}</Pill>
                        : <Pill tone="unknown">{t("not known")}</Pill>,
                },
                // The third axis - whether the transaction goes through -
                // belongs to the package plan, so the panel does not promise
                // it here.
                {
                  key: "repository",
                  head: t("In repositories"),
                  minor: true,
                  cell: (one) => one.repository_candidate === "visible"
                    ? <Pill tone="ok">{t("visible here")}</Pill>
                    : one.repository_candidate === "absent"
                      ? <Pill tone="warn">{t("not offered")}</Pill>
                      : <Pill tone="neutral">{t("plan an update to find out")}</Pill>,
                },
                {
                  key: "do",
                  head: "",
                  actions: true,
                  cell: (one) => {
                    const patch = patchAddress(host, [one]);
                    return patch ? <Link to={patch}>{t("Patch")}</Link> : null;
                  },
                },
              ]}
            />
          </Card>
        </C>
      </Grid>
      )}
    </>
  );
}
