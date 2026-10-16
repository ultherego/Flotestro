import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, fetchWithCredentials } from "../../lib/api";
import { exportAddress, exportFileName } from "../../components/ExportButton";
import { useToast } from "../../components/Toast";
import { useDebounced } from "../../lib/debounce";
import { relativeTime, absoluteTime } from "../../lib/format";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Bars, Banner, Card, Check, Empty, Field, Fields, Find, Kpi, Meter, Modal,
  Note, Pager, Pill, Problem, Ring, Seg, Table, Tags, Toolbar, TwoLine,
  type Segment, type Tone,
} from "../kit";

/**
 * The fleet's CVE picture: what is open, what the vendor has released for
 * it, and - the question the number on its own cannot answer - how much of
 * the fleet could be judged at all.
 *
 * Every verdict here is the distribution's own security tracker, because
 * fixes are backported: a version that looks vulnerable upstream may
 * already carry the patch. That is why a host whose packages were never
 * read shows an em dash and not a nought, on the tile and in the row
 * alike. A fleet nobody has scanned and a fleet with nothing wrong are
 * different answers and the screen must never give the second for the
 * first.
 */

/** One host's standing against the trackers that cover it. */
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
  /** The feed generation that produced this verdict, and when it was taken. */
  generation_id?: string;
  generation_at?: string;
  status?: "complete" | "partial" | "unknown" | "stale";
  /** Set when the last pass could not be computed at all; the numbers above
   *  are then the ones from before it. */
  evaluation_failed_reason?: string;
  evaluation_failed_source?: string;
  evaluation_failed_at?: string;
  last_successful_at?: string;
};

/** A feed the panel judges hosts against, and how fresh it is. */
type Source = {
  provider: string;
  digest: string;
  advisories: number;
  releases?: string[];
  /** For the repository metadata of the hosts themselves: how many carry it. */
  hosts?: number;
  fetched_at: string;
  stale: boolean;
  error?: string;
  generation_id?: string;
  generation_at?: string;
};

/** A fetch the sanity gate refused to put in force. */
type Candidate = {
  id: string;
  provider: string;
  digest: string;
  /** feed_shrank or feed_release_missing. */
  reason: string;
  advisories: number;
  releases?: string[];
  fetched_at: string;
  held_at?: string;
  active_advisories: number;
  active_releases?: string[];
};

/** One page of the host table, with the fleet-wide sums the head reads. */
type View = {
  items: Item[];
  count: number;
  total: number;
  offset: number;
  total_hosts: number;
  evaluated_hosts: number;
  unknown_hosts: number;
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
  candidates?: Candidate[];
};

/** One CVE across the fleet. */
type CVERow = {
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

/** Why a host could not be judged, as the server names it; an unknown code
 *  is shown as it came rather than swallowed. */
export const COVERAGE_REASONS: Record<string, string> = {
  feed_missing: "no feed for the distribution",
  family_unsupported: "this system family is not supported",
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

/** Why the sanity gate held a fetch back. */
export const GATE_REASONS: Record<string, string> = {
  feed_shrank: "the fetch lost most of the findings in force",
  feed_release_missing: "the fetch stopped covering a release that is in force",
};

/** The rungs the server groups by, the gravest first. Every vendor has its
 *  own words for them; the server translates and keeps the vendor's word
 *  beside the rung, which is why a badge carries it as its title. */
export const SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unrated"] as const;

/**
 * The colour of a rung. The two top ones are an error and the middle one a
 * warning; the bottom two are plain. An unrated finding is not a harmless
 * one - it is one the vendor has not weighed yet - so it wears the unknown
 * tone rather than the quiet one.
 */
export function severityTone(severity?: string): Tone {
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

/**
 * The open findings of one host, or undefined when nobody could decide.
 *
 * A host carrying a coverage reason and no findings has not been found
 * clean: nothing about it could be worked out. Drawn as a nought it would
 * be the best-looking row in the table.
 */
export function openFindings(item: Item): number | undefined {
  return item.coverage_reason && item.affected === 0 ? undefined : item.affected;
}

/**
 * Whether a host's verdict came from the generation in force. Three
 * answers and not two: a feed with no generation recorded cannot say.
 */
export function generationState(item: Item, sources: Source[]): "current" | "older" | "unknown" {
  if (!item.generation_id) return "unknown";
  const source = sources.find((one) => one.provider === item.provider);
  if (!source?.generation_id) return "unknown";
  return source.generation_id === item.generation_id ? "current" : "older";
}

/** The first few package names of a CVE row and how many more there are: a
 *  kernel CVE names forty binaries and the row has space for a handful. */
export function packagesPreview(packages: string[], shown = 4): { shown: string[]; more: number } {
  return { shown: packages.slice(0, shown), more: Math.max(0, packages.length - shown) };
}

const PAGE = 50;

export function Vulnerabilities() {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();

  const view = params.get("view") === "cves" ? "cves" : "hosts";
  const severity = params.get("severity") ?? "";
  const fixable = params.get("fixable") === "true";
  const sort = params.get("sort") ?? "";
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(PAGE);
  // A list that asked the server on every keystroke asked it five times for
  // one hostname; the settled value is what the address and the query use.
  const settled = useDebounced(search.trim());

  /* The address carries the whole of what is on screen, so "the critical
     CVEs with a fix" is a link somebody can send. */
  const narrow = (next: Record<string, string>) => {
    const after = new URLSearchParams(params);
    for (const [key, value] of Object.entries(next)) {
      if (value) after.set(key, value); else after.delete(key);
    }
    setParams(after, { replace: true });
    setPage(1);
  };

  const query = new URLSearchParams({ limit: String(size) });
  if (settled) query.set("q", settled);
  if (severity) query.set("severity", severity);
  if (view === "cves") {
    if (fixable) query.set("fixable", "true");
  } else if (sort) {
    query.set("sort", sort);
  }
  if (page > 1) query.set("offset", String((page - 1) * size));

  /* The head is read once, unfiltered: a search narrows what is listed, not
     how bad the fleet is. It brings the worst ten hosts with it, the ones
     with a vendor fix waiting first, which is where the work starts. */
  const summary = useQuery({
    queryKey: ["vulnerabilities", "summary"],
    queryFn: () => api.get<View>("/api/v1/vulnerabilities?sort=fixable&limit=10"),
    retry: false,
  });
  const hostList = useQuery({
    queryKey: ["vulnerabilities", "hosts", query.toString()],
    queryFn: () => api.get<View>(`/api/v1/vulnerabilities?${query}`),
    enabled: view === "hosts",
    retry: false,
  });
  const cveList = useQuery({
    queryKey: ["vulnerabilities", "cves", query.toString()],
    queryFn: () => api.get<CVEPage>(`/api/v1/vulnerabilities/cves?${query}`),
    enabled: view === "cves",
    retry: false,
  });

  // The fetch the operator is deciding about, and the reason that goes with
  // the decision into the trail.
  const [held, setHeld] = useState("");
  const [reason, setReason] = useState("");
  const accept = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/vulnerabilities/snapshots/${id}/accept`, { reason }),
    onSuccess: () => {
      setHeld("");
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
      toast.success(t("The fetch is in force. The hosts are judged against it on the next pass."));
    },
    onError: (error) => {
      if (error instanceof ApiError && error.unauthenticated) {
        toast.error(t("Fresh authentication is required: sign in again and repeat the acceptance."));
        return;
      }
      toast.error(error instanceof Error ? error.message : String(error));
    },
  });

  if (summary.error) return <Problem>{String(summary.error)}</Problem>;

  const data = summary.data;
  const reasonOf = (code: string) => (COVERAGE_REASONS[code] ? t(COVERAGE_REASONS[code]) : code);

  /* Nothing judged means nothing known. Every fleet-wide figure below goes
     through this, so the tiles say "unknown" with one rule rather than six. */
  const blind = data !== undefined && data.total_hosts > 0 && data.evaluated_hosts === 0;
  const figure = (value?: number) => (data === undefined || blind ? undefined : value);

  // A host the feed covers only in part is neither fully assessed nor
  // unassessed: it is the rest of the fleet, and it has its own segment.
  const partly = data
    ? Math.max(0, data.hosts_total - data.hosts_assessed - data.hosts_without_assessment)
    : 0;
  const worst = (data?.items ?? []).filter((one) => !one.coverage_reason && one.affected > 0);
  const coverageReasons = Object.entries(data?.coverage_reasons ?? {}).filter(([, count]) => count > 0);
  const candidates = data?.candidates ?? [];
  const sources = data?.sources ?? [];

  const findings: Segment[] = [
    { label: t("Vendor fix released"), value: figure(data?.affected_with_vendor_fix), tone: "error" },
    { label: t("No fix yet"), value: figure(data?.affected_no_fix), tone: "warn" },
    { label: t("Not established"), value: figure(data?.unknown), tone: "unknown" },
  ];

  const rows = view === "cves" ? cveList.data?.items ?? [] : hostList.data?.items ?? [];
  const total = (view === "cves" ? cveList.data?.total : hostList.data?.total) ?? 0;
  const listError = view === "cves" ? cveList.error : hostList.error;
  const loading = view === "cves" ? cveList.isLoading : hostList.isLoading;
  const narrowed = Boolean(settled || severity || (view === "cves" && fixable));

  /** The reading of a host's coverage, or the reason there is none. */
  const coverageCell = (one: Item) => {
    if (one.coverage_reason) return <Pill tone="unknown">{reasonOf(one.coverage_reason)}</Pill>;
    return (
      <Meter
        share={one.coverage_percent / 100}
        tone={one.fully_assessed ? "ok" : "warn"}
        // A whole number turned 99.4 into 99 and read as complete.
        text={t("{percent}% of {total}", {
          percent: one.coverage_percent.toFixed(1), total: one.packages_total,
        })}
      />
    );
  };

  /** When the host was judged, and whether against the feed in force. A
   *  verdict from an older generation is not wrong; it is simply not the
   *  answer the panel holds now, and the date alone does not show that. */
  const judgedCell = (one: Item) => {
    const state = generationState(one, sources);
    const generation = state === "current"
      ? t("current feed generation")
      : state === "older"
        ? t("older generation, {when}", { when: relativeTime(one.generation_at) })
        : t("generation not recorded");
    return (
      <TwoLine sub={generation}>
        {one.evaluated_at
          ? <span title={absoluteTime(one.evaluated_at)}>{relativeTime(one.evaluated_at)}</span>
          : <span className="fl-faint">{t("never")}</span>}
        {one.evaluation_failed_reason && (
          <> <Pill tone="error" title={one.evaluation_failed_reason}>{t("last pass failed")}</Pill></>
        )}
      </TwoLine>
    );
  };

  return (
    <Board screen={VULNERABILITIES_SCREEN} catalogue={VULNERABILITIES} drawn={{
      coverage: coverageReasons.length > 0 ? (
        <Banner tone="warn">
          {t("Those hosts show no findings because nothing could be decided for them, not because they are clean: {reasons}.", {
            reasons: coverageReasons.map(([code, count]) => `${count} × ${reasonOf(code)}`).join(", "),
          })}
        </Banner>
      ) : undefined,

      findings: (
        <Kpi
          hero
          icon="vulnerabilities"
          testId="findings"
          label={t("Open findings")}
          value={figure(data?.affected) ?? null}
          tone={data?.affected ? "error" : "ok"}
          note={data && !blind
            ? t("{cves} distinct CVEs, {advisories} vendor advisories", {
                cves: data.unique_cves, advisories: data.unique_advisories,
              })
            : t("no host has been judged yet")}
        />
      ),
      fixable: (
        <Kpi
          icon="bulk"
          testId="fixable"
          label={t("Vendor fix released")}
          value={figure(data?.affected_with_vendor_fix) ?? null}
          tone={data?.affected_with_vendor_fix ? "error" : "ok"}
          note={data && !blind
            ? t("{n} installed packages to move on {hosts} hosts", {
                n: data.affected_package_instances, hosts: data.hosts_affected,
              })
            : undefined}
        />
      ),
      nofix: (
        <Kpi
          icon="security"
          testId="nofix"
          label={t("No fix yet")}
          value={figure(data?.affected_no_fix) ?? null}
          tone={data?.affected_no_fix ? "warn" : "ok"}
          note={t("nothing to apply; mitigate or wait for the vendor")}
        />
      ),
      unassessed: (
        <Kpi
          icon="overview"
          testId="unassessed"
          label={t("Hosts never judged")}
          // This one is a real count even when nothing was judged: it is
          // the count of the hosts nobody has read, and it is the figure
          // that stops an unscanned fleet reading as a clean one.
          value={data?.hosts_without_assessment ?? null}
          tone={data?.hosts_without_assessment ? "unknown" : "ok"}
          note={data
            ? t("{n} of {total} hosts judged", { n: data.evaluated_hosts, total: data.total_hosts })
            : undefined}
        />
      ),

      split: (
        <Card title={t("What the vendor offers")} note={t("The open findings by what can be done about them.")}>
          <Band segments={findings} testId="findings-split" />
          {data && !blind && (
            <Note>
              {t("{cves} distinct CVEs · {advisories} vendor advisories · {packages} installed packages to move · {hosts} hosts affected.", {
                cves: data.unique_cves, advisories: data.unique_advisories,
                packages: data.affected_package_instances, hosts: data.hosts_affected,
              })}
            </Note>
          )}
        </Card>
      ),
      assessed: (
        <Card title={t("Judged")} note={t("What part of the fleet could be assessed at all.")}>
          <Ring
            share={data && data.total_hosts > 0 ? data.hosts_assessed / data.total_hosts : undefined}
            label={t("fully judged")}
            tone={data && data.hosts_assessed >= data.total_hosts ? "ok" : "warn"}
            legend={data ? [
              { label: t("Fully judged"), value: data.hosts_assessed, tone: "ok" },
              { label: t("Judged in part"), value: partly, tone: "warn" },
              { label: t("Never judged"), value: data.hosts_without_assessment, tone: "unknown" },
            ] : undefined}
          />
        </Card>
      ),
      worst: (
        <Card title={t("Where to start")} note={t("Hosts with open findings, the ones with a vendor fix first.")}>
          {worst.length === 0
            ? (
              <Empty>
                {data === undefined
                  ? t("Reading assessments…")
                  : data.evaluated_hosts > 0
                    ? t("No judged host has an open finding.")
                    : t("No host has been judged yet.")}
              </Empty>
            )
            : (
              <Bars items={worst.map((one) => ({
                label: <Link to={`/next/hosts/${one.host_id}/vulnerabilities`}>{one.hostname || one.host_id.slice(0, 8)}</Link>,
                value: one.affected,
                // A host with a fix waiting is work somebody can do today;
                // one without is work on the vendor.
                tone: (one.affected_with_vendor_fix > 0 ? "error" : "warn") as Tone,
              }))} />
            )}
        </Card>
      ),

      held: candidates.length > 0 ? (
        <Card
          title={t("Feed fetches held back")}
          note={t("A fetch that lost most of its findings, or a whole release, is not put in force. What is in force stays and grows stale, which at least shows. Accept one only after reading what it lost.")}
          flush
        >
          <Table
            rows={candidates}
            keyOf={(one) => one.id}
            rowTestId={(one) => `held-fetch-${one.provider}`}
            columns={[
              { key: "provider", head: t("Provider"), cell: (one) => (
                <TwoLine sub={<code>{one.digest.slice(0, 12)}</code>}>{one.provider}</TwoLine>
              ) },
              { key: "reason", head: t("Why"), cell: (one) => {
                const lost = (one.active_releases ?? []).filter((release) => !(one.releases ?? []).includes(release));
                return (
                  <TwoLine sub={lost.length > 0 ? t("no longer covers {releases}", { releases: lost.join(", ") }) : undefined}>
                    <Pill tone="warn">{GATE_REASONS[one.reason] ? t(GATE_REASONS[one.reason]) : one.reason}</Pill>
                  </TwoLine>
                );
              } },
              { key: "fetched", head: t("Fetched"), num: true, cell: (one) => one.advisories },
              { key: "force", head: t("In force"), num: true, cell: (one) => one.active_advisories },
              { key: "when", head: t("Held back"), minor: true, cell: (one) => (
                <span title={absoluteTime(one.held_at ?? one.fetched_at)}>{relativeTime(one.held_at ?? one.fetched_at)}</span>
              ) },
              { key: "do", actions: true, cell: (one) => (
                <button type="button" className="fl-quiet fl-small"
                        onClick={() => { setHeld(one.id); setReason(""); }}
                        data-testid={`accept-${one.provider}`}>
                  {t("Accept…")}
                </button>
              ) },
            ]}
          />
          {held && (
            <Modal
              title={t("Put this fetch in force")}
              onClose={() => setHeld("")}
              actions={
                <Actions right>
                  <button type="button" className="fl-quiet" onClick={() => setHeld("")}>{t("Cancel")}</button>
                  <button
                    type="button"
                    className="fl-danger"
                    disabled={reason.trim().length < 8 || accept.isPending}
                    onClick={() => accept.mutate({ id: held, reason: reason.trim() })}
                    data-testid="accept-confirm"
                  >
                    {accept.isPending ? t("accepting…") : t("Accept this fetch")}
                  </button>
                </Actions>
              }
            >
              <Fields>
                <Field
                  label={t("Reason (kept in the audit trail)")}
                  hint={t("At least 8 characters. Say what you checked: the vendor retired findings, the release went out of support.")}
                  wide
                >
                  <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="accept-reason" />
                </Field>
              </Fields>
            </Modal>
          )}
        </Card>
      ) : undefined,

      sources: (
        <Card title={t("Security data")} note={t("The trackers every verdict on this screen was taken from.")} flush>
          <Table
            rows={sources}
            keyOf={(one) => one.provider}
            rowTestId={(one) => `source-${one.provider}`}
            empty={summary.isLoading ? t("Reading assessments…") : t("No feed has been fetched yet.")}
            columns={[
              { key: "provider", head: t("Provider"), cell: (one) => (
                <TwoLine sub={one.generation_id ? <code>{t("generation {id}", { id: one.generation_id.slice(0, 8) })}</code> : undefined}>
                  {one.provider === "host repository metadata" ? t("host repository metadata") : one.provider}
                </TwoLine>
              ) },
              { key: "advisories", head: t("Advisories"), num: true, cell: (one) => one.advisories },
              { key: "releases", head: t("Releases"), minor: true, tight: true, cell: (one) => (
                one.hosts !== undefined
                  ? t("read on {n} hosts", { n: one.hosts })
                  : (one.releases ?? []).join(", ") || <span className="fl-faint">—</span>
              ) },
              { key: "fetched", head: t("Fetched"), minor: true, cell: (one) => (
                <span title={absoluteTime(one.fetched_at)}>{relativeTime(one.fetched_at)}</span>
              ) },
              { key: "state", head: t("State"), cell: (one) => (
                one.error
                  ? <Pill tone="error" title={one.error}>{one.error.slice(0, 80)}</Pill>
                  : one.stale
                    ? <Pill tone="warn">{t("older than {n} h", { n: data?.max_snapshot_age_hours ?? 0 })}</Pill>
                    : <Pill tone="ok">{t("fresh")}</Pill>
              ) },
            ]}
          />
        </Card>
      ),

      list: (
        <Card
          title={view === "cves" ? t("By CVE") : t("By host")}
          note={view === "cves"
            ? t("One row per CVE over the hosts you can see. The host count is the machines to move; the fix count says on how many of them the vendor has released one.")
            : t("One row per host, as the trackers that cover it last judged it.")}
          flush
          foot={<Pager page={page} size={size} total={total} onPage={setPage} onSize={setSize} />}
        >
          <Toolbar
            end={
              <>
                {/* The same findings grouped the other way round: a toggle
                    and not two screens, because the head above them is one
                    answer that serves both. */}
                <Seg
                  value={view}
                  onChange={(next) => narrow({ view: next === "cves" ? "cves" : "", fixable: "", sort: "" })}
                  options={[
                    { value: "hosts", label: t("By host") },
                    { value: "cves", label: t("By CVE") },
                  ]}
                />
                {/* The file is always the host view: the fleet's CSV is one
                    row per machine, whichever way the screen is grouped. */}
                {view === "hosts" && <ExportHosts query={query} />}
              </>
            }
          >
            <Find
              value={search}
              onChange={(value) => { setSearch(value); setPage(1); }}
              placeholder={view === "cves" ? t("CVE number or package name") : t("Search hostname")}
              testId="search"
            />
            <select
              value={severity}
              onChange={(event) => narrow({ severity: event.target.value })}
              aria-label={t("severity: any")}
              data-testid="severity"
            >
              <option value="">{t("severity: any")}</option>
              {SEVERITIES.map((one) => <option key={one} value={one}>{t(one)}</option>)}
            </select>
            {view === "cves" ? (
              <Check checked={fixable} onChange={(on) => narrow({ fixable: on ? "true" : "" })}>
                {t("only what the vendor has a fix for")}
              </Check>
            ) : (
              <select
                value={sort}
                onChange={(event) => narrow({ sort: event.target.value })}
                aria-label={t("Order")}
                data-testid="sort"
              >
                <option value="">{t("most open findings first")}</option>
                <option value="fixable">{t("most vendor fixes first")}</option>
                <option value="hostname">{t("by hostname")}</option>
              </select>
            )}
          </Toolbar>

          {listError ? <Problem>{String(listError)}</Problem> : view === "cves" ? (
            <Table
              rows={rows as CVERow[]}
              keyOf={(one) => one.cve}
              rowTestId={(one) => `cve-${one.cve}`}
              testId="cves"
              empty={loading
                ? t("Reading assessments…")
                : narrowed ? t("No CVE matches this.") : t("No judged host has an open finding.")}
              columns={[
                { key: "cve", head: t("CVE"), tight: true, cell: (one) => (
                  <Link className="fl-mono" to={`/next/vulnerabilities/${one.cve}`}>{one.cve}</Link>
                ) },
                { key: "severity", head: t("Severity"), cell: (one) => (
                  <Pill tone={severityTone(one.severity)} title={one.vendor_severity}>{t(one.severity)}</Pill>
                ) },
                // The upstream score stands beside the vendor's rating and
                // never instead of it: a score nobody published is a dash.
                { key: "cvss", head: t("CVSS"), num: true, minor: true, cell: (one) => (
                  one.cvss_score === undefined
                    ? <span className="fl-faint" title={t("unknown")}>—</span>
                    : <span title={one.cvss_severity}>{one.cvss_score.toFixed(1)}</span>
                ) },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.hosts },
                { key: "fix", head: t("Vendor fix"), num: true, cell: (one) => (
                  one.hosts_with_vendor_fix > 0
                    ? <Pill tone="ok">{t("{n} of {total}", { n: one.hosts_with_vendor_fix, total: one.hosts })}</Pill>
                    : <Pill tone="warn">{t("none")}</Pill>
                ) },
                { key: "packages", head: t("Packages"), minor: true, tight: true, cell: (one) => {
                  const preview = packagesPreview(one.packages);
                  return (
                    <span title={one.packages.join(", ")}>
                      <code>{preview.shown.join(", ")}</code>
                      {preview.more > 0 && <span className="fl-faint"> {t("+{n} more", { n: preview.more })}</span>}
                    </span>
                  );
                } },
                { key: "first", head: t("First seen"), minor: true, cell: (one) => (
                  <span title={absoluteTime(one.first_seen)}>{relativeTime(one.first_seen)}</span>
                ) },
              ]}
            />
          ) : (
            <Table
              rows={rows as Item[]}
              keyOf={(one) => one.host_id}
              rowTestId={(one) => `host-${one.hostname || one.host_id}`}
              testId="hosts"
              empty={loading
                ? t("Reading assessments…")
                : narrowed ? t("No host matches this.") : t("No host has been judged yet.")}
              columns={[
                { key: "host", head: t("Host"), cell: (one) => (
                  <TwoLine sub={[one.distribution, one.release].filter(Boolean).join(" ") || t("system unknown")}>
                    <Link to={`/next/hosts/${one.host_id}/vulnerabilities`}>{one.hostname || one.host_id.slice(0, 8)}</Link>
                  </TwoLine>
                ) },
                { key: "open", head: t("Open"), num: true, cell: (one) => {
                  const open = openFindings(one);
                  if (open === undefined) return <span className="fl-faint" title={t("unknown")}>—</span>;
                  return open > 0 ? <b className="fl-error">{open}</b> : <span className="fl-faint">0</span>;
                } },
                // The rungs in the order of the list, worst first: "3
                // critical" says what a sum of eleven never will.
                { key: "severity", head: t("By severity"), cell: (one) => {
                  const rungs = SEVERITIES.filter((rung) => (one.by_severity?.[rung] ?? 0) > 0);
                  if (rungs.length === 0) return <span className="fl-faint">—</span>;
                  return (
                    <Tags>
                      {rungs.map((rung) => (
                        <Pill key={rung} tone={severityTone(rung)}>
                          {t("{n} {severity}", { n: one.by_severity?.[rung] ?? 0, severity: t(rung) })}
                        </Pill>
                      ))}
                    </Tags>
                  );
                } },
                { key: "fix", head: t("Vendor fix"), num: true, cell: (one) => (
                  openFindings(one) === undefined
                    ? <span className="fl-faint" title={t("unknown")}>—</span>
                    : one.affected_with_vendor_fix > 0
                      ? <Pill tone="error">{one.affected_with_vendor_fix}</Pill>
                      : <span className="fl-faint">0</span>
                ) },
                { key: "nofix", head: t("No fix"), num: true, minor: true, cell: (one) => (
                  openFindings(one) === undefined ? <span className="fl-faint">—</span> : one.affected_no_fix
                ) },
                { key: "unknown", head: t("Not established"), num: true, minor: true, cell: (one) => (
                  openFindings(one) === undefined ? <span className="fl-faint">—</span> : one.unknown
                ) },
                { key: "coverage", head: t("Coverage"), cell: coverageCell },
                { key: "judged", head: t("Last judged"), minor: true, cell: judgedCell },
              ]}
            />
          )}
        </Card>
      ),
    }} />
  );
}

/**
 * The fleet assessment as a file, carrying the filter on screen.
 *
 * It is a fetch and not a plain link because a download that goes around
 * the API client goes without the bootstrap token, and an installation
 * signed in with one - the default, with no identity provider - was
 * answered 401 while the rest of the screen worked.
 */
function ExportHosts({ query }: { query: URLSearchParams }) {
  const t = useT();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const response = await fetchWithCredentials(exportAddress("/api/v1/vulnerabilities", query));
      if (!response.ok) throw new Error(response.statusText);
      const href = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = exportFileName(response.headers.get("Content-Disposition"));
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      toast.error(t("The export failed: {message}", { message: error instanceof Error ? error.message : String(error) }));
    } finally {
      setBusy(false);
    }
  };
  return (
    <button type="button" className="fl-quiet fl-small" onClick={download} disabled={busy} data-testid="export">
      {busy ? t("Exporting…") : t("Export CSV")}
    </button>
  );
}

export const VULNERABILITIES_SCREEN = "next_vulnerabilities";

export const VULNERABILITIES: BoardEntry[] = [
  { key: "coverage", title: "Incomplete coverage", width: 12, height: 1 },
  { key: "findings", title: "Open findings", width: 3, height: 1 },
  { key: "fixable", title: "Vendor fix released", width: 3, height: 1 },
  { key: "nofix", title: "No fix yet", width: 3, height: 1 },
  { key: "unassessed", title: "Hosts never judged", width: 3, height: 1 },
  { key: "split", title: "What the vendor offers", width: 5, height: 2 },
  { key: "assessed", title: "Judged", width: 3, height: 2 },
  { key: "worst", title: "Where to start", width: 4, height: 2 },
  { key: "held", title: "Feed fetches held back", width: 12, height: 2 },
  { key: "sources", title: "Security data", width: 12, height: 3 },
  { key: "list", title: "The list", width: 12, height: 6 },
];
