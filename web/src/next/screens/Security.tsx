import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { relativeTime } from "../../lib/format";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Bars, Card, Empty, Kpi, Pill, Problem, Table, type Segment, type Tone,
} from "../kit";

/**
 * What the fleet's own facts say about how it is set up.
 *
 * One bad setting on a hundred hosts is one problem, not a hundred - so a
 * check is the row and the hosts are its count. What nobody could judge is
 * never counted as passing: the sweep has a time budget, and an answer
 * taken over part of the fleet says so.
 */

type Check = {
  id: string;
  title: string;
  severity: string;
  expected: string;
  failed: number;
  passed: number;
  unknown: number;
  not_applicable: number;
  fixable: number;
  hosts?: { host_id: string; hostname: string }[];
};

type View = {
  hosts: number;
  checks: Check[];
  generated_at: string;
  partial?: boolean;
  unknown_hosts: number;
  hosts_judged?: number;
  partial_reason?: string;
};

/** The order the severities are listed in, the gravest first. */
const SEVERITIES = ["high", "medium", "low", "info"];

/** The colour of a severity: high is an error, info is a note, the rest a warning. */
export function severityTone(severity: string): Tone {
  return severity === "high" ? "error" : severity === "info" ? "unknown" : "warn";
}

export function Security() {
  const t = useT();
  const view = useQuery({
    queryKey: ["security", "fleet"],
    queryFn: () => api.get<View>("/api/v1/security"),
  });

  if (view.error) return <Problem>{String(view.error)}</Problem>;
  const data = view.data;
  const checks = data?.checks ?? [];
  const sum = (key: "failed" | "passed" | "fixable" | "unknown") =>
    data === undefined ? undefined : checks.reduce((total, one) => total + one[key], 0);

  const failed = sum("failed");
  const fixable = sum("fixable");
  const unknown = sum("unknown");
  const passed = sum("passed");

  const bySeverity = SEVERITIES.map((severity) => ({
    label: t(severity),
    value: checks.filter((one) => one.severity === severity).reduce((total, one) => total + one.failed, 0),
    tone: severityTone(severity),
  }));

  /* The hosts carrying the most findings, counted over the host lists the
     checks carry: where to start is a question about machines, not checks. */
  const byHost = new Map<string, { hostname: string; count: number }>();
  for (const check of checks) {
    for (const host of check.hosts ?? []) {
      const entry = byHost.get(host.host_id) ?? { hostname: host.hostname, count: 0 };
      entry.count += 1;
      byHost.set(host.host_id, entry);
    }
  }
  const worst = [...byHost.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);

  const outcome: Segment[] = [
    { label: t("Failing"), value: failed, tone: "error" },
    { label: t("Passing"), value: passed, tone: "ok" },
    { label: t("Not judged"), value: unknown, tone: "unknown" },
  ];

  return (
    <Board screen={SECURITY_SCREEN} catalogue={SECURITY} drawn={{
      findings: (
        <Kpi
          icon="security"
          label={t("Findings")}
          value={failed ?? null}
          tone={failed ? "error" : "ok"}
          note={data ? t("over {n} hosts the sweep judged", { n: data.hosts_judged ?? data.hosts }) : undefined}
        />
      ),
      fixable: (
        <Kpi
          icon="bulk"
          label={t("Fixable from here")}
          value={fixable ?? null}
          tone={fixable ? "warn" : "ok"}
          note={t("one campaign covers the whole set")}
        />
      ),
      unjudged: (
        <Kpi
          icon="overview"
          label={t("Not judged")}
          value={unknown ?? null}
          tone={unknown ? "unknown" : "ok"}
          note={data?.partial ? t("the sweep did not reach the whole fleet") : t("every host answered")}
        />
      ),
      outcome: (
        <Card
          title={t("How the checks came out")}
          note={data ? t("Taken {when}.", { when: relativeTime(data.generated_at) }) : undefined}
          foot={data?.partial && data.partial_reason ? t(data.partial_reason) : undefined}
        >
          <Band segments={outcome} testId="outcome" />
        </Card>
      ),
      severity: (
        <Card title={t("By severity")} note={t("A finding counted once per host it was found on.")}>
          {data ? <Bars items={bySeverity} /> : <Empty>{t("Computing findings…")}</Empty>}
        </Card>
      ),
      worst: (
        <Card title={t("Where to start")} note={t("The hosts carrying the most findings.")}>
          {worst.length === 0
            ? <Empty>{data ? t("No host carries a finding.") : t("Computing findings…")}</Empty>
            : (
              <Bars items={worst.map(([id, one]) => ({
                label: <Link to={`/next/hosts/${id}/security`}>{one.hostname}</Link>,
                value: one.count,
                tone: "error" as Tone,
              }))} />
            )}
        </Card>
      ),
      checks: (
        <Card title={t("Checks")} note={t("One row per check, whatever it was found on.")} flush>
          <Table
            rows={[...checks].sort((a, b) => b.failed - a.failed || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))}
            keyOf={(one) => one.id}
            rowTestId={(one) => `check-${one.id}`}
            empty={view.isLoading ? t("Computing findings…") : t("No check ran over this fleet.")}
            columns={[
              { key: "title", head: t("Check"), cell: (one) => one.title },
              { key: "severity", head: t("Severity"), cell: (one) => (
                <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
              ) },
              { key: "failed", head: t("Failing"), num: true, cell: (one) => (
                one.failed > 0 ? <b className="fl-error">{one.failed}</b> : <span className="fl-faint">0</span>
              ) },
              { key: "unknown", head: t("Not judged"), num: true, minor: true, cell: (one) => (
                // Unknown is not passing: a check nobody could judge on a
                // host says nothing about that host.
                one.unknown > 0 ? <b className="fl-unknown">{one.unknown}</b> : <span className="fl-faint">0</span>
              ) },
              { key: "passed", head: t("Passing"), num: true, minor: true, cell: (one) => one.passed },
              { key: "fixable", head: t("Fixable"), num: true, cell: (one) => (
                one.fixable > 0 ? <Pill tone="warn">{one.fixable}</Pill> : <span className="fl-faint">—</span>
              ) },
              { key: "expected", head: t("Expected"), minor: true, tight: true, cell: (one) => (
                <code title={one.expected}>{one.expected}</code>
              ) },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

export const SECURITY_SCREEN = "next_security";

export const SECURITY: BoardEntry[] = [
  { key: "findings", title: "Findings", width: 4, height: 1 },
  { key: "fixable", title: "Fixable from here", width: 4, height: 1 },
  { key: "unjudged", title: "Not judged", width: 4, height: 1 },
  { key: "outcome", title: "How the checks came out", width: 5, height: 2 },
  { key: "severity", title: "By severity", width: 3, height: 2 },
  { key: "worst", title: "Where to start", width: 4, height: 2 },
  { key: "checks", title: "Checks", width: 12, height: 4 },
];
