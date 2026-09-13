import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader } from "../components/layout";
import { Breakdown, StatusBar, type WidgetTone } from "../components/widgets";
import { useT } from "../i18n";

type HostWithFinding = { host_id: string; hostname: string; observed: string; action?: string };

type Check = {
  check_id: string;
  title: string;
  severity: string;
  expected: string;
  failed: number;
  passed: number;
  unknown: number;
  not_applicable: number;
  fixable: number;
  hosts?: HostWithFinding[];
};

type View = { hosts: number; checks: Check[]; generated_at: string };

function severityBadge(severity: string, count: number) {
  if (count === 0) return <span className="badge ok">0</span>;
  return <span className={`badge ${severityTone(severity)}`}>{count}</span>;
}

/** The colour of a severity: high is an error, info is a note, the rest a warning. */
function severityTone(severity: string): WidgetTone {
  return severity === "high" ? "error" : severity === "info" ? "unknown" : "warn";
}

/** The order the severities are listed in, the gravest first. */
const SEVERITIES = ["high", "medium", "low", "info"];

/**
 * The fleet's compliance with the hardening profile.
 *
 * One bad setting on a hundred hosts is one problem, not a hundred - and
 * that only shows once the findings stand next to each other. The fix
 * however goes host by host: each one creates an ordinary job of the module
 * that owns the given thing.
 */
export function FleetSecurity() {
  const t = useT();
  const [expanded, setExpanded] = useState("");
  const { data, error } = useQuery({
    queryKey: ["security", "fleet"],
    queryFn: () => api.get<View>("/api/v1/security"),
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Computing findings…")}</Empty>;

  // The fleet-wide sums: a finding on a hundred hosts counts a hundred
  // times here, because that is how many jobs the fix takes.
  const sum = (key: "failed" | "passed" | "fixable" | "unknown" | "not_applicable") => data.checks.reduce((total, check) => total + check[key], 0);
  const needAction = sum("failed");
  const fixable = sum("fixable");
  const unknown = sum("unknown");

  // The findings by severity: the same sums as the bar, cut the other way.
  // A severity the profile does not use is still named, at zero.
  const bySeverity = SEVERITIES.map((severity) => ({
    severity,
    count: data.checks.filter((check) => check.severity === severity).reduce((total, check) => total + check.failed, 0),
  }));
  const otherSeverities = data.checks
    .filter((check) => !SEVERITIES.includes(check.severity))
    .reduce<Record<string, number>>((acc, check) => { acc[check.severity] = (acc[check.severity] ?? 0) + check.failed; return acc; }, {});

  // The hosts with the most findings, counted over the host lists the
  // checks carry. A check that carries no host list is counted in the
  // bar but not here, and the widget says when that leaves it blank.
  const byHost = new Map<string, { hostname: string; count: number }>();
  for (const check of data.checks) {
    for (const host of check.hosts ?? []) {
      const entry = byHost.get(host.host_id) ?? { hostname: host.hostname, count: 0 };
      entry.count += 1;
      byHost.set(host.host_id, entry);
    }
  }
  const worstHosts = [...byHost.entries()].sort((x, y) => y[1].count - x[1].count).slice(0, 8);

  return (
    <>
      <PageHeader
        title={t("Security")}
        description={t("Versioned checks over the facts hosts already report. One bad setting on a hundred hosts is one problem, not a hundred — but the fix still goes host by host, as a job of the module that owns it.")}
      />

      <div className="widgets">
        {/* The fleet-wide sums, one segment per verdict: a finding on a
            hundred hosts counts a hundred times, because that is how many
            jobs the fix takes. Fixable is a part of "need action", named
            because it is the part that takes no decision. */}
        <Card
          className="span-12"
          title={t("Findings")}
          description={`${t("{n} hosts", { n: data.hosts })} · ${t("{n} checks", { n: data.checks.length })}`}
        >
          <StatusBar segments={[
            { label: t("Need action"), value: needAction, tone: "error" },
            { label: t("Passed"), value: sum("passed"), tone: "ok" },
            { label: t("Unknown"), value: unknown, tone: "unknown" },
            { label: t("Not applicable"), value: sum("not_applicable"), tone: "neutral" },
            { label: t("Fixable"), value: fixable, tone: "info" },
          ]} />
        </Card>

        <Card
          className="span-8"
          flush
          footer={<p>{t("{n} hosts", { n: data.hosts })} · {t("computed")} <Time value={data.generated_at} /></p>}
        >
          <table>
            <thead>
              <tr>
                <th>{t("Check")}</th><th className="num">{t("Need action")}</th><th className="num">{t("Passed")}</th><th className="num">{t("Unknown")}</th><th className="num">{t("N/A")}</th><th>{t("Expected")}</th><th className="num">{t("Fixable")}</th>
              </tr>
            </thead>
            <tbody>
              {data.checks.map((check) => (
                <Fragment key={check.check_id}>
                  <tr>
                    <td>
                      <button
                        className="expander"
                        aria-expanded={expanded === check.check_id}
                        onClick={() =>
                          setExpanded((current) =>
                            current === check.check_id ? "" : check.check_id,
                          )
                        }
                        disabled={!check.failed}
                      >
                        {expanded === check.check_id ? "▾" : "▸"}
                      </button>
                      {check.title}
                      <div className="source mono">{check.check_id}</div>
                    </td>
                    <td className="num">{severityBadge(check.severity, check.failed)}</td>
                    <td className="num">{check.passed}</td>
                    {/* Unknown is not passed: a host that did not report the
                        fact is not a compliant host. */}
                    <td className="num">{check.unknown ? <span className="badge unknown">{check.unknown}</span> : 0}</td>
                    {/* A check that does not apply to the host enters neither
                        compliance nor non-compliance. */}
                    <td className="num">{check.not_applicable}</td>
                    <td className="mono">{check.expected}</td>
                    <td className="num">
                      {check.fixable}
                      {check.failed > check.fixable && (
                        <div className="source">
                          {t("{n} need a decision", { n: check.failed - check.fixable })}
                        </div>
                      )}
                    </td>
                  </tr>
                  {expanded === check.check_id &&
                    (check.hosts ?? []).map((host) => (
                      <tr key={`${check.check_id}-${host.host_id}`} className="detail-row">
                        <td colSpan={2}>
                          <Link to={`/hosts/${host.host_id}/security`}>{host.hostname}</Link>
                        </td>
                        <td colSpan={4} className="mono">{host.observed}</td>
                        <td>{host.action ? <code>{host.action}</code> : <span className="source">—</span>}</td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="span-4" title={t("By severity")} description={t("Findings that need action, by the severity of the check.")}>
          <div className="fp-tones">
            <Breakdown items={[
              ...bySeverity.map((row) => ({ label: row.severity, value: row.count, tone: severityTone(row.severity) })),
              ...Object.entries(otherSeverities).map(([severity, count]) => ({ label: severity, value: count, tone: severityTone(severity) })),
            ]} />
          </div>
          <h4 className="widget-subhead">{t("Hosts with most findings")}</h4>
          {worstHosts.length === 0 ? (
            <p className="fp-blank">
              {needAction > 0 ? t("The checks carry no host list.") : t("No host has a finding.")}
            </p>
          ) : (
            <div className="fp-links">
              <Breakdown tone="error" items={worstHosts.map(([hostId, entry]) => ({
                label: <Link to={`/hosts/${hostId}/security`}>{entry.hostname}</Link>,
                value: entry.count,
              }))} />
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
