import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader, Stat, StatGrid } from "../components/layout";
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
  const cls = severity === "high" ? "error" : severity === "info" ? "unknown" : "warn";
  return <span className={`badge ${cls}`}>{count}</span>;
}

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
  const sum = (key: "failed" | "fixable" | "unknown") => data.checks.reduce((total, check) => total + check[key], 0);
  const needAction = sum("failed");
  const fixable = sum("fixable");
  const unknown = sum("unknown");

  return (
    <>
      <PageHeader
        title={t("Security")}
        description={t("Versioned checks over the facts hosts already report. One bad setting on a hundred hosts is one problem, not a hundred — but the fix still goes host by host, as a job of the module that owns it.")}
      />

      <StatGrid>
        <Stat label={t("Hosts")} value={data.hosts} />
        <Stat label={t("Checks")} value={data.checks.length} />
        <Stat label={t("Need action")} value={needAction} tone={needAction > 0 ? "error" : "ok"} />
        <Stat label={t("Fixable")} value={fixable} />
        <Stat label={t("Unknown")} value={unknown} tone={unknown > 0 ? "unknown" : undefined} />
      </StatGrid>

      <Card
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
    </>
  );
}
