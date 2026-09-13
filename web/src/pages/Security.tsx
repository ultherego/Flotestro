import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
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

  return (
    <>
      <h1>{t("Security")}</h1>
      <p className="subtitle">
        {t("Versioned checks over the facts hosts already report. One bad setting on a hundred hosts is one problem, not a hundred — but the fix still goes host by host, as a job of the module that owns it.")}
      </p>

      <table>
        <thead>
          <tr>
            <th>{t("Check")}</th><th>{t("Need action")}</th><th>{t("Passed")}</th><th>{t("Unknown")}</th><th>{t("N/A")}</th><th>{t("Expected")}</th><th>{t("Fixable")}</th>
          </tr>
        </thead>
        <tbody>
          {data.checks.map((check) => (
            <Fragment key={check.check_id}>
              <tr>
                <td>
                  <button
                    className="secondary"
                    onClick={() =>
                      setExpanded((current) =>
                        current === check.check_id ? "" : check.check_id,
                      )
                    }
                    disabled={!check.failed}
                  >
                    {expanded === check.check_id ? "▾" : "▸"}
                  </button>{" "}
                  {check.title}
                  <div className="source">{check.check_id}</div>
                </td>
                <td>{severityBadge(check.severity, check.failed)}</td>
                <td>{check.passed}</td>
                {/* Unknown is not passed: a host that did not report the
                    fact is not a compliant host. */}
                <td>{check.unknown ? <span className="badge unknown">{check.unknown}</span> : 0}</td>
                {/* A check that does not apply to the host enters neither
                    compliance nor non-compliance. */}
                <td>{check.not_applicable}</td>
                <td>{check.expected}</td>
                <td>
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
                  <tr key={`${check.check_id}-${host.host_id}`}>
                    <td colSpan={2}>
                      <Link to={`/hosts/${host.host_id}/security`}>{host.hostname}</Link>
                    </td>
                    <td colSpan={4}>{host.observed}</td>
                    <td>{host.action ? <code>{host.action}</code> : <span className="source">—</span>}</td>
                  </tr>
                ))}
            </Fragment>
          ))}
        </tbody>
      </table>

      <p className="source">
        {t("{n} hosts", { n: data.hosts })} · {t("computed")} <Time value={data.generated_at} />
      </p>
    </>
  );
}
