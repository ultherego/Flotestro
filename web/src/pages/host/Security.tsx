import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Listener = {
  protocol: string;
  address: string;
  port: number;
  process?: string;
  exposed: boolean;
};

type Snapshot = {
  mac: {
    system?: string;
    mode?: string;
    configured_mode?: string;
    policy?: string;
    profiles_enforcing?: number | null;
    profiles_complain?: number | null;
    reason?: string;
  };
  audit: { present: boolean; active?: boolean | null; rules?: number | null; reason?: string };
  fips_enabled?: boolean | null;
  secure_boot?: boolean | null;
  secure_boot_reason?: string;
  lockdown?: string;
  listening?: Listener[];
  listening_known?: boolean;
  observed_at?: string;
  unavailable_reason?: string;
};

type Remediation = { action?: string; payload?: unknown; note?: string };

type Finding = {
  check_id: string;
  check_version: number;
  title: string;
  severity: string;
  rationale: string;
  applicable: boolean;
  passed: boolean;
  unknown: boolean;
  reason_code?: string;
  expected: string;
  observed: string;
  evidence?: string;
  module: string;
  revision?: string;
  observed_at?: string;
  remediation?: Remediation;
};

type Report = {
  findings: Finding[];
  plan_hash: string;
  plan_hash_version: number;
  generated_at: string;
  counts: Record<string, number>;
};

type PlanStep = {
  position: number;
  check_id: string;
  action_type: string;
  lock_class?: string;
  requires_reboot: boolean;
  job_id?: string;
  state: string;
  reason?: string;
};

type RemediationPlan = {
  id: string;
  plan_hash: string;
  reason: string;
  created_by: string;
  stop_on_failure: boolean;
  state: string;
  created_at: string;
  finished_at?: string;
  steps?: PlanStep[];
};

/** The severity says what happens when nobody does anything - not how hard the fix is. */
function SeverityBadge({ finding }: { finding: Finding }) {
  const t = useT();
  // "Not applicable" is a separate answer: a host without SELinux does not
  // fail a check that requires it, and does not pass it quietly either.
  if (!finding.applicable) return <span className="badge unknown">{t("n/a")}</span>;
  if (finding.unknown) return <span className="badge unknown">{t("unknown")}</span>;
  if (finding.passed) return <span className="badge ok">{t("passed")}</span>;
  const cls = finding.severity === "high" ? "error" : finding.severity === "info" ? "unknown" : "warn";
  return <span className={`badge ${cls}`}>{finding.severity}</span>;
}

/**
 * Security and hardening.
 *
 * The host reports facts, the panel judges them. The checks are versioned
 * and computed from what is in the inventory anyway, so the result can be
 * repeated and two hosts are judged by the same check. A fix is not a
 * separate mechanism: each maps to a typed operation of the module that
 * owns the given thing.
 */
export function Security() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "security");
  const [selected, setSelected] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const [planMessage, setPlanMessage] = useState("");
  const [intent, setIntent] = useState<{ label: string; description: string } | null>(null);
  const unknown = <span className="badge unknown">{t("unknown")}</span>;
  const flag = (value?: boolean | null) =>
    value === undefined || value === null ? unknown : value ? t("yes") : t("no");

  const report = useQuery({
    queryKey: ["security", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/security`),
  });

  const scan = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "security.scan",
        reason: "refresh of the host's protective state",
        payload: {},
      }),
    onSuccess: (job) => {
      setMessage(t("Job {id} has been queued; findings refresh once it reports back.", { id: job.id.slice(0, 8) }));
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // Remediation plans advance on their own, so the list refreshes itself -
  // otherwise the operator would look at a state from a few steps ago.
  const plans = useQuery({
    queryKey: ["remediation", host.id],
    queryFn: () => api.get<{ items: RemediationPlan[] }>(`/api/v1/hosts/${host.id}/security/remediation`),
    refetchInterval: 5000,
  });
  const running = (plans.data?.items ?? []).find((plan) => plan.state === "running");

  const remediate = useMutation({
    mutationFn: (reason: string) =>
      api.post<{ plan: RemediationPlan; skipped: Record<string, string> }>(
        `/api/v1/hosts/${host.id}/security/remediation`,
        { plan_hash: report.data?.plan_hash, check_ids: selected, reason },
      ),
    onSuccess: (response) => {
      const skipped = Object.entries(response.skipped ?? {});
      setPlanMessage(
        skipped.length
          ? t("Plan {id} started; skipped: {skipped}", {
              id: response.plan.id.slice(0, 8),
              skipped: skipped.map(([id, reason]) => `${id} (${reason})`).join("; "),
            })
          : t("Plan {id} started.", { id: response.plan.id.slice(0, 8) }),
      );
      setSelected([]);
      setIntent(null);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["remediation", host.id] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setIntent(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const stop = useMutation({
    mutationFn: (planID: string) =>
      api.post(`/api/v1/hosts/${host.id}/security/remediation/${planID}/stop`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["remediation", host.id] }),
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const findings = report.data?.findings ?? [];
  const fixable = findings.filter((f) => !f.passed && !f.unknown && f.remediation?.action);

  return (
    <>
      <p className="subtitle">
        {t("The host reports facts; the panel judges them. Checks are versioned and run against inventory the host already sends, so a result can be repeated and two hosts are judged by the same check. Every fix maps to a typed operation of the module that owns the thing being fixed.")}
      </p>

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Security state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr>
            <th>{t("Mandatory access control")}</th>
            <td>
              {snapshot?.mac?.system
                ? `${snapshot.mac.system}: ${snapshot.mac.mode || t("unknown")}`
                : snapshot?.mac?.reason || unknown}
              {snapshot?.mac?.policy && <span className="source"> · {snapshot.mac.policy}</span>}
              {/* The running mode and the configured mode may differ - and
                  that is the whole difference between protection and
                  protection until the reboot. */}
              {snapshot?.mac?.configured_mode &&
                snapshot.mac.configured_mode !== snapshot.mac.mode && (
                  <span className="badge warn"> {t("after reboot: {mode}", { mode: snapshot.mac.configured_mode })}</span>
                )}
              {snapshot?.mac?.profiles_enforcing !== undefined &&
                snapshot?.mac?.profiles_enforcing !== null && (
                  <span className="source">
                    {" "}· {t("{enforcing} enforcing, {complaining} complaining", {
                      enforcing: snapshot.mac.profiles_enforcing, complaining: snapshot.mac.profiles_complain ?? 0,
                    })}
                  </span>
                )}
            </td>
          </tr>
          <tr>
            <th>{t("Audit daemon")}</th>
            <td>
              {!snapshot?.audit?.present
                ? snapshot?.audit?.reason || t("not installed")
                : <>
                    {flag(snapshot.audit.active)}
                    {snapshot.audit.rules !== undefined && snapshot.audit.rules !== null
                      ? ` · ${t("{n} rules", { n: snapshot.audit.rules })}`
                      : ""}
                  </>}
            </td>
          </tr>
          <tr>
            <th>{t("Secure boot")}</th>
            <td>
              {snapshot?.secure_boot === undefined || snapshot?.secure_boot === null ? (
                <>
                  {unknown}
                  {snapshot?.secure_boot_reason && (
                    <span className="source"> · {snapshot.secure_boot_reason}</span>
                  )}
                </>
              ) : (
                flag(snapshot.secure_boot)
              )}
            </td>
          </tr>
          <tr><th>{t("FIPS mode")}</th><td>{flag(snapshot?.fips_enabled)}</td></tr>
          <tr><th>{t("Kernel lockdown")}</th><td>{snapshot?.lockdown || unknown}</td></tr>
        </tbody>
      </table>

      <h2>{t("Exposed services")}</h2>
      <p className="subtitle">
        {t("Sockets listening beyond the loopback interface. Each one is a way into this host for anyone who can see its network.")}
      </p>
      {!snapshot?.listening_known ? (
        <Empty>{t("This host did not report its listening sockets.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Proto")}</th><th>{t("Address")}</th><th>{t("Port")}</th><th>{t("Process")}</th><th>{t("Reach")}</th></tr></thead>
          <tbody>
            {(snapshot.listening ?? [])
              .slice()
              .sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port)
              .map((socket, i) => (
                <tr key={`${socket.protocol}-${socket.address}-${socket.port}-${i}`}>
                  <td>{socket.protocol}</td>
                  <td>{socket.address}</td>
                  <td>{socket.port}</td>
                  <td>{socket.process || "—"}</td>
                  <td>
                    {socket.exposed ? (
                      <span className="badge warn">{t("exposed")}</span>
                    ) : (
                      <span className="source">loopback</span>
                    )}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      )}

      <h2>{t("Findings")}</h2>
      <div className="filters">
        <button onClick={() => scan.mutate()} disabled={scan.isPending}>
          {t("Scan now")}
        </button>
        <span className="source">
          {report.data
            ? t("{failed} need action · {passed} passed · {unknown} unknown · {na} n/a", {
                failed: report.data.counts.failed ?? 0, passed: report.data.counts.passed ?? 0,
                unknown: report.data.counts.unknown ?? 0, na: report.data.counts.not_applicable ?? 0,
              })
            : "…"}
        </span>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {!report.data ? (
        <Empty>{t("Computing findings…")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th></th><th>{t("Check")}</th><th>{t("State")}</th><th>{t("Expected")}</th><th>{t("Observed")}</th><th>{t("Fix")}</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.check_id}>
                <td>
                  {/* Only a finding with a remediation operation can be
                      ticked. The rest needs a decision the panel will not
                      make for the operator. */}
                  <input
                    type="checkbox"
                    disabled={
                      !finding.remediation?.action ||
                      !finding.applicable ||
                      finding.passed ||
                      finding.unknown ||
                      Boolean(running)
                    }
                    checked={selected.includes(finding.check_id)}
                    onChange={(e) =>
                      setSelected((list) =>
                        e.target.checked
                          ? [...list, finding.check_id]
                          : list.filter((id) => id !== finding.check_id),
                      )
                    }
                  />
                </td>
                <td>
                  {finding.title}
                  <div className="source">
                    {finding.check_id} v{finding.check_version} · {finding.rationale}
                  </div>
                </td>
                <td><SeverityBadge finding={finding} /></td>
                <td>{finding.expected}</td>
                <td>
                  {finding.observed}
                  {/* The reason code says what to do about it: wait for a
                      read, fix the agent or grant permissions. */}
                  {finding.reason_code && (
                    <div className="source">{t("reason")}: {finding.reason_code}</div>
                  )}
                  {finding.evidence && <div className="source">{finding.evidence}</div>}
                  {/* The evidence carries the module and the revision the
                      result came from. */}
                  {finding.revision && (
                    <div className="source">
                      {finding.module} @ {finding.revision.slice(0, 8)}
                      {finding.observed_at && (
                        <>
                          {" · "}
                          <Time value={finding.observed_at} />
                        </>
                      )}
                    </div>
                  )}
                </td>
                <td>
                  {finding.remediation?.action ? (
                    <>
                      <code>{finding.remediation.action}</code>
                      {finding.remediation.note && (
                        <div className="source">{finding.remediation.note}</div>
                      )}
                    </>
                  ) : (
                    <span className="source">{finding.remediation?.note || "—"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="filters">
        <button
          onClick={() =>
            setIntent({
              label: t("Apply remediation"),
              description: t("{n} finding(s) on {host} will be fixed step by step, each step an ordinary job of the module that owns it, with its own permissions and approval. The next step starts only once the previous one succeeded, and the plan stops at the first failure. It is bound to the state you are looking at: if the host changed meanwhile, the request is refused.", {
                n: selected.length, host: host.hostname,
              }),
            })
          }
          disabled={!selected.length || remediate.isPending || Boolean(running)}
          title={running ? t("a remediation plan is already running on this host") : undefined}
        >
          {t("Fix selected ({n})", { n: selected.length })}
        </button>
        <span className="source">
          {t("{n} of the findings that need action have an operation behind them", { n: fixable.length })}
        </span>
      </div>

      {planMessage && <p className="source" style={{ marginBottom: 12 }}>{planMessage}</p>}

      <h2>{t("Remediation plans")}</h2>
      <p className="subtitle">
        {t("Steps run one after another: each is an ordinary job of the module that owns it, and the next one starts only once the previous succeeded. A step that needs a reboot ends the plan — what comes after a reboot has to be judged against the host that came back.")}
      </p>
      {!(plans.data?.items ?? []).length ? (
        <Empty>{t("No remediation has been planned on this host.")}</Empty>
      ) : (
        (plans.data?.items ?? []).map((plan) => (
          <div key={plan.id} style={{ marginBottom: 16 }}>
            <div className="filters">
              <strong>{plan.id.slice(0, 8)}</strong>
              <span className={`badge ${plan.state === "succeeded" ? "ok" : plan.state === "running" ? "warn" : "error"}`}>
                {plan.state}
              </span>
              <span className="source">
                {plan.created_by} · <Time value={plan.created_at} />
                {plan.stop_on_failure ? ` · ${t("stops on failure")}` : ` · ${t("continues after failure")}`}
              </span>
              {plan.state === "running" && (
                <button className="secondary" onClick={() => stop.mutate(plan.id)} disabled={stop.isPending}>
                  {t("Stop")}
                </button>
              )}
            </div>
            <table>
              <thead>
                <tr><th>#</th><th>{t("Check")}</th><th>{t("Operation")}</th><th>{t("Lock")}</th><th>{t("Job")}</th><th>{t("State")}</th></tr>
              </thead>
              <tbody>
                {(plan.steps ?? []).map((step) => (
                  <tr key={step.position}>
                    <td>{step.position}</td>
                    <td>{step.check_id}</td>
                    <td>
                      <code>{step.action_type}</code>
                      {step.requires_reboot && <span className="badge warn"> {t("reboot")}</span>}
                    </td>
                    {/* The lock class says which host resource the step
                        reaches for - two steps of the same class do not run
                        at once. */}
                    <td>{step.lock_class || <span className="source">—</span>}</td>
                    <td>{step.job_id ? step.job_id.slice(0, 8) : "—"}</td>
                    <td>
                      {step.state}
                      {step.reason && <div className="source">{step.reason}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))
      )}

      <ModuleFreshness fragment={module.data} />
      {report.data?.generated_at && (
        <p className="source">
          {t("Findings computed")} <Time value={report.data.generated_at} /> · {t("plan")}{" "}
          {report.data.plan_hash.slice(0, 12)} ({t("canonical form v{n}", { n: report.data.plan_hash_version })})
        </p>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={remediate.isPending}
          onConfirm={(reason) => remediate.mutate(reason)}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}
