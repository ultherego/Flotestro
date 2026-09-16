import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Fact, Facts, Foot, JobNotice, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets,
  countWhere, useHost, useModule,
} from "./shared";
import { capability } from "./modules";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

/**
 * One listening socket, with its reach as the host names it: on the
 * loopback, on one of the host's own addresses, or on every interface.
 * Neither says "visible from the internet" - that cannot be read off an
 * address - so the panel names the reach and leaves the judgement.
 */
type Listener = {
  protocol: string;
  address: string;
  port: number;
  process?: string;
  reach: "loopback" | "host-network" | "all-interfaces" | string;
};

/** Whether the socket stands outside the loopback: the same test the checks apply. */
function beyondLoopback(socket: Listener): boolean {
  return socket.reach !== "loopback" && socket.reach !== "";
}

/** The reach of a socket as a badge: every interface is the loud one. */
function ReachBadge({ reach }: { reach: string }) {
  const t = useT();
  if (reach === "all-interfaces") return <span className="badge warn">{t("every interface")}</span>;
  if (reach === "host-network") return <span className="badge">{t("host address")}</span>;
  if (reach === "loopback") return <span className="source">{t("loopback")}</span>;
  return <span className="badge unknown">{reach || t("unknown")}</span>;
}

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
  audit: {
    present: boolean;
    active?: boolean | null;
    // The rules the kernel knows and the rules written in files are two
    // numbers: a file written but not loaded describes an audit that does
    // not exist. A null is a read that failed, not an absence of rules.
    rules_loaded?: number | null;
    rules_configured?: number | null;
    reason?: string;
  };
  fips_enabled?: boolean | null;
  secure_boot?: boolean | null;
  secure_boot_reason?: string;
  lockdown?: string;
  listening?: Listener[];
  listening_known?: boolean;
  /** Whether the sockets carry their owner; without root the list is complete but nameless. */
  owners_known?: boolean;
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
  // A single operation of the module - the SELinux mode, the audit rules -
  // ordered through the same confirmation as everything else critical.
  const [operation, setOperation] = useState<Operation | null>(null);
  const [ordered, setOrdered] = useState<Job | null>(null);
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

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setOrdered(job);
      setOperation(null);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setOperation(null);
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
  const counts = report.data?.counts;
  const sockets = snapshot?.listening ?? [];
  const everyInterface = sockets.filter((socket) => socket.reach === "all-interfaces").length;
  const hostAddress = sockets.filter((socket) => socket.reach === "host-network").length;
  const loopback = sockets.filter((socket) => socket.reach === "loopback").length;
  // The failing findings by severity: what happens when nobody does
  // anything, read before the list. Unknown until the report is computed.
  const failing = report.data ? findings.filter((f) => f.applicable && !f.passed && !f.unknown) : undefined;
  const severities = ["high", "medium", "low", "info"];
  // The mode switch exists only where SELinux runs and the adapter writes:
  // the panel does not disable SELinux and does not turn it on, only
  // moves between enforcing and permissive.
  const selinux = snapshot?.mac?.system?.toLowerCase() === "selinux" && !!capability(host, "security.mac")?.available
    && !capability(host, "security.mac")?.read_only;
  const otherMode = snapshot?.mac?.mode === "enforcing" ? "permissive" : "enforcing";
  const auditWritable = !!snapshot?.audit?.present && !!capability(host, "security.audit")?.available
    && !capability(host, "security.audit")?.read_only;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Security")}
        description={t("The host reports facts; the panel judges them. Checks are versioned and run against inventory the host already sends, so a result can be repeated and two hosts are judged by the same check. Every fix maps to a typed operation of the module that owns the thing being fixed.")}
        actions={
          <button onClick={() => scan.mutate()} disabled={scan.isPending}>
            {t("Scan now")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />
      {ordered && <JobNotice job={ordered} hostID={host.id} />}

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Security state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <Widgets>
      {/* The counts of the findings decide whether the list is worth
          reading; while the report computes, the bar shows dashes rather
          than zeros. */}
      <Summary
        title={t("Checks")}
        description={t("Every versioned check, by its verdict on this host.")}
        span={8}
        segments={[
          { label: t("need action"), value: counts ? counts.failed ?? 0 : undefined, tone: "error" },
          { label: t("passed"), value: counts ? counts.passed ?? 0 : undefined, tone: "ok" },
          { label: t("unknown"), value: counts ? counts.unknown ?? 0 : undefined, tone: "unknown" },
          { label: t("not applicable"), value: counts ? counts.not_applicable ?? 0 : undefined, tone: "neutral" },
        ]}
      />
      <Section title={t("Need action")} span={4} description={t("By what happens when nobody does anything.")}>
        {failing ? (
          <Breakdown
            items={severities.map((severity) => ({
              label: severity,
              value: countWhere(failing, (f) => f.severity === severity) ?? 0,
              tone: severity === "high" ? "error" as const : severity === "info" ? "unknown" as const : "warn" as const,
            }))}
          />
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("Computing findings…")}</p>
        )}
        <p className="widget-subhead">{t("Listening sockets")}</p>
        {/* By reach, as the host names it; an unread list is a sentence,
            not a row of zeros. */}
        {snapshot?.listening_known ? (
          <Breakdown
            items={[
              { label: t("every interface"), value: everyInterface, tone: "warn" },
              { label: t("host address"), value: hostAddress, tone: "info" },
              { label: t("loopback"), value: loopback, tone: "ok" },
            ]}
          />
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("This host did not report its listening sockets.")}</p>
        )}
      </Section>

      {/* The protective facts and the open sockets are the two short
          answers; they share a row above the findings. */}
      <Section title={t("Protective state")} span={5} flush>
        <Facts>
          <Fact label={t("Mandatory access control")}>
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
            {selinux && (snapshot?.mac?.mode === "enforcing" || snapshot?.mac?.mode === "permissive") && (
              <>
                {" "}
                <button
                  type="button"
                  className="hm-link"
                  disabled={operation !== null}
                  onClick={() =>
                    setOperation({
                      action: "selinux.mode.set",
                      label: otherMode === "enforcing" ? t("Set SELinux to enforcing") : t("Set SELinux to permissive"),
                      description: otherMode === "enforcing"
                        ? t("SELinux on {host} starts enforcing its policy now and after reboot. A process the policy does not cover is denied from this moment.", { host: host.hostname })
                        : t("SELinux on {host} stops enforcing its policy, now and after reboot: denials are only logged. Coming back is another order, not a reboot.", { host: host.hostname }),
                      payload: { security: { mode: otherMode } },
                    })
                  }
                >
                  {otherMode === "enforcing" ? t("set enforcing…") : t("set permissive…")}
                </button>
              </>
            )}
          </Fact>
          <Fact label={t("Audit daemon")}>
            {!snapshot?.audit?.present
              ? snapshot?.audit?.reason || t("not installed")
              : <>
                  {snapshot.audit.active === true ? t("running") : snapshot.audit.active === false ? t("not running") : unknown}
                  {snapshot.audit.rules_loaded !== undefined && snapshot.audit.rules_loaded !== null
                    ? ` · ${t("{n} rules loaded", { n: snapshot.audit.rules_loaded })}`
                    : ""}
                  {snapshot.audit.rules_configured !== undefined && snapshot.audit.rules_configured !== null
                    && snapshot.audit.rules_configured !== snapshot.audit.rules_loaded && (
                      <span className="badge warn"> {t("{n} in files", { n: snapshot.audit.rules_configured })}</span>
                    )}
                  {auditWritable && (
                    <>
                      {" "}
                      <button
                        type="button"
                        className="hm-link"
                        disabled={operation !== null}
                        onClick={() =>
                          setOperation({
                            action: "security.audit.reload",
                            label: t("Reload the audit rules"),
                            description: t("auditd on {host} re-reads its rule files. Rules removed from the files stop; the daemon keeps running.", { host: host.hostname }),
                            payload: {},
                          })
                        }
                      >
                        {t("reload rules…")}
                      </button>
                    </>
                  )}
                </>}
          </Fact>
          <Fact label={t("Secure boot")}>
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
          </Fact>
          <Fact label={t("FIPS mode")}>{flag(snapshot?.fips_enabled)}</Fact>
          <Fact label={t("Kernel lockdown")}>{snapshot?.lockdown || unknown}</Fact>
        </Facts>
      </Section>

      <Section
        title={t("Listening sockets")}
        count={snapshot?.listening_known ? sockets.length : undefined}
        span={7}
        description={t("Every socket the host listens on, the ones beyond the loopback first. A socket on every interface is a way into this host for anyone who can see its network; the panel names the reach and does not rule what is visible from where.")}
        flush
      >
        {!snapshot?.listening_known ? (
          <Empty>{t("This host did not report its listening sockets.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Proto")}</th><th>{t("Address")}</th><th className="hm-num">{t("Port")}</th><th>{t("Process")}</th><th>{t("Reach")}</th></tr></thead>
            <tbody>
              {sockets
                .slice()
                .sort((a, b) => Number(beyondLoopback(b)) - Number(beyondLoopback(a)) || a.port - b.port)
                .map((socket, i) => (
                  <tr key={`${socket.protocol}-${socket.address}-${socket.port}-${i}`}>
                    <td>{socket.protocol}</td>
                    <td className="hm-mono">{socket.address}</td>
                    <td className="hm-num">{socket.port}</td>
                    <td className="hm-mono">
                      {socket.process || <span className="source">{snapshot.owners_known === false ? t("not readable") : "—"}</span>}
                    </td>
                    <td><ReachBadge reach={socket.reach} /></td>
                  </tr>
                ))}
            </tbody>
          </Table>
        )}
        {snapshot?.listening_known && snapshot.owners_known === false && (
          <Foot>{t("The owners of the sockets are not known: the agent could not read them without root.")}</Foot>
        )}
      </Section>

      <Section
        title={t("Findings")}
        count={report.data ? findings.length : undefined}
        span={12}
        tools={
          <span className="source">
            {report.data
              ? t("{failed} need action · {passed} passed · {unknown} unknown · {na} n/a", {
                  failed: report.data.counts.failed ?? 0, passed: report.data.counts.passed ?? 0,
                  unknown: report.data.counts.unknown ?? 0, na: report.data.counts.not_applicable ?? 0,
                })
              : "…"}
          </span>
        }
        flush
      >
        {!report.data ? (
          <Empty>{t("Computing findings…")}</Empty>
        ) : (
          <Table>
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
                    <span className="hm-primary">{finding.title}</span>
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
          </Table>
        )}
        <Foot>
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
          <span>
            {t("{n} of the findings that need action have an operation behind them", { n: fixable.length })}
          </span>
          {report.data?.generated_at && (
            <span title={t("The fingerprint of this set of findings; a remediation is bound to it and refused when the host changed meanwhile.") + ` ${report.data.plan_hash} (${t("canonical form v{n}", { n: report.data.plan_hash_version })})`}>
              {t("Findings computed")} <Time value={report.data.generated_at} /> · {t("fingerprint")}{" "}
              <span className="hm-mono">{report.data.plan_hash.slice(0, 12)}</span>
            </span>
          )}
        </Foot>
      </Section>

      </Widgets>

      <Message text={planMessage} />

      <Section
        title={t("Remediation plans")}
        count={(plans.data?.items ?? []).length}
        description={t("Steps run one after another: each is an ordinary job of the module that owns it, and the next one starts only once the previous succeeded. A step that needs a reboot ends the plan — what comes after a reboot has to be judged against the host that came back.")}
        flush
      >
        {!(plans.data?.items ?? []).length ? (
          <Empty>{t("No remediation has been planned on this host.")}</Empty>
        ) : (
          (plans.data?.items ?? []).map((plan) => (
            <div key={plan.id} className="hm-plan">
              <div className="hm-section-head">
                <strong className="hm-mono">{plan.id.slice(0, 8)}</strong>
                <span className={`badge ${plan.state === "succeeded" ? "ok" : plan.state === "running" ? "warn" : "error"}`}>
                  {plan.state}
                </span>
                <span className="source">
                  {plan.created_by} · <Time value={plan.created_at} />
                  {plan.stop_on_failure ? ` · ${t("stops on failure")}` : ` · ${t("continues after failure")}`}
                </span>
                {plan.state === "running" && (
                  <div className="hm-tools">
                    <button className="hm-danger" onClick={() => stop.mutate(plan.id)} disabled={stop.isPending}>
                      {t("Stop")}
                    </button>
                  </div>
                )}
              </div>
              <Table>
                <thead>
                  <tr><th className="hm-num">#</th><th>{t("Check")}</th><th>{t("Operation")}</th><th>{t("Lock")}</th><th>{t("Job")}</th><th>{t("State")}</th></tr>
                </thead>
                <tbody>
                  {(plan.steps ?? []).map((step) => (
                    <tr key={step.position}>
                      <td className="hm-num">{step.position}</td>
                      <td className="hm-mono">{step.check_id}</td>
                      <td>
                        <code>{step.action_type}</code>
                        {step.requires_reboot && <span className="badge warn"> {t("reboot")}</span>}
                      </td>
                      {/* The lock class says which host resource the step
                          reaches for - two steps of the same class do not run
                          at once. */}
                      <td>{step.lock_class || <span className="source">—</span>}</td>
                      <td className="hm-mono">{step.job_id ? step.job_id.slice(0, 8) : "—"}</td>
                      <td>
                        {step.state}
                        {step.reason && <div className="source">{step.reason}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          ))
        )}
      </Section>

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

      {operation && (
        <TargetConfirmation
          host={host}
          label={operation.label}
          description={operation.description}
          busy={order.isPending}
          onConfirm={(reason) => order.mutate({ action: operation.action, reason, payload: operation.payload })}
          onCancel={() => setOperation(null)}
        />
      )}
    </ModulePage>
  );
}

/** One operation of the module waiting for its confirmation. */
type Operation = { action: string; label: string; description: string; payload: Record<string, unknown> };
