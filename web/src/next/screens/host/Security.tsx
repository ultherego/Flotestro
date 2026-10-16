import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import { capability } from "../../../lib/modules";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { stateName } from "../../../components/ui";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Bars, Bones, Button, Card, Empty, Fact, Facts, Field, Fields, HeadActions,
  Modal, Note, Pill, Table, type Segment, type Tone,
} from "../../kit";

/**
 * What protects this machine, and what does not.
 *
 * The host reports facts; the panel judges them with versioned checks, so a
 * result can be repeated and two hosts are judged by the same check. A
 * check that could not be judged is *unknown* and says which side has to
 * move - the host, the agent or the operator. It is never counted as a
 * pass, because a host nobody could read is not a host with nothing wrong.
 */

/** One listening socket, with its reach as the host names it. */
type Listener = {
  protocol: string;
  address: string;
  port: number;
  process?: string;
  reach: "loopback" | "host-network" | "all-interfaces" | string;
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
  audit: {
    present: boolean;
    active?: boolean | null;
    // The rules the kernel knows and the rules written in files are two
    // numbers: a file written but not loaded describes an audit that does
    // not exist.
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

/** One operation of the module waiting for its confirmation. */
type Operation = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The changes this module offers; when every one is refused, it says so once. */
const SECURITY_CHANGES = ["selinux.mode.set", "security.audit.reload", "security.remediate"];

/** The shortest reason the API takes for a critical operation. */
const MIN_REASON = 8;

const SEVERITIES = ["high", "medium", "low", "info"];

/** The severity in the operator's language; the report speaks in codes. */
export function severityLabel(severity: string, t: (key: string) => string): string {
  const names: Record<string, string> = { high: t("high"), medium: t("medium"), low: t("low"), info: t("info") };
  return names[severity] ?? severity;
}

/**
 * Why a check could not be judged, as a sentence: the code says which side
 * has to move, and the sentence says it in words.
 */
export function reasonText(code: string, t: (key: string) => string): string {
  const names: Record<string, string> = {
    fact_missing: t("the host did not report this fact"),
    read_failed: t("the agent could not read this on the host"),
    unsupported_system: t("this system has nothing to check here"),
    module_unread: t("the module this check reads has not been read yet"),
    permission_denied: t("the agent lacks the permission to read this"),
    inventory_stale: t("the read this check rests on is too old to judge from"),
    parse_error: t("the host's files were read but not understood in full"),
    checker_missing: t("the host has not got the tool this proof needs"),
    checker_failed: t("the tool this proof needs returned no result on the host"),
  };
  return names[code] ?? code;
}

/** Whether the socket stands outside the loopback: the same test the checks apply. */
function beyondLoopback(socket: Listener): boolean {
  return socket.reach !== "loopback" && socket.reach !== "";
}

/** The reach of a socket as a badge: every interface is the loud one. */
function ReachBadge({ reach }: { reach: string }) {
  const t = useT();
  if (reach === "all-interfaces") return <Pill tone="warn">{t("every interface")}</Pill>;
  if (reach === "host-network") return <Pill tone="neutral">{t("host address")}</Pill>;
  if (reach === "loopback") return <Note>{t("loopback")}</Note>;
  return <Pill tone="unknown">{reach || t("unknown")}</Pill>;
}

/** The severity says what happens when nobody does anything - not how hard the fix is. */
function SeverityBadge({ finding }: { finding: Finding }) {
  const t = useT();
  // "Not applicable" is a separate answer: a host without SELinux does not
  // fail a check that requires it, and does not pass it quietly either.
  if (!finding.applicable) return <Pill tone="unknown">{t("n/a")}</Pill>;
  if (finding.unknown) return <Pill tone="unknown">{t("unknown")}</Pill>;
  if (finding.passed) return <Pill tone="ok">{t("passed")}</Pill>;
  const tone: Tone = finding.severity === "high" ? "error" : finding.severity === "info" ? "unknown" : "warn";
  return <Pill tone={tone}>{severityLabel(finding.severity, t)}</Pill>;
}

/** The state of a plan or of one of its steps. */
function planTone(state: string): Tone {
  if (["succeeded", "completed", "no_change"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired", "stopped", "plan_failed"].includes(state)) return "error";
  if (["unknown", "skipped", "ineligible"].includes(state)) return "unknown";
  if (state === "running") return "info";
  return "warn";
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

/**
 * The confirmation of an operation that changes what protects the machine.
 * The reason goes into the trail and the hostname is typed out, so the
 * operator approves a specific machine rather than the one they think is open.
 */
function Confirm({ host, title, children, label, busy, onConfirm, onClose, testId }: {
  host: Host;
  title: string;
  children: ReactNode;
  label: string;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onClose: () => void;
  testId: string;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ready = reason.trim().length >= MIN_REASON && typed === host.hostname;
  return (
    <Modal
      title={title}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</Button>
          <Button kind="danger" disabled={!ready || busy} testId={testId} onClick={() => onConfirm(reason.trim())}>
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{children}</Note>
      <Facts>
        <Fact label={t("Target")}>
          {host.hostname} · {host.management_address || t("address unknown")} · {host.site} / {host.environment}
        </Fact>
      </Facts>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid={`${testId}-reason`} />
        </Field>
        <Field label={t("Type the hostname to confirm: {name}", { name: host.hostname })} wide>
          <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid={`${testId}-typed`} />
        </Field>
      </Fields>
    </Modal>
  );
}

/* ------------------------------------------------------------ the module */

export function Security({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const [planMessage, setPlanMessage] = useState("");
  const [intent, setIntent] = useState<{ label: string; description: string } | null>(null);
  // A single operation of the module - the SELinux mode, the audit rules -
  // ordered through the same confirmation as everything else critical.
  const [operation, setOperation] = useState<Operation | null>(null);
  const [ordered, setOrdered] = useState<Job | null>(null);

  const module = useQuery({
    queryKey: ["inventory", host.id, "security"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/security`),
    retry: false,
  });
  const report = useQuery({
    queryKey: ["security", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/security`),
  });
  // Remediation plans advance on their own, so the list refreshes itself -
  // otherwise the operator would look at a state from a few steps ago.
  const plans = useQuery({
    queryKey: ["remediation", host.id],
    queryFn: () => api.get<{ items: RemediationPlan[] }>(`/api/v1/hosts/${host.id}/security/remediation`),
    refetchInterval: 5000,
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
    mutationFn: (body: Record<string, unknown>) => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
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
    mutationFn: (planID: string) => api.post(`/api/v1/hosts/${host.id}/security/remediation/${planID}/stop`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["remediation", host.id] }),
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const findings = report.data?.findings ?? [];
  const fixable = findings.filter((one) => !one.passed && !one.unknown && one.remediation?.action);
  const counts = report.data?.counts;
  const sockets = snapshot?.listening ?? [];
  const running = (plans.data?.items ?? []).find((plan) => plan.state === "running");
  // The failing findings by severity: what happens when nobody does
  // anything, read before the list. Unknown until the report is computed.
  const failing = report.data ? findings.filter((one) => one.applicable && !one.passed && !one.unknown) : undefined;
  // Sudoers files the host's own checker refuses mean sudo loads none of
  // them: the grants the panel lists elsewhere are not the policy in force.
  const sudoersRefused = findings.find(
    (one) => one.check_id === "sudo.syntax_valid" && one.applicable && !one.passed && !one.unknown,
  );
  // The mode switch exists only where SELinux runs and the adapter writes:
  // the panel does not disable SELinux and does not turn it on, only moves
  // between enforcing and permissive.
  const selinux = snapshot?.mac?.system?.toLowerCase() === "selinux"
    && !!capability(host, "security.mac")?.available
    && !capability(host, "security.mac")?.read_only;
  const otherMode = snapshot?.mac?.mode === "enforcing" ? "permissive" : "enforcing";
  const auditWritable = !!snapshot?.audit?.present
    && !!capability(host, "security.audit")?.available
    && !capability(host, "security.audit")?.read_only;

  const checks: Segment[] = [
    { label: t("need action"), value: counts ? counts.failed ?? 0 : undefined, tone: "error" },
    { label: t("passed"), value: counts ? counts.passed ?? 0 : undefined, tone: "ok" },
    { label: t("unknown"), value: counts ? counts.unknown ?? 0 : undefined, tone: "unknown" },
    { label: t("not applicable"), value: counts ? counts.not_applicable ?? 0 : undefined, tone: "neutral" },
  ];

  return (
    <>
      <HeadActions>
        <Guard action="security.scan" host={host.id} explain>
          <Button kind="quiet" onClick={() => scan.mutate()} disabled={scan.isPending} testId="scan">
            {t("Scan now")}
          </Button>
        </Guard>
      </HeadActions>

      <ReadOnlyNotice host={host.id} actions={SECURITY_CHANGES} />
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">{t("Security state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</Banner>
      )}
      {sudoersRefused && (
        <Banner tone="error">
          {t("The host's own checker refuses the sudoers files, so sudo loads none of them: {observed}", { observed: sudoersRefused.observed })}
          {sudoersRefused.evidence ? ` ${sudoersRefused.evidence}` : ""}
        </Banner>
      )}
      {message && <Banner tone="error">{message}</Banner>}
      {planMessage && <Banner tone="info">{planMessage}</Banner>}
      {ordered && (
        // The job it names is one click away, and so is the list of this
        // host's jobs: "waiting for approval" is a sentence to act on.
        <Banner
          tone="info"
          actions={<Link to={`/next/hosts/${host.id}/jobs`}>{t("See all jobs")}</Link>}
        >
          {(ordered.requires_approval
            ? t("Job {id} is waiting for approval.")
            : t("Job {id} has been queued.")).split("{id}")[0]}
          <Link to={`/next/jobs/${ordered.id}`}>{ordered.id.slice(0, 8)}</Link>
          {(ordered.requires_approval
            ? t("Job {id} is waiting for approval.")
            : t("Job {id} has been queued.")).split("{id}")[1] ?? ""}
        </Banner>
      )}

      <Board screen="next_host_security" catalogue={HOST_SECURITY} drawn={{
        checks: (
          <Card
            title={t("Checks")}
            note={t("Every versioned check, by its verdict on this host.")}
            foot={module.data
              ? t("Source: {source}, revision {revision}, observed {when}", {
                  source: module.data.source,
                  revision: module.data.revision.slice(0, 12),
                  when: relativeTime(module.data.observed_at),
                })
              : undefined}
          >
            {/* While the report computes, the band shows dashes rather than
                zeros: nothing counted is not nothing wrong. */}
            <Band segments={checks} testId="check-counts" />
          </Card>
        ),
        need: (
          <Card title={t("Need action")} note={t("By what happens when nobody does anything.")}>
            {failing === undefined ? <Bones rows={4} /> : (
              <Bars items={SEVERITIES.map((severity) => ({
                label: severityLabel(severity, t),
                value: failing.filter((one) => one.severity === severity).length,
                tone: (severity === "high" ? "error" : severity === "info" ? "unknown" : "warn") as Tone,
              }))} />
            )}
          </Card>
        ),
        reach: (
          <Card title={t("Where the host listens")} note={t("By reach, as the host names it.")}>
            {snapshot?.listening_known ? (
              <Bars items={[
                { label: t("every interface"), value: sockets.filter((one) => one.reach === "all-interfaces").length, tone: "warn" as Tone },
                { label: t("host address"), value: sockets.filter((one) => one.reach === "host-network").length, tone: "accent" as Tone },
                { label: t("loopback"), value: sockets.filter((one) => one.reach === "loopback").length, tone: "ok" as Tone },
              ]} />
            ) : (
              <Empty icon="network">{t("This host did not report its listening sockets.")}</Empty>
            )}
          </Card>
        ),
        state: (
          <Card title={t("Protective state")}>
            <Facts>
              <Fact label={t("Mandatory access control")}>
                {snapshot?.mac?.system
                  ? `${snapshot.mac.system}: ${snapshot.mac.mode || t("unknown")}`
                  : snapshot?.mac?.reason || <Pill tone="unknown">{t("unknown")}</Pill>}
                {snapshot?.mac?.policy && <Note>{snapshot.mac.policy}</Note>}
                {/* The running mode and the configured mode may differ - and
                    that is the whole difference between protection and
                    protection until the reboot. */}
                {snapshot?.mac?.configured_mode && snapshot.mac.configured_mode !== snapshot.mac.mode && (
                  <> <Pill tone="warn">{t("after reboot: {mode}", { mode: snapshot.mac.configured_mode })}</Pill></>
                )}
                {snapshot?.mac?.profiles_enforcing !== undefined && snapshot?.mac?.profiles_enforcing !== null && (
                  <Note>
                    {t("{enforcing} enforcing, {complaining} complaining", {
                      enforcing: snapshot.mac.profiles_enforcing,
                      complaining: snapshot.mac.profiles_complain ?? 0,
                    })}
                  </Note>
                )}
                {selinux && (snapshot?.mac?.mode === "enforcing" || snapshot?.mac?.mode === "permissive") && (
                  <Guard action="selinux.mode.set" host={host.id}>
                    <Button
                      kind="word"
                      disabled={operation !== null}
                      testId="selinux-mode"
                      onClick={() => setOperation({
                        action: "selinux.mode.set",
                        label: otherMode === "enforcing" ? t("Set SELinux to enforcing") : t("Set SELinux to permissive"),
                        description: otherMode === "enforcing"
                          ? t("SELinux on {host} starts enforcing its policy now and after reboot. A process the policy does not cover is denied from this moment.", { host: host.hostname })
                          : t("SELinux on {host} stops enforcing its policy, now and after reboot: denials are only logged. Coming back is another order, not a reboot.", { host: host.hostname }),
                        payload: { security: { mode: otherMode } },
                      })}
                    >
                      {otherMode === "enforcing" ? t("set enforcing…") : t("set permissive…")}
                    </Button>
                  </Guard>
                )}
              </Fact>
              <Fact label={t("Audit daemon")}>
                {!snapshot?.audit?.present
                  ? snapshot?.audit?.reason || t("not installed")
                  : (
                    <>
                      {snapshot.audit.active === true
                        ? t("running")
                        : snapshot.audit.active === false
                          ? t("not running")
                          : <Pill tone="unknown">{t("unknown")}</Pill>}
                      {snapshot.audit.rules_loaded !== undefined && snapshot.audit.rules_loaded !== null
                        ? ` · ${t("{n} rules loaded", { n: snapshot.audit.rules_loaded })}`
                        : ""}
                      {snapshot.audit.rules_configured !== undefined && snapshot.audit.rules_configured !== null
                        && snapshot.audit.rules_configured !== snapshot.audit.rules_loaded && (
                          <> <Pill tone="warn">{t("{n} in files", { n: snapshot.audit.rules_configured })}</Pill></>
                        )}
                      {auditWritable && (
                        <Guard action="security.audit.reload" host={host.id}>
                          <Button
                            kind="word"
                            disabled={operation !== null}
                            testId="audit-reload"
                            onClick={() => setOperation({
                              action: "security.audit.reload",
                              label: t("Reload the audit rules"),
                              description: t("auditd on {host} re-reads its rule files. Rules removed from the files stop; the daemon keeps running.", { host: host.hostname }),
                              payload: {},
                            })}
                          >
                            {t("reload rules…")}
                          </Button>
                        </Guard>
                      )}
                    </>
                  )}
              </Fact>
              <Fact label={t("Secure boot")}>
                {snapshot?.secure_boot === undefined || snapshot?.secure_boot === null ? (
                  <>
                    <Pill tone="unknown">{t("unknown")}</Pill>
                    {snapshot?.secure_boot_reason && <Note>{snapshot.secure_boot_reason}</Note>}
                  </>
                ) : snapshot.secure_boot ? t("yes") : t("no")}
              </Fact>
              <Fact label={t("FIPS mode")}>
                {snapshot?.fips_enabled === undefined || snapshot?.fips_enabled === null
                  ? <Pill tone="unknown">{t("unknown")}</Pill>
                  : snapshot.fips_enabled ? t("yes") : t("no")}
              </Fact>
              <Fact label={t("Kernel lockdown")}>
                {snapshot?.lockdown || <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
            </Facts>
          </Card>
        ),
        sockets: (
          <Card
            title={t("Listening sockets")}
            note={t("Every socket the host listens on, the ones beyond the loopback first. A socket on every interface is a way into this host for anyone who can see its network; the panel names the reach and does not rule what is visible from where.")}
            foot={snapshot?.listening_known && snapshot.owners_known === false
              ? t("The owners of the sockets are not known: the agent could not read them without root.")
              : undefined}
            flush
          >
            {!snapshot?.listening_known ? (
              <Empty icon="network">{t("This host did not report its listening sockets.")}</Empty>
            ) : (
              <Table
                rows={sockets.slice().sort((a, b) =>
                  Number(beyondLoopback(b)) - Number(beyondLoopback(a)) || a.port - b.port)}
                keyOf={(socket, index) => `${socket.protocol}-${socket.address}-${socket.port}-${index}`}
                testId="sockets"
                columns={[
                  { key: "proto", head: t("Proto"), cell: (socket) => socket.protocol },
                  { key: "address", head: t("Address"), tight: true, cell: (socket) => socket.address },
                  { key: "port", head: t("Port"), num: true, cell: (socket) => socket.port },
                  { key: "process", head: t("Process"), tight: true, cell: (socket) =>
                    socket.process || <Note>{snapshot.owners_known === false ? t("not readable") : "—"}</Note> },
                  { key: "reach", head: t("Reach"), cell: (socket) => <ReachBadge reach={socket.reach} /> },
                ]}
              />
            )}
          </Card>
        ),
        findings: (
          <Card
            title={t("Findings")}
            note={report.data
              ? t("{failed} need action · {passed} passed · {unknown} unknown · {na} n/a", {
                  failed: report.data.counts.failed ?? 0,
                  passed: report.data.counts.passed ?? 0,
                  unknown: report.data.counts.unknown ?? 0,
                  na: report.data.counts.not_applicable ?? 0,
                })
              : undefined}
            foot={
              <>
                {/* The plan and its stop go through the remediation endpoint,
                    which asks for the same permission the catalogue names for
                    security.remediate; the preview of that action answers for
                    both. */}
                <Guard action="security.remediate" host={host.id}>
                  <Button
                    disabled={!selected.length || remediate.isPending || Boolean(running)}
                    title={running ? t("a remediation plan is already running on this host") : undefined}
                    testId="fix-selected"
                    onClick={() => setIntent({
                      label: t("Apply remediation"),
                      description: t("{n} finding(s) on {host} will be fixed step by step, each step an ordinary job of the module that owns it, with its own permissions and approval. The next step starts only once the previous one succeeded, and the plan stops at the first failure. It is bound to the state you are looking at: if the host changed meanwhile, the request is refused.", {
                        n: selected.length, host: host.hostname,
                      }),
                    })}
                  >
                    {t("Fix selected ({n})", { n: selected.length })}
                  </Button>
                </Guard>
                <span>{t("{n} of the findings that need action have an operation behind them", { n: fixable.length })}</span>
                {report.data?.generated_at && (
                  <span
                    title={`${t("The fingerprint of this set of findings; a remediation is bound to it and refused when the host changed meanwhile.")} ${report.data.plan_hash} (${t("canonical form v{n}", { n: report.data.plan_hash_version })})`}
                  >
                    {t("Findings computed {when} · fingerprint {hash}", {
                      when: relativeTime(report.data.generated_at),
                      hash: report.data.plan_hash.slice(0, 12),
                    })}
                  </span>
                )}
              </>
            }
            flush
          >
            <Table
              rows={findings}
              keyOf={(one) => one.check_id}
              loading={report.isLoading}
              rowTestId={(one) => `finding-${one.check_id}`}
              empty={t("No check has been run against this host yet.")}
              columns={[
                {
                  key: "pick",
                  head: "",
                  cell: (one) => (
                    // Only a finding with a remediation operation can be
                    // ticked. The rest needs a decision the panel will not
                    // make for the operator.
                    <input
                      type="checkbox"
                      aria-label={t("Fix {check}", { check: one.check_id })}
                      disabled={
                        !one.remediation?.action || !one.applicable || one.passed || one.unknown || Boolean(running)
                      }
                      checked={selected.includes(one.check_id)}
                      onChange={(event) => setSelected((list) =>
                        event.target.checked ? [...list, one.check_id] : list.filter((id) => id !== one.check_id))}
                    />
                  ),
                },
                {
                  key: "check",
                  head: t("Check"),
                  cell: (one) => (
                    <>
                      <span>{one.title}</span>
                      <Note>{one.check_id} v{one.check_version} · {one.rationale}</Note>
                    </>
                  ),
                },
                { key: "state", head: t("State"), cell: (one) => <SeverityBadge finding={one} /> },
                { key: "expected", head: t("Expected"), minor: true, cell: (one) => one.expected },
                {
                  key: "observed",
                  head: t("Observed"),
                  cell: (one) => (
                    <>
                      {one.observed}
                      {/* The reason code says what to do about it: wait for a
                          read, fix the agent or grant permissions. */}
                      {one.reason_code && (
                        <Note>{t("reason")}: {reasonText(one.reason_code, t)}</Note>
                      )}
                      {one.evidence && <Note>{one.evidence}</Note>}
                      {one.revision && (
                        <Note>
                          {one.module} @ {one.revision.slice(0, 8)}
                          {one.observed_at && (
                            <span title={absoluteTime(one.observed_at)}> · {relativeTime(one.observed_at)}</span>
                          )}
                        </Note>
                      )}
                    </>
                  ),
                },
                {
                  key: "fix",
                  head: t("Fix"),
                  cell: (one) => one.remediation?.action
                    ? (
                      <>
                        <span>{t("operation")} {one.remediation.action}</span>
                        {one.remediation.note && <Note>{one.remediation.note}</Note>}
                      </>
                    )
                    : <Note>{one.remediation?.note || "—"}</Note>,
                },
              ]}
            />
          </Card>
        ),
        plans: (
          <Card
            title={t("Remediation plans")}
            note={t("Steps run one after another: each is an ordinary job of the module that owns it, and the next one starts only once the previous succeeded. A step that needs a reboot ends the plan — what comes after a reboot has to be judged against the host that came back.")}
          >
            {!(plans.data?.items ?? []).length ? (
              <Empty icon="security">{t("No remediation has been planned on this host.")}</Empty>
            ) : (
              (plans.data?.items ?? []).map((plan) => (
                <div key={plan.id}>
                  <Facts>
                    <Fact label={t("Plan")}>{plan.id.slice(0, 8)}</Fact>
                    <Fact label={t("State")}><Pill tone={planTone(plan.state)}>{t(stateName(plan.state))}</Pill></Fact>
                    <Fact label={t("Ordered by")}>
                      <span title={absoluteTime(plan.created_at)}>{plan.created_by} · {relativeTime(plan.created_at)}</span>
                    </Fact>
                    <Fact label={t("On a failure")}>
                      {plan.stop_on_failure ? t("stops on failure") : t("continues after failure")}
                    </Fact>
                  </Facts>
                  {plan.state === "running" && (
                    <Guard action="security.remediate" host={host.id}>
                      <Actions>
                        <Button
                          kind="danger"
                          onClick={() => stop.mutate(plan.id)}
                          disabled={stop.isPending}
                          testId={`stop-${plan.id}`}
                        >
                          {t("Stop")}
                        </Button>
                      </Actions>
                    </Guard>
                  )}
                  <Table
                    rows={plan.steps ?? []}
                    keyOf={(step) => String(step.position)}
                    empty={t("The plan has no steps.")}
                    columns={[
                      { key: "n", head: "#", num: true, cell: (step) => step.position },
                      { key: "check", head: t("Check"), tight: true, cell: (step) => step.check_id },
                      { key: "op", head: t("Operation"), tight: true, cell: (step) => (
                        <>
                          {step.action_type}
                          {step.requires_reboot && <> <Pill tone="warn">{t("reboot")}</Pill></>}
                        </>
                      ) },
                      // The lock class says which host resource the step
                      // reaches for - two steps of the same class do not run
                      // at once.
                      { key: "lock", head: t("Lock"), minor: true, cell: (step) => step.lock_class || <Note>—</Note> },
                      { key: "job", head: t("Job"), cell: (step) => step.job_id
                        ? <Link to={`/next/jobs/${step.job_id}`}>{step.job_id.slice(0, 8)}</Link>
                        : "—" },
                      { key: "state", head: t("State"), cell: (step) => (
                        <>
                          <Pill tone={planTone(step.state)}>{t(stateName(step.state))}</Pill>
                          {step.reason && <Note>{step.reason}</Note>}
                        </>
                      ) },
                    ]}
                  />
                </div>
              ))
            )}
          </Card>
        ),
      }} />

      {intent && (
        <Confirm
          host={host}
          title={intent.label}
          label={intent.label}
          busy={remediate.isPending}
          testId="confirm-remediate"
          onClose={() => setIntent(null)}
          onConfirm={(reason) => remediate.mutate(reason)}
        >
          {intent.description}
        </Confirm>
      )}

      {operation && (
        <Confirm
          host={host}
          title={operation.label}
          label={operation.label}
          busy={order.isPending}
          testId="confirm-operation"
          onClose={() => setOperation(null)}
          onConfirm={(reason) => order.mutate({ action: operation.action, reason, payload: operation.payload })}
        >
          {operation.description}
        </Confirm>
      )}
    </>
  );
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_SECURITY: BoardEntry[] = [
  { key: "checks", title: "Checks", width: 12, height: 2 },
  { key: "need", title: "Need action", width: 4, height: 2 },
  { key: "reach", title: "Where the host listens", width: 4, height: 2 },
  { key: "state", title: "Protective state", width: 4, height: 2 },
  { key: "sockets", title: "Listening sockets", width: 12, height: 3 },
  { key: "findings", title: "Findings", width: 12, height: 5 },
  { key: "plans", title: "Remediation plans", width: 12, height: 4 },
];

/** The name this module's arrangement is stored under. */
export const HOST_SECURITY_SCREEN = "next_host_security";
