import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess, type Allowance } from "../../../lib/actions";
import { emptyForm, operationForm, type FormProblem, type FormValue } from "../../../lib/operations";
import { absoluteTime, relativeTime } from "../../../lib/format";
import { changesSummary, planWords, type HostPlan } from "../../../components/plan";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Banner, Bars, Bones, Button, Card, Empty, Fact, Facts, Field, Fields, HeadActions, Modal,
  Note, Pill, Problem, Readout, Table, Tags, TwoLine, type Segment, type Tone,
} from "../../kit";

/**
 * The certificates this machine serves, and what renews them.
 *
 * The scope is enumerated, never searched: the panel reads the paths it
 * was pointed at and whatever certmonger tracks here. The private key is
 * never read - only where it lies and who may open it.
 *
 * A certificate the host has not reported is unknown, not valid. That is
 * why the deadline band counts an unknown of its own and why a key with
 * no answer about it is a dash rather than a clean mode.
 */

/* ------------------------------------------------------------- the data */

type KeyMetadata = {
  path: string;
  exists: boolean;
  mode?: string;
  owner?: string;
  group?: string;
  world_readable?: boolean;
  reason?: string;
};

type Tracking = {
  request?: string;
  status?: string;
  ca?: string;
  key_path?: string;
  auto_renew?: boolean;
  expires?: string;
};

export type Certificate = {
  path: string;
  subject?: string;
  issuer?: string;
  serial?: string;
  sans?: string[];
  not_before?: string;
  not_after?: string;
  fingerprint_sha256?: string;
  key_algorithm?: string;
  key_bits?: number;
  self_signed?: boolean;
  is_ca?: boolean;
  chain_length?: number;
  key?: KeyMetadata;
  source: string;
  owner_service?: string;
  renewal: string;
  tracking?: Tracking;
  unavailable_reason?: string;
  status: string;
  days_to_expiry?: number;
  watched: boolean;
  managed: boolean;
  deployed_at?: string;
  deployed_by?: string;
  key_secret?: string;
  reload_unit?: string;
  probe_target?: string;
};

export type Target = {
  id: string;
  path: string;
  key_path?: string;
  key_secret?: string;
  reload_unit?: string;
  probe_target?: string;
  service?: string;
  note?: string;
  updated_by: string;
  updated_at: string;
};

type Report = {
  host_id: string;
  certificates: Certificate[];
  targets: Target[];
  status: string;
  tracking_known: boolean;
  tracking_reason?: string;
  keys_known: boolean;
  missing?: Record<string, string>;
  observed_at?: string;
  revision?: string;
  stale: boolean;
  unavailable_reason?: string;
};

type Deployment = {
  path: string;
  fingerprint_sha256: string;
  subject?: string;
  not_after?: string;
  key_secret?: string;
  key_secret_version?: number;
  job_id?: string;
  deployed_by: string;
  deployed_at: string;
};

/** What the operator has asked for and has not yet confirmed. */
type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The shortest reason the API takes for a change of this risk. */
export const MIN_REASON_LENGTH = 8;

/** The changes this module offers; when every one is refused, it says so once. */
export const CERTIFICATE_CHANGES = ["certificate.deploy", "certificate.renew"];

/* ---------------------------------------------------------- the reading */

/**
 * The list soonest deadline first: the certificate that expires next week
 * is the one to look at, wherever certmonger listed it.
 */
export function byDeadline(list: Certificate[]): Certificate[] {
  return list.slice().sort((a, b) => {
    if (!a.not_after && !b.not_after) return a.path.localeCompare(b.path);
    if (!a.not_after) return 1;
    if (!b.not_after) return -1;
    return a.not_after.localeCompare(b.not_after) || a.path.localeCompare(b.path);
  });
}

/** The common name out of a subject, so the SAN list can leave it out. */
export function commonName(subject?: string): string {
  const match = /(?:^|,\s*)CN=([^,]+)/.exec(subject ?? "");
  return match ? match[1].trim() : "";
}

/** The deadline as a state. It is the panel's judgement, not a host fact. */
export function deadlineTone(status: string): Tone {
  if (status === "valid") return "ok";
  if (status === "expired" || status === "critical") return "error";
  if (status === "warning") return "warn";
  return "unknown";
}

/** How many of a list answer a question; undefined when there is no list. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/* --------------------------------------------------------- the registry */

/** One order as the registry composes it: what goes out, and what is wrong with it. */
export type RegistryOrder = {
  action: string;
  payload: Record<string, unknown>;
  problems: FormProblem[];
};

/**
 * Puts an order through the registry entry of its action, so this module
 * and the Bulk workspace send one payload and refuse one set of values.
 */
export function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  if (!entry) {
    return {
      action,
      payload: {},
      problems: [{ message: "The registry has no form for {action} yet.", params: { action } }],
    };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

/** Whether the registry would take this order as it stands. */
export function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

/** The first refusal of an order as a sentence, or empty when there is none. */
export function refusalOf(t: Translate, order: RegistryOrder): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

/** A renewal as the registry composes it. */
export function renewOrder(
  request: string, path: string, reloadUnit: string, probeTarget: string,
): RegistryOrder {
  return registryOrder("certificate.renew", {
    request, path, reload_unit: reloadUnit, probe_target: probeTarget,
  });
}

/** The values a certificate plan was computed for. */
export function certificateOrder(path: string, content: string): string {
  return path + "\u0000" + content;
}

/** The certificate plan of a planning job: the digest the change binds to. */
type CertificatePlanDetail = { kind?: string; plan_hash?: string; plan?: HostPlan };

/** The deployment plan and its digest, or null when the job carries none. */
export function certificatePlanBinding(detail?: CertificatePlanDetail):
  { hash: string; plan: HostPlan } | null {
  if (detail?.kind !== "certificate_plan" || !detail.plan_hash) return null;
  return { hash: detail.plan_hash, plan: detail.plan ?? {} };
}

/* ------------------------------------------------------- read by a job */

type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/**
 * A read ordered through a job: the order goes out, the attempts are
 * polled until the host answers, and the last one is the result.
 */
function useReadOperation<T>(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<T>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items?.[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  return {
    order: order.mutate,
    busy: order.isPending || (job !== "" && !last?.status),
    message,
    attempt: last?.status ? last : undefined,
  };
}

/* ----------------------------------------------------------- the pieces */

/**
 * A control that exists only where the order it places would be taken.
 *
 * Refused and asked about, it stands disabled with the server's own reason
 * on it; refused and not asked about, it is not drawn at all, because a
 * dead button teaches nothing. While the verdict is on its way there is no
 * button, so nobody presses one that is about to be taken away.
 */
function Guarded({ verdict, explain = false, children }: {
  verdict: Allowance;
  explain?: boolean;
  children: (disabled: boolean, reason: string | undefined) => ReactNode;
}) {
  if (verdict.allowed) return <>{children(false, verdict.note || undefined)}</>;
  if (!explain || verdict.pending) return null;
  return <>{children(true, verdict.reason || undefined)}</>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ hostID, actions }: { hostID: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(hostID, actions);
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

/** The answer to an order, with the job it names one click away. */
function JobNotice({ job }: { job: Job }) {
  const t = useT();
  const sentence = job.requires_approval
    ? t("Job {id} is waiting for approval.")
    : t("Job {id} has been queued.");
  const [before, after = ""] = sentence.split("{id}");
  return (
    <Banner tone="info">
      {before}
      <Link to={`/next/jobs/${job.id}`}>{job.id.slice(0, 8)}</Link>
      {after}
    </Banner>
  );
}

/**
 * The confirmation of an order that changes the host.
 *
 * It names the machine again, takes the reason the trail keeps, and asks
 * for the hostname to be typed: an operator approves a specific machine,
 * not whichever one the screen happened to be on.
 */
function Confirm({ host, label, description, danger = false, busy, onConfirm, onCancel }: {
  host: Host;
  label: string;
  description: string;
  danger?: boolean;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ready = reason.trim().length >= MIN_REASON_LENGTH && typed === host.hostname;
  return (
    <Modal
      title={label}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind={danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason)}
            testId="confirm-order"
          >
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{description}</Note>
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {` · ${host.management_address || t("address unknown")} · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-host" />
        </Field>
      </Fields>
    </Modal>
  );
}

/**
 * What the host says it would do, and the text it would write.
 *
 * The summary names the change; the verbatim document is what actually
 * lands, and that is what the operator consents to - not a paraphrase.
 */
function PlanView({ plan }: { plan: HostPlan }) {
  const t = useT();
  if (plan.refusal) return <Pill tone="error">{t("refused: {reason}", { reason: plan.refusal })}</Pill>;
  if (plan.validator_failed) {
    return (
      <Pill tone="error">
        {t("validator failed")}
        {plan.validator_output ? `: ${plan.validator_output.slice(0, 200)}` : ""}
      </Pill>
    );
  }
  const parts = [planWords(plan, t)];
  if (plan.changes?.length) parts.push(changesSummary(plan.changes));
  if (plan.resolved_source && plan.resolved_source !== plan.requested_source) {
    parts.push(`${plan.requested_source} → ${plan.resolved_source}`);
  }
  const verbatim = plan.document
    ? { label: t("Document"), text: plan.document }
    : plan.commands?.length
      ? { label: t("Commands"), text: plan.commands.join("\n") }
      : null;
  return (
    <>
      <Note>{parts.filter(Boolean).join(" · ")}</Note>
      {plan.warnings && plan.warnings.length > 0 && (
        <Tags>{plan.warnings.map((warning) => <Pill key={warning} tone="warn">{warning}</Pill>)}</Tags>
      )}
      {verbatim && <Readout label={verbatim.label} value={verbatim.text} lines={10} testId="plan-verbatim" />}
    </>
  );
}

/* ------------------------------------------------------------ the forms */

/** The watch scope. This changes what the panel looks at, not the host. */
function WatchCard({ busy, onSave }: {
  busy: boolean;
  onSave: (body: Record<string, unknown>) => void;
}) {
  const t = useT();
  const [path, setPath] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [secret, setSecret] = useState("");
  const [unit, setUnit] = useState("");
  const [probe, setProbe] = useState("");
  const [service, setService] = useState("");

  return (
    <Card
      title={t("Watch a path")}
      note={t("This changes what the panel looks at, not the host. The service that reads the file and the address where the result is visible are yours to fill in — the panel does not guess them from a directory name.")}
      foot={
        <Button
          disabled={!path || busy}
          testId="watch-save"
          onClick={() => onSave({
            path, key_path: keyPath, key_secret: secret,
            reload_unit: unit, probe_target: probe, service,
          })}
        >
          {t("Watch")}
        </Button>
      }
    >
      <Fields>
        <Field label={t("Path")}>
          <input
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="/etc/pki/tls/certs/service.crt"
            data-testid="watch-path"
          />
        </Field>
        <Field label={t("Key")}>
          <input
            value={keyPath}
            onChange={(event) => setKeyPath(event.target.value)}
            placeholder="/etc/pki/tls/private/service.key"
            data-testid="watch-key"
          />
        </Field>
        <Field
          label={t("Key secret")}
          hint={t("The name of the secret the private key comes from at deployment; the value never travels in a job.")}
        >
          <input value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="web.tls.key" />
        </Field>
        <Field
          label={t("Reload unit")}
          hint={t("The service reloaded after a deployment, so it picks the new certificate up.")}
        >
          <input value={unit} onChange={(event) => setUnit(event.target.value)} placeholder="httpd.service" />
        </Field>
        <Field
          label={t("Probe target")}
          hint={t("Where the host checks the certificate after the swap; a failed probe rolls the deployment back.")}
        >
          <input value={probe} onChange={(event) => setProbe(event.target.value)} placeholder="www.example.internal:443" />
        </Field>
        <Field label={t("Owner service")} hint={t("The service this certificate belongs to, for the list.")}>
          <input value={service} onChange={(event) => setService(event.target.value)} placeholder="httpd" />
        </Field>
      </Fields>
    </Card>
  );
}

/**
 * The deployment. The key is named by a secret and never pasted, and the
 * host plans the swap first: what already lies under the path decides what
 * is replaced, and only the host can read that.
 */
function DeployCard({ host, targets, planGuard, onIntent }: {
  host: Host;
  targets: Target[];
  planGuard: Allowance;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const [path, setPath] = useState(targets[0]?.path ?? "");
  const [content, setContent] = useState("");
  const chosen = targets.find((target) => target.path === path);
  const plan = useReadOperation<CertificatePlanDetail>(host);
  // The order the plan was asked for, kept beside it: a field edited after
  // the planning leaves the digest bound to values nobody looked at.
  const [planned, setPlanned] = useState("");
  const order = certificateOrder(path, content);
  const binding = planned === order ? certificatePlanBinding(plan.attempt?.detail) : null;
  const refused = planned === order && plan.attempt && plan.attempt.status !== "succeeded";
  const hash = binding && !binding.plan.refusal ? binding.hash : "";

  return (
    <Card
      title={t("Deploy a certificate")}
      note={t("Paste the certificate with its chain, leaf first. The private key is not pasted here and never travels in the job: the host fetches it from the secret named on the watched path, once, while it runs the operation.")}
      foot={
        <>
          <Guarded verdict={planGuard} explain>
            {(disabled, reason) => (
              <Button
                kind="quiet"
                title={reason}
                disabled={disabled || !path || !content.includes("BEGIN CERTIFICATE") || plan.busy
                  || host.connection_state !== "online"}
                testId="certificate-plan"
                onClick={() => {
                  setPlanned(order);
                  plan.order({
                    action: "certificate.plan",
                    payload: {
                      certificate: {
                        path, key_path: chosen?.key_path ?? "", certificate: content,
                        // The plan covers whether the order brings a key: the
                        // digest would not match the deployment without it.
                        ...(chosen?.key_secret ? { key_secret: { name: chosen.key_secret } } : {}),
                      },
                    },
                  });
                }}
              >
                {plan.busy ? t("Planning…") : t("Plan on the host")}
              </Button>
            )}
          </Guarded>
          <Button
            disabled={!hash}
            testId="certificate-deploy"
            onClick={() => onIntent({
              action: "certificate.deploy",
              label: t("Deploy certificate"),
              description:
                t("{path} on {host} is replaced", { path, host: host.hostname })
                + (chosen?.key_secret ? `, ${t("with the key from secret {secret}", { secret: chosen.key_secret })}` : "")
                + (chosen?.reload_unit ? `, ${t("then {unit} is reloaded", { unit: chosen.reload_unit })}` : "")
                + (chosen?.probe_target ? ` ${t("and {target} is checked", { target: chosen.probe_target })}` : "")
                + `. ${t("The host verifies key and chain before the swap and rolls back if the service does not come back with the new certificate.")}`,
              payload: {
                certificate: {
                  path,
                  key_path: chosen?.key_path ?? "",
                  certificate: content,
                  reload_unit: chosen?.reload_unit ?? "",
                  probe_target: chosen?.probe_target ?? "",
                  ...(chosen?.key_secret ? { key_secret: { name: chosen.key_secret } } : {}),
                  plan_hash: hash,
                },
              },
            })}
          >
            {t("Deploy")}
          </Button>
        </>
      }
    >
      <Fields>
        <Field
          label={t("Watched path")}
          wide
          hint={chosen && (
            <>
              {t("Key")}: {chosen.key_path || t("not set")}
              {chosen.key_secret
                ? ` ${t("from secret {secret}", { secret: chosen.key_secret })}`
                : ` — ${t("no secret set, the key stays as it is")}`}
              {` · ${t("reload")} ${chosen.reload_unit || t("nothing")}`}
              {` · ${t("probe")} ${chosen.probe_target || t("none")}`}
            </>
          )}
        >
          <select value={path} onChange={(event) => setPath(event.target.value)} data-testid="deploy-path">
            {targets.length === 0 && <option value="">{t("no watched path on this host")}</option>}
            {targets.map((target) => <option key={target.id} value={target.path}>{target.path}</option>)}
          </select>
        </Field>
        <Field label={t("Certificate (PEM, leaf first)")} wide>
          <textarea
            rows={10}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="-----BEGIN CERTIFICATE-----"
            data-testid="deploy-certificate"
          />
        </Field>
      </Fields>
      {plan.message && <Problem>{plan.message}</Problem>}
      {refused && (
        <Problem>
          {plan.attempt?.message || plan.attempt?.error_code || t("The host refused to plan the deployment.")}
        </Problem>
      )}
      {binding
        ? <PlanView plan={binding.plan} />
        : <Note>{plan.busy
            ? t("The host is planning this deployment…")
            : t("Plan the deployment on the host first: the certificate is replaced only against the plan it answers with.")}</Note>}
    </Card>
  );
}

/**
 * The renewal of one row. The registry composes the order, so a row whose
 * values the panel would not send says why instead of placing an order the
 * host refuses.
 */
function RenewButton({ host, certificate, onIntent }: {
  host: Host;
  certificate: Certificate;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const order = renewOrder(
    certificate.tracking?.request ?? "", certificate.path,
    certificate.reload_unit ?? "", certificate.probe_target ?? "",
  );
  return (
    <Button
      kind="quiet"
      disabled={!orderReady(order)}
      title={refusalOf(t, order) || undefined}
      testId={`renew-${certificate.path}`}
      onClick={() => onIntent({
        action: order.action,
        label: t("Renew certificate"),
        description:
          t("certmonger on {host} is asked to reissue request {request} for {path}", {
            host: host.hostname,
            request: certificate.tracking?.request ?? "",
            path: certificate.path,
          })
          + (certificate.reload_unit ? `, ${t("then {unit} is reloaded", { unit: certificate.reload_unit })}` : "")
          + ".",
        payload: order.payload,
      })}
    >
      {t("Renew")}
    </Button>
  );
}

/* ----------------------------------------------------------- the module */

export function Certificates({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");
  const [form, setForm] = useState<"" | "watch" | "deploy">("");
  const [selected, setSelected] = useState("");
  const [unwatching, setUnwatching] = useState("");
  // The last job ordered from here, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);

  const scanGuard = useAllowed(host.id, "certificate.scan");
  const deployGuard = useAllowed(host.id, "certificate.deploy");
  const renewGuard = useAllowed(host.id, "certificate.renew");
  const planGuard = useAllowed(host.id, "certificate.plan");

  const fragment = useQuery({
    queryKey: ["inventory", host.id, "certificates"],
    queryFn: () => api.get<InventoryFragment<unknown>>(`/api/v1/hosts/${host.id}/inventory/certificates`),
    retry: false,
  });
  const report = useQuery({
    queryKey: ["certificates", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/certificates`),
  });
  const history = useQuery({
    queryKey: ["certificate-deployments", host.id, selected],
    queryFn: () => api.get<{ items: Deployment[] }>(
      `/api/v1/hosts/${host.id}/certificates/deployments?path=${encodeURIComponent(selected)}`,
    ),
    enabled: selected !== "",
  });

  const settled = (text: string) => {
    setNotice(text);
    setProblem("");
    void queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
  };
  const failed = (error: unknown) => setProblem(error instanceof Error ? error.message : String(error));

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setOrdered(job);
      setNotice("");
      setProblem("");
      setIntent(null);
      setForm("");
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: failed,
  });

  const watch = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Target>(`/api/v1/hosts/${host.id}/certificates/targets`, body),
    onSuccess: (target) => {
      settled(t("The panel now watches {path}. Scan the host to read it.", { path: target.path }));
      setForm("");
    },
    onError: failed,
  });

  const forget = useMutation({
    mutationFn: ({ path, reason }: { path: string; reason: string }) =>
      api.del(
        `/api/v1/hosts/${host.id}/certificates/targets`
        + `?path=${encodeURIComponent(path)}&reason=${encodeURIComponent(reason)}`,
      ),
    onSuccess: () => {
      settled(t("The panel stopped watching that path."));
      setUnwatching("");
    },
    onError: failed,
  });

  if (report.error) return <Problem>{String(report.error)}</Problem>;

  const data = report.data;
  const list = byDeadline(data?.certificates ?? []);
  const targets = data?.targets ?? [];
  // The list is unknown until the report lands; the band shows dashes then.
  const known = data ? list : undefined;
  const byStatus = (status: string) => countWhere(known, (one) => one.status === status);

  // The renewal and the source are codes in the report; the module speaks
  // the operator's words, and the breakdown the same ones.
  const renewalName = (renewal: string) =>
    renewal === "tracked" ? "certmonger" : renewal === "manual" ? t("manual") : t("unknown");
  const sourceName = (source: string) =>
    source === "flotestro" ? t("panel")
      : source === "certmonger" ? "certmonger"
        : source === "external" ? t("outside the panel") : source;
  const tally = (key: (one: Certificate) => string) =>
    Object.entries(list.reduce<Record<string, number>>((into, one) => {
      const value = key(one);
      into[value] = (into[value] ?? 0) + 1;
      return into;
    }, {})).sort((a, b) => b[1] - a[1]);

  const deadline: Segment[] = [
    { label: t("valid"), value: byStatus("valid"), tone: "ok" },
    { label: t("under 30 days"), value: byStatus("warning"), tone: "warn" },
    { label: t("under 7 days"), value: byStatus("critical"), tone: "error" },
    { label: t("expired"), value: byStatus("expired"), tone: "error" },
    {
      label: t("unknown"),
      value: countWhere(known, (one) => !["valid", "warning", "critical", "expired"].includes(one.status)),
      tone: "unknown",
    },
  ];

  const chosen = list.find((one) => one.path === selected);
  const missing = Object.entries(data?.missing ?? {});

  return (
    <>
      {/* Actions on the whole module stand in the heading beside the
          machine's name, where every other screen puts its own. */}
      <HeadActions>
        <Button kind="quiet" testId="watch-open" onClick={() => setForm(form === "watch" ? "" : "watch")}>
          {form === "watch" ? t("Cancel") : t("Watch a path")}
        </Button>
        {deployGuard.allowed && (
          <Button kind="quiet" testId="deploy-open" onClick={() => setForm(form === "deploy" ? "" : "deploy")}>
            {form === "deploy" ? t("Cancel") : t("Deploy a certificate")}
          </Button>
        )}
        <Guarded verdict={scanGuard} explain>
          {(disabled, reason) => (
            <Button
              title={reason}
              testId="certificate-scan"
              disabled={disabled || host.connection_state !== "online" || request.isPending}
              onClick={() => request.mutate({
                action: "certificate.scan",
                payload: {
                  certificate: {
                    targets: targets.map((target) => ({
                      path: target.path,
                      key_path: target.key_path ?? "",
                      service: target.service ?? "",
                    })),
                  },
                },
              })}
            >
              {t("Scan host")}
            </Button>
          )}
        </Guarded>
      </HeadActions>

      <ReadOnlyNotice hostID={host.id} actions={CERTIFICATE_CHANGES} />
      {data?.stale && (
        <Banner tone="warn">
          {t("This picture is older than a day and a half. Scan the host to see what is on disk now.")}
        </Banner>
      )}
      {data && !data.tracking_known && (
        <Banner tone="warn">
          {t("The panel could not tell what renews these certificates")}
          {data.tracking_reason ? `: ${data.tracking_reason}` : "."}
        </Banner>
      )}
      {fragment.data?.unavailable_reason && (
        <Banner tone="warn">
          {t("could not be read: {reason}", { reason: fragment.data.unavailable_reason })}
        </Banner>
      )}
      {problem && <Problem>{problem}</Problem>}
      {notice && <Banner tone="info">{notice}</Banner>}
      {ordered && <JobNotice job={ordered} />}

      <Board screen="next_host_certificates" catalogue={HOST_CERTIFICATES} drawn={{
        deadline: (
          <Card
            title={t("By deadline")}
            note={t("How long each certificate has left, as the panel judges it.")}
          >
            <Band segments={deadline} testId="deadline" />
          </Card>
        ),
        renewal: (
          <Card
            title={t("Renewal")}
            note={t("What renews each certificate, and where the panel learnt of it.")}
          >
            {!known ? (
              <Bones rows={3} />
            ) : list.length === 0 ? (
              <Empty>{t("No certificate is watched on this host yet.")}</Empty>
            ) : (
              <>
                <Bars items={tally((one) => one.renewal || "unknown").map(([renewal, count]) => ({
                  label: renewalName(renewal),
                  value: count,
                  tone: renewal === "manual" ? "warn" : renewal === "tracked" ? "ok" : "unknown",
                }))} />
                <Note>{t("Source")}</Note>
                <Bars items={tally((one) => one.source).map(([source, count]) => ({
                  label: sourceName(source), value: count,
                }))} />
              </>
            )}
          </Card>
        ),
        watch: form === "watch" && <WatchCard busy={watch.isPending} onSave={(body) => watch.mutate(body)} />,
        deploy: form === "deploy" && deployGuard.allowed && (
          <DeployCard host={host} targets={targets} planGuard={planGuard} onIntent={setIntent} />
        ),
        list: (
          <Card
            title={t("Certificates")}
            note={list.length > 0
              ? t("Soonest deadline first. Open a path for the issuer, the chain and the deployments of that file.")
              : undefined}
            foot={fragment.data
              ? t("Source: {source}, revision {revision}, observed {when}", {
                  source: fragment.data.source,
                  revision: fragment.data.revision.slice(0, 12),
                  when: relativeTime(fragment.data.observed_at),
                })
              : undefined}
            flush
          >
            {!report.isLoading && list.length === 0 ? (
              <Empty icon="certificates" action={<Button kind="quiet" onClick={() => setForm("watch")}>{t("Watch a path")}</Button>}>
                {t("No certificate is watched on this host yet. Add a path, or scan the host if certmonger tracks something here.")}
              </Empty>
            ) : (
              <Table
                rows={list}
                keyOf={(one) => one.path}
                loading={report.isLoading}
                testId="certificates"
                rowTestId={(one) => `certificate-${one.path}`}
                /* The row the cards beside the table are about carries the
                   mark, as it did in the panel being replaced: without it
                   the detail belongs to no row the reader can see. */
                marked={(one) => one.path === selected}
                columns={[
                  {
                    key: "path",
                    head: t("Path"),
                    cell: (one) => (
                      <TwoLine sub={one.owner_service}>
                        <Button
                          kind="word"
                          onClick={() => setSelected(selected === one.path ? "" : one.path)}
                        >
                          {one.path}
                        </Button>
                      </TwoLine>
                    ),
                  },
                  {
                    key: "subject",
                    head: t("Subject"),
                    cell: (one) => {
                      if (one.unavailable_reason) return <Pill tone="unknown">{one.unavailable_reason}</Pill>;
                      // A SAN that only repeats the common name says nothing new.
                      const extra = one.sans?.filter((san) => san !== commonName(one.subject)) ?? [];
                      return (
                        <TwoLine sub={extra.length > 0 ? `${t("also")} ${extra.join(", ")}` : undefined}>
                          {one.subject || "—"}
                        </TwoLine>
                      );
                    },
                  },
                  {
                    key: "expires",
                    head: t("Expires"),
                    cell: (one) => (
                      <TwoLine sub={one.not_after ? absoluteTime(one.not_after).slice(0, 10) : undefined}>
                        <Pill tone={deadlineTone(one.status)}>
                          {one.status === "expired"
                            ? one.days_to_expiry === undefined
                              ? t("expired")
                              : t("expired {n} d ago", { n: Math.abs(one.days_to_expiry) })
                            : one.status === "unknown"
                              ? t("unknown")
                              : one.days_to_expiry === undefined
                                ? one.status
                                : t("{n} d left", { n: one.days_to_expiry })}
                        </Pill>
                      </TwoLine>
                    ),
                  },
                  {
                    key: "renewal",
                    head: t("Renewal"),
                    // "Manual" is a finding: the daemon answered that it does
                    // not watch this file. "Unknown" is a missing answer.
                    cell: (one) => one.renewal === "tracked" ? (
                      <TwoLine sub={one.tracking?.status}><Pill tone="ok">certmonger</Pill></TwoLine>
                    ) : one.renewal === "manual" ? (
                      <Pill tone="warn">{t("manual")}</Pill>
                    ) : (
                      <Pill tone="unknown">{t("unknown")}</Pill>
                    ),
                  },
                  {
                    key: "source",
                    head: t("Source"),
                    minor: true,
                    cell: (one) => one.managed ? (
                      <TwoLine sub={one.deployed_at
                        ? `${relativeTime(one.deployed_at)} · ${one.deployed_by ?? ""}`
                        : undefined}
                      >
                        <Pill tone="ok">{t("panel")}</Pill>
                      </TwoLine>
                    ) : one.source === "certmonger" ? (
                      <Pill tone="neutral">certmonger</Pill>
                    ) : (
                      <Pill tone="neutral">{t("outside the panel")}</Pill>
                    ),
                  },
                  {
                    key: "key",
                    head: (
                      <span title={t("The private key file: its mode and owner. The key itself is never read.")}>
                        {t("Key file")}
                      </span>
                    ),
                    minor: true,
                    cell: (one) => (
                      <TwoLine sub={one.key_secret ? `${t("secret")} ${one.key_secret}` : undefined}>
                        {!one.key ? "—"
                          : one.key.reason ? <Pill tone="unknown">{one.key.reason}</Pill>
                            : !one.key.exists ? <Pill tone="error">{t("missing")}</Pill>
                              : one.key.world_readable
                                ? <Pill tone="error">{t("mode {mode}, world-readable", { mode: one.key.mode ?? "" })}</Pill>
                                : <code>{`${one.key.mode ?? ""} ${one.key.owner ?? ""}`}</code>}
                      </TwoLine>
                    ),
                  },
                  {
                    key: "do",
                    head: t("Actions"),
                    actions: true,
                    cell: (one) => {
                      // Only certmonger renews from the panel; a manual
                      // certificate has no button, not a dead one.
                      const renewable = one.renewal === "tracked" && !!one.tracking?.request;
                      if (!renewable && !one.watched) {
                        return (
                          <span title={t("Renewed outside the panel; certmonger does not track this file and the panel does not watch it.")}>
                            —
                          </span>
                        );
                      }
                      return (
                        <>
                          {renewable && renewGuard.allowed && (
                            <RenewButton host={host} certificate={one} onIntent={setIntent} />
                          )}
                          {one.watched && (
                            <Button
                              kind="quiet"
                              title={t("The panel stops reading this path; the file on the host stays as it is.")}
                              testId={`unwatch-${one.path}`}
                              onClick={() => setUnwatching(one.path)}
                            >
                              {t("Stop watching")}
                            </Button>
                          )}
                        </>
                      );
                    },
                  },
                ]}
              />
            )}
          </Card>
        ),
        certificate: chosen && (
          <Card title={chosen.path}>
            <Facts>
              <Fact label={t("Issuer")}>{chosen.issuer || <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
              <Fact label={t("Serial")}>{chosen.serial ? <code>{chosen.serial}</code> : "—"}</Fact>
              <Fact label={t("Key")}>
                {chosen.key_algorithm
                  ? `${chosen.key_algorithm} ${chosen.key_bits ?? ""}`.trim()
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Chain")}>
                {/* A bare leaf without the chain is the most common reason a
                    client rejects the connection despite a valid certificate. */}
                {chosen.chain_length
                  ? chosen.chain_length === 1
                    ? t("leaf only — clients that need the issuer will reject it")
                    : t("{n} certificates", { n: chosen.chain_length })
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Valid from")}>
                {chosen.not_before
                  ? <span title={absoluteTime(chosen.not_before)}>{relativeTime(chosen.not_before)}</span>
                  : "—"}
              </Fact>
              <Fact label={t("Valid until")}>
                {chosen.not_after
                  ? <span title={absoluteTime(chosen.not_after)}>{relativeTime(chosen.not_after)}</span>
                  : "—"}
              </Fact>
              {chosen.tracking?.request && (
                <Fact label="certmonger">
                  {`${t("request")} ${chosen.tracking.request} · CA ${chosen.tracking.ca ?? ""} · `}
                  {`${t("auto-renew")} ${chosen.tracking.auto_renew ? t("yes") : t("no")}`}
                </Fact>
              )}
            </Facts>
            {chosen.fingerprint_sha256 && (
              <Readout label={t("Fingerprint")} value={chosen.fingerprint_sha256} testId="fingerprint" />
            )}
          </Card>
        ),
        deployments: chosen && (
          <Card title={t("Deployments from the panel")} flush>
            <Table
              rows={history.data?.items ?? []}
              keyOf={(one) => `${one.fingerprint_sha256}-${one.deployed_at}`}
              loading={history.isLoading}
              empty={t("The panel has never deployed this file.")}
              testId="deployments"
              columns={[
                {
                  key: "fingerprint",
                  head: t("Fingerprint"),
                  tight: true,
                  cell: (one) => (
                    <>
                      <code>{one.fingerprint_sha256.slice(0, 16)}</code>
                      {one.fingerprint_sha256 === chosen.fingerprint_sha256 && (
                        <Pill tone="ok">{t("on host")}</Pill>
                      )}
                    </>
                  ),
                },
                {
                  key: "expires",
                  head: t("Expires"),
                  cell: (one) => one.not_after
                    ? <span title={absoluteTime(one.not_after)}>{relativeTime(one.not_after)}</span>
                    : "—",
                },
                {
                  key: "key",
                  head: t("Key"),
                  minor: true,
                  tight: true,
                  cell: (one) => one.key_secret
                    ? <code>{`${one.key_secret}@v${one.key_secret_version ?? ""}`}</code>
                    : "—",
                },
                {
                  key: "when",
                  head: t("Deployed"),
                  cell: (one) => <span title={absoluteTime(one.deployed_at)}>{relativeTime(one.deployed_at)}</span>,
                },
                { key: "by", head: t("By"), minor: true, cell: (one) => one.deployed_by },
              ]}
            />
          </Card>
        ),
        missing: missing.length > 0 && (
          <Card
            title={t("Not established")}
            note={t("Facts the host could not collect. Each one is an answer of \"not known\", not a value of zero.")}
            flush
          >
            <Table
              rows={missing}
              keyOf={([fact]) => fact}
              testId="not-established"
              columns={[
                { key: "fact", head: t("Fact"), tight: true, cell: ([fact]) => <code>{fact}</code> },
                { key: "reason", head: t("Reason"), cell: ([, reason]) => reason },
              ]}
            />
          </Card>
        ),
      }} />

      {intent && (
        <Confirm
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onCancel={() => setIntent(null)}
          onConfirm={(reason) => request.mutate({ action: intent.action, reason, payload: intent.payload })}
        />
      )}

      {unwatching && (
        <Confirm
          host={host}
          label={t("Stop watching")}
          danger
          description={t("The panel stops reading {path} on {host}. The file on the host stays exactly as it is, and so does whatever renews it.", {
            path: unwatching, host: host.hostname,
          })}
          busy={forget.isPending}
          onCancel={() => setUnwatching("")}
          onConfirm={(reason) => forget.mutate({ path: unwatching, reason })}
        />
      )}
    </>
  );
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_CERTIFICATES: BoardEntry[] = [
  { key: "deadline", title: "By deadline", width: 8, height: 2 },
  { key: "renewal", title: "Renewal", width: 4, height: 2 },
  { key: "watch", title: "Watch a path", width: 12, height: 3 },
  { key: "deploy", title: "Deploy a certificate", width: 12, height: 4 },
  { key: "list", title: "Certificates", width: 12, height: 4 },
  { key: "certificate", title: "The chosen certificate", width: 6, height: 3 },
  { key: "deployments", title: "Deployments from the panel", width: 6, height: 3 },
  { key: "missing", title: "Not established", width: 12, height: 2 },
];

/** The name this module's arrangement is stored under. */
export const HOST_CERTIFICATES_SCREEN = "next_host_certificates";
