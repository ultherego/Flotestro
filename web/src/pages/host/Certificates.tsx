import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

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

type Certificate = {
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

type Target = {
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

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The deadline state is the panel's judgement, not a fact from the host - hence its own look. */
function StatusBadge({ status, days }: { status: string; days?: number }) {
  const t = useT();
  const cls =
    status === "valid" ? "ok" : status === "expired" || status === "critical" ? "error"
      : status === "warning" ? "warn" : "unknown";
  const caption =
    status === "expired"
      ? days === undefined ? t("expired") : t("expired {n} d ago", { n: Math.abs(days) })
      : status === "unknown"
        ? t("unknown")
        : days === undefined ? status : t("{n} d left", { n: days });
  return <span className={`badge ${cls}`}>{caption}</span>;
}

/**
 * The host's certificates.
 *
 * The scope is enumerated, not searched: the panel looks at the files it
 * was pointed to and at those certmonger watches. Searching the whole
 * filesystem would find above all the trust store - a few hundred authority
 * certificates that belong to no service.
 *
 * The panel never looks at the private key: it only knows where it lies,
 * what permissions it has and which secret it comes from.
 */
export function Certificates() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState<"" | "watch" | "deploy">("");
  const [selected, setSelected] = useState("");

  const module = useModule<unknown>(host.id, "certificates");
  const report = useQuery({
    queryKey: ["certificates", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/certificates`),
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      setForm("");
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const watch = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Target>(`/api/v1/hosts/${host.id}/certificates/targets`, body),
    onSuccess: (target) => {
      setMessage(t("The panel now watches {path}. Scan the host to read it.", { path: target.path }));
      setForm("");
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const forget = useMutation({
    mutationFn: (path: string) =>
      api.del(`/api/v1/hosts/${host.id}/certificates/targets?path=${encodeURIComponent(path)}`),
    onSuccess: () => {
      setMessage(t("The panel stopped watching that path."));
      queryClient.invalidateQueries({ queryKey: ["certificates", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (report.error) return <ErrorBox error={report.error} />;
  const data = report.data;
  const list = data?.certificates ?? [];
  const targets = data?.targets ?? [];
  const unknown = <span className="badge unknown">{t("unknown")}</span>;
  // The list is unknown until the report loads; the bar shows dashes then.
  const known = data ? list : undefined;
  const byStatus = (status: string) => countWhere(known, (certificate) => certificate.status === status);
  const tally = (key: (certificate: Certificate) => string) =>
    Object.entries(list.reduce<Record<string, number>>((acc, certificate) => {
      const value = key(certificate);
      acc[value] = (acc[value] ?? 0) + 1;
      return acc;
    }, {})).sort((a, b) => b[1] - a[1]);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Certificates")}
        description={t("Certificates on the paths the panel watches, plus everything certmonger tracks on this host. Nothing here comes from walking the filesystem, and the private key is never read — only its location and permissions.")}
        actions={
          <>
            <button className="secondary" onClick={() => setForm(form === "watch" ? "" : "watch")}>
              {form === "watch" ? t("Cancel") : t("Watch a path")}
            </button>
            <button className="secondary" onClick={() => setForm(form === "deploy" ? "" : "deploy")}>
              {form === "deploy" ? t("Cancel") : t("Deploy a certificate")}
            </button>
            <button
              onClick={() =>
                request.mutate({
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
                })
              }
              disabled={host.connection_state !== "online" || request.isPending}
            >
              {t("Scan host")}
            </button>
          </>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {data?.stale && (
        <p className="warning">
          <span>
            {t("This picture is older than a day and a half. Scan the host to see what is on disk now.")}
          </span>
        </p>
      )}
      {data && !data.tracking_known && (
        <p className="warning">
          <span>
            {t("The panel could not tell what renews these certificates")}
            {data.tracking_reason ? `: ${data.tracking_reason}` : "."}
          </span>
        </p>
      )}

      <Widgets>
      {/* The certificates by deadline: the panel's judgement of what the
          host reported, read before the list. */}
      <Summary
        title={t("By deadline")}
        description={t("How long each certificate has left, as the panel judges it.")}
        span={8}
        segments={[
          { label: t("valid"), value: byStatus("valid"), tone: "ok" },
          { label: t("Expiring soon"), value: byStatus("warning"), tone: "warn" },
          { label: t("critical"), value: byStatus("critical"), tone: "error" },
          { label: t("Expired"), value: byStatus("expired"), tone: "error" },
          { label: t("unknown"), value: countWhere(known, (c) => !["valid", "warning", "critical", "expired"].includes(c.status)), tone: "unknown" },
        ]}
      />
      <Section title={t("Renewal")} span={4} description={t("What renews each certificate, and where the panel learnt of it.")}>
        {!known ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : !list.length ? (
          <p className="source" style={{ margin: 0 }}>{t("No certificate is watched on this host yet.")}</p>
        ) : (
          <>
            <Breakdown
              items={tally((c) => c.renewal || t("unknown")).map(([renewal, count]) => ({
                label: renewal, value: count, tone: renewal === "manual" ? "warn" as const : renewal === "unknown" ? "unknown" as const : "ok" as const,
              }))}
            />
            <p className="widget-subhead">{t("Source")}</p>
            <Breakdown items={tally((c) => c.source).map(([source, count]) => ({ label: source, value: count }))} />
          </>
        )}
      </Section>

      {form === "watch" && <WatchForm onSave={(body) => watch.mutate(body)} />}
      {form === "deploy" && (
        <DeployForm targets={targets} hostname={host.hostname} onIntent={setIntent} />
      )}

      <Section title={t("Certificates")} count={list.length} span={12} flush>
        {!list.length ? (
          <Empty>
            {t("No certificate is watched on this host yet. Add a path, or scan the host if certmonger tracks something here.")}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Path")}</th><th>{t("Subject")}</th><th>{t("Expires")}</th><th>{t("Renewal")}</th>
                <th>{t("Source")}</th><th>{t("Key")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {list.map((certificate) => (
                <tr key={certificate.path} className={selected === certificate.path ? "selected" : undefined}>
                  <td>
                    <button
                      type="button"
                      className="hm-link hm-mono"
                      onClick={() => setSelected(selected === certificate.path ? "" : certificate.path)}
                    >
                      {certificate.path}
                    </button>
                    {certificate.owner_service && (
                      <div className="source">{certificate.owner_service}</div>
                    )}
                  </td>
                  <td>
                    {certificate.unavailable_reason ? (
                      <span className="badge unknown">{certificate.unavailable_reason}</span>
                    ) : (
                      <>
                        {certificate.subject}
                        {certificate.sans?.length ? (
                          <div className="source">{certificate.sans.join(", ")}</div>
                        ) : null}
                      </>
                    )}
                  </td>
                  <td>
                    <StatusBadge status={certificate.status} days={certificate.days_to_expiry} />
                    {certificate.not_after && (
                      <div className="source"><Time value={certificate.not_after} /></div>
                    )}
                  </td>
                  <td>
                    {/* "Manual" is a finding: the daemon answered that it does
                        not watch this file. "Unknown" is a missing answer. */}
                    {certificate.renewal === "tracked" ? (
                      <>
                        <span className="badge ok">certmonger</span>
                        {certificate.tracking?.status && (
                          <div className="source">{certificate.tracking.status}</div>
                        )}
                      </>
                    ) : certificate.renewal === "manual" ? (
                      <span className="badge warn">{t("manual")}</span>
                    ) : (
                      unknown
                    )}
                  </td>
                  <td>
                    {certificate.managed ? (
                      <>
                        <span className="badge ok">{t("panel")}</span>
                        {certificate.deployed_at && (
                          <div className="source">
                            <Time value={certificate.deployed_at} /> · {certificate.deployed_by}
                          </div>
                        )}
                      </>
                    ) : certificate.source === "certmonger" ? (
                      <span className="badge">certmonger</span>
                    ) : (
                      <span className="badge">{t("outside the panel")}</span>
                    )}
                  </td>
                  <td>
                    {!certificate.key ? (
                      <span className="source">—</span>
                    ) : certificate.key.reason ? (
                      <span className="badge unknown">{certificate.key.reason}</span>
                    ) : !certificate.key.exists ? (
                      <span className="badge error">{t("missing")}</span>
                    ) : certificate.key.world_readable ? (
                      <span className="badge error">{t("mode {mode}, world-readable", { mode: certificate.key.mode ?? "" })}</span>
                    ) : (
                      <span className="source hm-mono">
                        {certificate.key.mode} {certificate.key.owner}
                      </span>
                    )}
                    {certificate.key_secret && (
                      <div className="source">{t("secret")} {certificate.key_secret}</div>
                    )}
                  </td>
                  <td>
                    <div className="operations">
                      <button
                        className="secondary"
                        disabled={certificate.renewal !== "tracked" || !certificate.tracking?.request}
                        onClick={() =>
                          setIntent({
                            action: "certificate.renew",
                            label: t("Renew certificate"),
                            description:
                              t("certmonger on {host} is asked to reissue request {request} for {path}", {
                                host: host.hostname, request: certificate.tracking?.request ?? "", path: certificate.path,
                              }) +
                              (certificate.reload_unit ? `, ${t("then {unit} is reloaded", { unit: certificate.reload_unit })}` : "") +
                              ".",
                            payload: {
                              certificate: {
                                request: certificate.tracking?.request ?? "",
                                path: certificate.path,
                                reload_unit: certificate.reload_unit ?? "",
                                probe_target: certificate.probe_target ?? "",
                              },
                            },
                          })
                        }
                      >
                        {t("Renew")}
                      </button>
                      {certificate.watched && (
                        <button className="secondary" onClick={() => forget.mutate(certificate.path)}>
                          {t("Stop watching")}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>

      {selected && <Details hostID={host.id} certificate={list.find((c) => c.path === selected)} />}

      {data?.missing && Object.keys(data.missing).length > 0 && (
        <Section
          title={t("Not established")}
          count={Object.keys(data.missing).length}
          description={t("Facts the host could not collect. Each one is an answer of \"not known\", not a value of zero.")}
          flush
        >
          <Table>
            <thead><tr><th>{t("Fact")}</th><th>{t("Reason")}</th></tr></thead>
            <tbody>
              {Object.entries(data.missing).map(([fact, reason]) => (
                <tr key={fact}><td className="hm-mono">{fact}</td><td className="source">{reason}</td></tr>
              ))}
            </tbody>
          </Table>
        </Section>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ action: intent.action, reason, payload: intent.payload })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}

/** Certificate details together with the deployment history of this file. */
function Details({ hostID, certificate }: { hostID: string; certificate?: Certificate }) {
  const t = useT();
  const history = useQuery({
    queryKey: ["certificate-deployments", hostID, certificate?.path],
    queryFn: () =>
      api.get<{ items: Deployment[] }>(
        `/api/v1/hosts/${hostID}/certificates/deployments?path=${encodeURIComponent(certificate?.path ?? "")}`,
      ),
    enabled: !!certificate,
  });
  if (!certificate) return null;
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  // The facts of the file beside its deployment history: one row for the
  // chosen certificate, not two blocks under the list.
  return (
    <div className="columns">
      <Section title={<span className="hm-mono">{certificate.path}</span>} flush>
        <Facts>
          <Fact label={t("Issuer")}>{certificate.issuer || unknown}</Fact>
          <Fact label={t("Serial")}><span className="hm-mono">{certificate.serial || "—"}</span></Fact>
          <Fact label={t("Key")}>
            {certificate.key_algorithm
              ? `${certificate.key_algorithm} ${certificate.key_bits}`
              : unknown}
          </Fact>
          <Fact label={t("Chain")}>
            {/* A bare leaf without the chain is the most common reason a
                client rejects the connection despite a valid certificate. */}
            {certificate.chain_length
              ? certificate.chain_length === 1
                ? t("leaf only — clients that need the issuer will reject it")
                : t("{n} certificates", { n: certificate.chain_length })
              : unknown}
          </Fact>
          <Fact label={t("Valid from")}><Time value={certificate.not_before} /></Fact>
          <Fact label={t("Valid until")}><Time value={certificate.not_after} /></Fact>
          <Fact label={t("Fingerprint")} wide>
            <span className="hm-mono">{certificate.fingerprint_sha256 || "—"}</span>
          </Fact>
          {certificate.tracking?.request && (
            <Fact label="certmonger" wide>
              <span className="source">
                {t("request")} {certificate.tracking.request} · CA {certificate.tracking.ca} ·{" "}
                {t("auto-renew")} {certificate.tracking.auto_renew ? t("yes") : t("no")}
              </span>
            </Fact>
          )}
        </Facts>
      </Section>

      <Section title={t("Deployments from the panel")} count={(history.data?.items ?? []).length} flush>
        {!(history.data?.items ?? []).length ? (
          <Empty>{t("The panel has never deployed this file.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Fingerprint")}</th><th>{t("Expires")}</th><th>{t("Key")}</th><th>{t("Deployed")}</th><th>{t("By")}</th></tr>
            </thead>
            <tbody>
              {(history.data?.items ?? []).map((deployment) => (
                <tr key={`${deployment.fingerprint_sha256}-${deployment.deployed_at}`}>
                  <td className="hm-mono">
                    {deployment.fingerprint_sha256.slice(0, 16)}
                    {deployment.fingerprint_sha256 === certificate.fingerprint_sha256 && (
                      <span className="badge"> {t("on host")}</span>
                    )}
                  </td>
                  <td><Time value={deployment.not_after} /></td>
                  <td className="source hm-mono">
                    {deployment.key_secret
                      ? `${deployment.key_secret}@v${deployment.key_secret_version}`
                      : "—"}
                  </td>
                  <td><Time value={deployment.deployed_at} /></td>
                  <td>{deployment.deployed_by}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
    </div>
  );
}

/** The watch scope form. This is not an operation on the host. */
function WatchForm({ onSave }: { onSave: (body: Record<string, unknown>) => void }) {
  const t = useT();
  const [path, setPath] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [secret, setSecret] = useState("");
  const [unit, setUnit] = useState("");
  const [probe, setProbe] = useState("");
  const [service, setService] = useState("");

  return (
    <Section
      title={t("Watch a path")}
      description={t("This changes what the panel looks at, not the host. The service that reads the file and the address where the result is visible are yours to fill in — the panel does not guess them from a directory name.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Path")}>
            <input value={path} onChange={(e) => setPath(e.target.value)}
              placeholder="/etc/pki/tls/certs/service.crt" />
          </Field>
          <Field label={t("Key")}>
            <input value={keyPath} onChange={(e) => setKeyPath(e.target.value)}
              placeholder="/etc/pki/tls/private/service.key" />
          </Field>
          <Field label={t("Key secret (name only)")}>
            <input value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
          <Field label={t("Reload unit (httpd.service)")}>
            <input value={unit} onChange={(e) => setUnit(e.target.value)} />
          </Field>
          <Field label={t("Probe target (host:443)")}>
            <input value={probe} onChange={(e) => setProbe(e.target.value)} />
          </Field>
          <Field label={t("Owner service")}>
            <input value={service} onChange={(e) => setService(e.target.value)} />
          </Field>
        </Fields>
        <FormActions>
          <button
            disabled={!path}
            onClick={() =>
              onSave({
                path, key_path: keyPath, key_secret: secret,
                reload_unit: unit, probe_target: probe, service,
              })
            }
          >
            {t("Watch")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}

/** The certificate deployment form. The key is named by a secret. */
function DeployForm({
  targets, hostname, onIntent,
}: {
  targets: Target[];
  hostname: string;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const [path, setPath] = useState(targets[0]?.path ?? "");
  const [content, setContent] = useState("");
  const chosen = targets.find((target) => target.path === path);

  return (
    <Section
      title={t("Deploy a certificate")}
      description={t("Paste the certificate with its chain, leaf first. The private key is not pasted here and never travels in the job: the host fetches it from the secret named on the watched path, once, while it runs the operation.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field
            label={t("Watched path")}
            wide
            help={chosen && (
              <>
                {t("Key")}: {chosen.key_path || t("not set")}
                {chosen.key_secret ? ` ${t("from secret {secret}", { secret: chosen.key_secret })}` : ` — ${t("no secret set, the key stays as it is")}`} ·{" "}
                {t("reload")} {chosen.reload_unit || t("nothing")} ·{" "}
                {t("probe")} {chosen.probe_target || t("none")}
              </>
            )}
          >
            <select value={path} onChange={(e) => setPath(e.target.value)}>
              {targets.length === 0 && <option value="">{t("no watched path on this host")}</option>}
              {targets.map((target) => (
                <option key={target.id} value={target.path}>{target.path}</option>
              ))}
            </select>
          </Field>
          <Field label={t("Certificate (PEM, leaf first)")} wide>
            <textarea rows={10} value={content} onChange={(e) => setContent(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----" />
          </Field>
        </Fields>
        <FormActions>
          <button
            disabled={!path || !content.includes("BEGIN CERTIFICATE")}
            onClick={() =>
              onIntent({
                action: "certificate.deploy",
                label: t("Deploy certificate"),
                description:
                  t("{path} on {host} is replaced", { path, host: hostname }) +
                  (chosen?.key_secret ? `, ${t("with the key from secret {secret}", { secret: chosen.key_secret })}` : "") +
                  (chosen?.reload_unit ? `, ${t("then {unit} is reloaded", { unit: chosen.reload_unit })}` : "") +
                  (chosen?.probe_target ? ` ${t("and {target} is checked", { target: chosen.probe_target })}` : "") +
                  `. ${t("The host verifies key and chain before the swap and rolls back if the service does not come back with the new certificate.")}`,
                payload: {
                  certificate: {
                    path,
                    key_path: chosen?.key_path ?? "",
                    certificate: content,
                    reload_unit: chosen?.reload_unit ?? "",
                    probe_target: chosen?.probe_target ?? "",
                    ...(chosen?.key_secret ? { key_secret: { name: chosen.key_secret } } : {}),
                  },
                },
              })
            }
          >
            {t("Deploy")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
