import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { useHost } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Definition = {
  id: string;
  name: string;
  tool: string;
  repository?: string;
  paths?: string[];
  excludes?: string[];
  tags?: string[];
  keep_last?: number;
  keep_daily?: number;
  keep_weekly?: number;
  keep_monthly?: number;
  prune?: boolean;
  runbook?: string;
  initialize?: boolean;
  password_secret?: string;
  env_secrets?: Record<string, string>;
  note?: string;
  updated_by: string;
  updated_at: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  last_run_at?: string;
  last_verify_at?: string;
  unverified: boolean;
  snapshots?: number;
  repository_size?: number;
};

type Tool = { name: string; available: boolean; version?: string };

type Report = {
  host_id: string;
  definitions: Definition[];
  status: string;
  tools?: { tools?: Tool[]; runbooks?: string[]; runbooks_known?: boolean };
};

type Snapshot = { id: string; time: string; paths?: string[]; tags?: string[]; size_bytes?: number };

type RepositoryState = {
  tool?: string;
  tool_version?: string;
  snapshots?: Snapshot[];
  last_success_at?: string;
  total_size_bytes?: number;
  unavailable_reason?: string;
};

type AttemptDetail = {
  kind?: string;
  message?: string;
  state?: RepositoryState;
  outcome?: { snapshot_id?: string; bytes_added?: number; message?: string };
};

type Attempt = { status?: string; message?: string; detail?: AttemptDetail };

type Run = {
  definition: string;
  kind: string;
  outcome: string;
  snapshot_id?: string;
  bytes_added?: number;
  files_new?: number;
  duration_seconds?: number;
  snapshots?: number;
  repository_size?: number;
  message?: string;
  started_by?: string;
  recorded_at: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** A size in human-readable form. A missing value is not zero. */
function Size({ bytes }: { bytes?: number }) {
  const t = useT();
  if (bytes === undefined || bytes === null) return <span className="badge unknown">{t("unknown")}</span>;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return <>{`${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`}</>;
}

function StatusBadge({ status, age }: { status: string; age?: number }) {
  const t = useT();
  const cls =
    status === "ok" ? "ok" : status === "warning" ? "warn" : status === "unknown" ? "unknown" : "error";
  const caption =
    status === "never"
      ? t("no backup yet")
      : age === undefined
        ? status
        : age < 48
          ? t("{n} h old", { n: Math.round(age) })
          : t("{n} d old", { n: Math.round(age / 24) });
  return <span className={`badge ${cls}`}>{caption}</span>;
}

/**
 * The host's backups.
 *
 * The data does not flow through the panel: the host talks to the
 * repository directly, and the panel sees the metadata - when a copy
 * succeeded, how much it takes and whether anyone ever checked it. The
 * repository password is named by a secret; the host fetches its value once,
 * at the moment of the operation.
 */
export function Backups() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState(false);
  const [selected, setSelected] = useState("");
  const [planJob, setPlanJob] = useState("");

  const report = useQuery({
    queryKey: ["backups", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/backups`),
  });

  // The copy list belongs to the job, not to the panel state: it is the
  // repository's answer from one moment, after the password was given.
  const plan = useQuery({
    queryKey: ["job-attempts", planJob],
    queryFn: () => api.get<{ items: Attempt[] }>(`/api/v1/jobs/${planJob}/attempts`),
    enabled: planJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: Attempt[] } | undefined)?.items;
      return attempts?.[attempts.length - 1]?.status ? false : 2000;
    },
  });
  const planAttempts = plan.data?.items ?? [];
  const lastPlan = planAttempts[planAttempts.length - 1];
  const repositoryState = lastPlan?.detail?.state;

  const history = useQuery({
    queryKey: ["backup-runs", host.id, selected],
    queryFn: () =>
      api.get<{ items: Run[] }>(
        `/api/v1/hosts/${host.id}/backups/runs?definition=${encodeURIComponent(selected)}`,
      ),
    enabled: selected !== "",
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job, variables) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      if ((variables as { action?: string }).action === "backup.plan") setPlanJob(job.id);
      setIntent(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Definition>(`/api/v1/hosts/${host.id}/backups`, body),
    onSuccess: (definition) => {
      setMessage(t("Definition {name} saved. Plan it to read the repository.", { name: definition.name }));
      setForm(false);
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const remove = useMutation({
    mutationFn: (name: string) =>
      api.del(`/api/v1/hosts/${host.id}/backups?name=${encodeURIComponent(name)}`),
    onSuccess: () => {
      setMessage(t("Definition removed. The history of its runs stays."));
      queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (report.error) return <ErrorBox error={report.error} />;
  const definitions = report.data?.definitions ?? [];
  const tools = report.data?.tools?.tools ?? [];
  const runbooks = report.data?.tools?.runbooks ?? [];
  const definition = definitions.find((item) => item.name === selected);

  const definitionRequest = (item: Definition, extra: Record<string, unknown> = {}) => ({
    id: item.name,
    tool: item.tool,
    repository: item.repository ?? "",
    paths: item.paths ?? [],
    excludes: item.excludes ?? [],
    tags: item.tags ?? [],
    keep_last: item.keep_last ?? 0,
    keep_daily: item.keep_daily ?? 0,
    keep_weekly: item.keep_weekly ?? 0,
    keep_monthly: item.keep_monthly ?? 0,
    prune: item.prune ?? false,
    runbook: item.runbook ?? "",
    initialize: item.initialize ?? false,
    ...(item.password_secret ? { password_secret: { name: item.password_secret } } : {}),
    ...(item.env_secrets && Object.keys(item.env_secrets).length
      ? {
          env_secrets: Object.fromEntries(
            Object.entries(item.env_secrets).map(([variable, secret]) => [variable, { name: secret }]),
          ),
        }
      : {}),
    ...extra,
  });

  return (
    <>
      <p className="subtitle">
        {t("Backups run with the tools this host already has. The data never passes through the panel — the host talks to the repository directly, and what you see here is metadata: when a copy last succeeded, how much it takes and whether anyone has ever read it back.")}
      </p>

      <div className="filters">
        {tools.map((tool) => (
          <span key={tool.name} className={`badge ${tool.available ? "ok" : ""}`}>
            {tool.name}
            {tool.available && tool.version ? ` · ${tool.version.split("\n")[0]}` : ""}
            {!tool.available ? ` · ${t("not installed")}` : ""}
          </span>
        ))}
        {runbooks.length > 0 && (
          <span className="source">{t("runbooks")}: {runbooks.join(", ")}</span>
        )}
        <button className="secondary" onClick={() => setForm((open) => !open)}>
          {form ? t("Cancel") : t("Define a backup")}
        </button>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {form && <DefinitionForm runbooks={runbooks} onSave={(body) => save.mutate(body)} />}

      {!definitions.length ? (
        <Empty>
          {t("The panel does not back up anything on this host yet. A definition says what to copy, where to and how long it stays.")}
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Definition")}</th><th>{t("Destination")}</th><th>{t("Last copy")}</th>
              <th>{t("Verified")}</th><th>{t("Size")}</th><th>{t("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {definitions.map((item) => (
              <tr key={item.name}>
                <td>
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setSelected(selected === item.name ? "" : item.name);
                    }}
                  >
                    {item.name}
                  </a>
                  <div className="source">
                    {item.tool}
                    {item.runbook ? ` · ${item.runbook}` : ""}
                    {item.paths?.length ? ` · ${item.paths.join(", ")}` : ""}
                  </div>
                </td>
                <td className="source">
                  {item.repository}
                  {item.password_secret && (
                    <div>{t("password from {secret}", { secret: item.password_secret })}</div>
                  )}
                </td>
                <td>
                  <StatusBadge status={item.status} age={item.age_hours} />
                  {item.last_success_at && (
                    <div className="source"><Time value={item.last_success_at} /></div>
                  )}
                </td>
                <td>
                  {/* A copy nobody has ever read back is a promise, not a
                      safeguard - and it is to look like one. */}
                  {item.unverified ? (
                    <span className="badge warn">{t("not verified")}</span>
                  ) : (
                    <>
                      <span className="badge ok">{t("verified")}</span>
                      <div className="source"><Time value={item.last_verify_at} /></div>
                    </>
                  )}
                </td>
                <td>
                  <Size bytes={item.repository_size} />
                  {item.snapshots !== undefined && (
                    <div className="source">{t("{n} copies", { n: item.snapshots })}</div>
                  )}
                </td>
                <td>
                  <div className="operations">
                    <button
                      className="secondary"
                      disabled={host.connection_state !== "online"}
                      onClick={() =>
                        request.mutate({
                          action: "backup.plan",
                          payload: { backup: definitionRequest(item) },
                        })
                      }
                    >
                      {t("Read repository")}
                    </button>
                    <button
                      className="secondary"
                      onClick={() =>
                        setIntent({
                          action: "backup.run",
                          label: t("Run backup"),
                          description: t("{name} copies {paths} from {host} to {repository}. The data goes straight from the host; the panel only records that it happened.", {
                            name: item.name, paths: (item.paths ?? []).join(", "), host: host.hostname, repository: item.repository ?? "",
                          }),
                          payload: { backup: definitionRequest(item) },
                        })
                      }
                    >
                      {t("Back up now")}
                    </button>
                    <button
                      className="secondary"
                      onClick={() =>
                        setIntent({
                          action: "backup.verify",
                          label: t("Verify backup"),
                          description: t("{name} is checked on {host}, including reading part of the data back. Until something reads a copy, it is a promise, not a safeguard.", {
                            name: item.name, host: host.hostname,
                          }),
                          payload: { backup: definitionRequest(item, { read_data: true }) },
                        })
                      }
                    >
                      {t("Verify")}
                    </button>
                    <button className="secondary" onClick={() => remove.mutate(item.name)}>
                      {t("Forget")}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {repositoryState && (
        <>
          <h2>{t("Copies in the repository")}</h2>
          {repositoryState.unavailable_reason ? (
            <p className="warning">
              <span>{t("The repository could not be read: {reason}", { reason: repositoryState.unavailable_reason })}</span>
            </p>
          ) : !repositoryState.snapshots?.length ? (
            <Empty>{t("The repository holds no copy yet.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Copy")}</th><th>{t("Taken")}</th><th>{t("Paths")}</th><th>{t("Restore")}</th></tr>
              </thead>
              <tbody>
                {[...repositoryState.snapshots].reverse().map((snapshot) => (
                  <tr key={snapshot.id}>
                    <td className="source">{snapshot.id}</td>
                    <td><Time value={snapshot.time} /></td>
                    <td className="source">{snapshot.paths?.join(", ")}</td>
                    <td>
                      <button
                        className="secondary"
                        disabled={!definition}
                        onClick={() => {
                          const target = window.prompt(
                            t("Restore into which directory? The panel never restores straight into system directories, and not into /tmp either — the host helper has its own private one, where restored data would vanish with the operation."),
                            "/srv/flotestro-restore",
                          );
                          if (!target || !definition) return;
                          setIntent({
                            action: "backup.restore",
                            label: t("Restore copy"),
                            description: t("Copy {id} is unpacked into {target} on {host}. The target must be empty; what goes back from there to its place is a separate decision.", {
                              id: snapshot.id, target, host: host.hostname,
                            }),
                            payload: {
                              backup: definitionRequest(definition, {
                                snapshot_id: snapshot.id,
                                target,
                                overwrite: "empty-target",
                              }),
                            },
                          });
                        }}
                      >
                        {t("Restore…")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="source">
            {t("Read from the repository by job {id}", { id: planJob.slice(0, 8) })}
            {repositoryState.tool_version
              ? ` · ${repositoryState.tool_version.split("\n")[0]}`
              : ""}
          </p>
        </>
      )}

      {selected && (
        <>
          <h2>{t("History of {name}", { name: selected })}</h2>
          {!(history.data?.items ?? []).length ? (
            <Empty>{t("Nothing has run for this definition yet.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("When")}</th><th>{t("Operation")}</th><th>{t("Result")}</th><th>{t("Copy")}</th><th>{t("Added")}</th><th>{t("By")}</th></tr>
              </thead>
              <tbody>
                {(history.data?.items ?? []).map((run, index) => (
                  <tr key={`${run.recorded_at}-${index}`}>
                    <td><Time value={run.recorded_at} /></td>
                    <td>{run.kind}</td>
                    <td>
                      {run.outcome === "succeeded" ? (
                        <span className="badge ok">{t("succeeded")}</span>
                      ) : (
                        <span className="badge error">{t("failed")}</span>
                      )}
                      {run.message && <div className="source">{run.message}</div>}
                    </td>
                    <td className="source">{run.snapshot_id || "—"}</td>
                    <td>{run.bytes_added === undefined ? "—" : <Size bytes={run.bytes_added} />}</td>
                    <td className="source">{run.started_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
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
    </>
  );
}

/** The backup definition form. The repository password is named by a secret. */
function DefinitionForm({
  runbooks, onSave,
}: {
  runbooks: string[];
  onSave: (body: Record<string, unknown>) => void;
}) {
  const t = useT();
  const [name, setName] = useState("");
  const [tool, setTool] = useState("restic");
  const [repository, setRepository] = useState("");
  const [paths, setPaths] = useState("");
  const [excludes, setExcludes] = useState("");
  const [secret, setSecret] = useState("");
  const [runbook, setRunbook] = useState("");
  const [keepLast, setKeepLast] = useState("7");
  const [initialize, setInitialize] = useState(true);

  const byRunbook = tool === "runbook";
  const ready = name !== "" && (byRunbook ? runbook !== "" : repository !== "" && paths !== "");

  return (
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("Backup definition")}</h2>
      <p className="subtitle" style={{ margin: 0 }}>
        {t("The repository password is named, not pasted: the host fetches its value from the secret store once, while the backup runs, and passes it to the tool through the environment — never as a command-line argument, which every user on the host can read.")}
      </p>
      <div className="filters">
        <input value={name} onChange={(e) => setName(e.target.value)}
               placeholder="nightly" style={{ minWidth: 160 }} />
        <select value={tool} onChange={(e) => setTool(e.target.value)}>
          <option value="restic">restic</option>
          <option value="borg">borg</option>
          <option value="runbook">runbook</option>
        </select>
        {byRunbook ? (
          <select value={runbook} onChange={(e) => setRunbook(e.target.value)}>
            <option value="">{t("choose a runbook")}</option>
            {runbooks.map((runbookName) => (
              <option key={runbookName} value={runbookName}>{runbookName}</option>
            ))}
          </select>
        ) : null}
        <input value={repository} onChange={(e) => setRepository(e.target.value)}
               placeholder="/srv/backup or s3:https://…" style={{ minWidth: 280 }} />
      </div>
      <div className="filters">
        <input value={paths} onChange={(e) => setPaths(e.target.value)}
               placeholder={t("Paths (/etc /var/lib/app)")} style={{ minWidth: 280 }} />
        <input value={excludes} onChange={(e) => setExcludes(e.target.value)}
               placeholder={t("Excludes (*.tmp)")} style={{ minWidth: 200 }} />
        <input value={secret} onChange={(e) => setSecret(e.target.value)}
               placeholder={t("Password secret (name only)")} style={{ minWidth: 220 }} />
        <input value={keepLast} onChange={(e) => setKeepLast(e.target.value)}
               placeholder={t("Keep last")} style={{ width: 110 }} />
      </div>
      <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={initialize} onChange={(e) => setInitialize(e.target.checked)} />
        {t("Create the repository on the first backup if it does not exist yet")}
      </label>
      <button
        disabled={!ready}
        onClick={() =>
          onSave({
            name, tool, repository, initialize,
            paths: paths.split(/[\s,]+/).filter(Boolean),
            excludes: excludes.split(/[\s,]+/).filter(Boolean),
            keep_last: Number(keepLast) || 0,
            runbook: byRunbook ? runbook : "",
            password_secret: secret,
          })
        }
      >
        {t("Save definition")}
      </button>
    </div>
  );
}
