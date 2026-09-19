import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { EmptyState } from "../../components/layout";
import { absoluteTime, bytes } from "../../lib/format";
import { Breakdown } from "../../components/widgets";
import {
  Field, Fields, Form, FormActions, JobNotice, Message, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere,
  useHost,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import { useT } from "../../i18n";

/**
 * A copy of the file the host itself kept before a write took its place. The
 * panel's own history covers only what the panel sent.
 */
type HostVersion = {
  // No checksum means a version whose content came from the secret store:
  // the host keeps the copy but does not name it, because the checksum of a
  // short secret is a hint about it.
  sha256?: string;
  size_bytes: number;
  mode?: string;
  owner?: string;
  group?: string;
  kept_at: string;
  ordered_by?: string;
  from_secret?: boolean;
};

type ManagedFile = {
  path: string;
  // An empty desired-state fingerprint means a file from a secret: the
  // panel then holds neither the content nor its fingerprint.
  desired_sha256?: string;
  desired_secret?: string;
  desired_secret_version?: number;
  mode?: string;
  owner?: string;
  group?: string;
  validator?: string;
  updated_by: string;
  updated_at: string;
  observed_sha256?: string;
  exists: boolean;
  drift: boolean;
  drift_unknown_reason?: string;
  observed_mode?: string;
  observed_owner?: string;
  unavailable_reason?: string;
  // The versions the host keeps of this file, newest first.
  host_versions?: HostVersion[];
};

/**
 * Why a version the host keeps cannot be ordered back, or an empty string
 * when it can.
 */
export function hostVersionRefusal(version: HostVersion): "" | "from_secret" | "no_checksum" {
  if (version.from_secret) return "from_secret";
  if (!version.sha256) return "no_checksum";
  return "";
}

/**
 * The order that puts a version the host kept back in place.
 */
export function hostRollbackPayload(file: ManagedFile, version: HostVersion) {
  return {
    file: {
      path: file.path,
      version_sha256: version.sha256,
      expected_sha256: file.observed_sha256 ?? "",
      mode: version.mode ?? "",
    },
  };
}

type Version = {
  sha256?: string;
  secret_name?: string;
  secret_version?: number;
  size_bytes: number;
  job_id?: string;
  applied_by: string;
  applied_at: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/**
 * The host's configuration files.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const FILE_CHANGES = ["file.ensure", "file.remove", "file.rollback"];

export function Files() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [selected, setSelected] = useState("");
  const [adding, setAdding] = useState(false);
  // The last job ordered from this page, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);

  const files = useQuery({
    queryKey: ["managed-files", host.id],
    queryFn: () => api.get<{ items: ManagedFile[] }>(`/api/v1/hosts/${host.id}/files`),
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setOrdered(job);
      setMessage("");
      setIntent(null);
      setAdding(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["managed-files", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (files.error) return <ErrorBox error={files.error} />;
  const list = files.data?.items ?? [];
  const drifted = list.filter((file) => file.exists && file.drift).length;
  const missing = list.filter((file) => !file.unavailable_reason && !file.exists).length;
  // The list is unknown until it loads; then every file is in one of four
  // states, and a file the host could not read is in the unknown one.
  const known = files.data ? list : undefined;
  const unreadable = (file: ManagedFile) => !!file.unavailable_reason || !!file.drift_unknown_reason;
  const editors = Object.entries(list.reduce<Record<string, number>>((acc, file) => {
    acc[file.updated_by] = (acc[file.updated_by] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Files")}
        description={t("Files the panel manages, with the content it expects and the content the host actually has. Paths are limited by the host's own allowlist, and password files, private keys and sudo rules are never editable here.")}
        actions={
          <ActionGuard action="file.ensure" host={host.id}>
            <button onClick={() => setAdding((open) => !open)}>
              {adding ? t("Cancel") : t("Manage a file")}
            </button>
          </ActionGuard>
        }
      />
      <ReadOnlyModuleNotice host={host.id} actions={FILE_CHANGES} />
      <Message text={message} error />
      {ordered && <JobNotice job={ordered} hostID={host.id} />}

      <Widgets>
      {/* The files by whether the host has what the panel expects: the
          reason to open the page, before the list. Two cards of zeros
          over an empty list say nothing the empty state does not, so the
          summaries wait for the first file. */}
      {(!files.data || list.length > 0) && (
      <>
      <Summary
        title={t("Managed files")}
        description={t("What the host has against what the panel expects.")}
        span={8}
        segments={[
          { label: t("as expected"), value: countWhere(known, (file) => file.exists && !file.drift && !unreadable(file)), tone: "ok" },
          { label: t("changed outside the panel"), value: known ? drifted : undefined, tone: "warn" },
          { label: t("missing on host"), value: known ? missing : undefined, tone: "error" },
          { label: t("unknown"), value: countWhere(known, unreadable), tone: "unknown" },
        ]}
      />
      <Section title={t("Content")} span={4} description={t("Where the content comes from, and who last wrote it.")}>
        {known ? (
          <>
            <Breakdown
              items={[
                { label: t("from the panel"), value: countWhere(known, (file) => !file.desired_secret) ?? 0, tone: "info" },
                { label: t("from a secret"), value: countWhere(known, (file) => !!file.desired_secret) ?? 0, tone: "info" },
                { label: t("with a validator"), value: countWhere(known, (file) => !!file.validator) ?? 0, tone: "ok" },
              ]}
            />
            {editors.length > 0 && (
              <>
                <p className="widget-subhead">{t("Last changed by")}</p>
                <Breakdown items={editors.map(([who, count]) => ({ label: who, value: count }))} />
              </>
            )}
          </>
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        )}
      </Section>
      </>
      )}

      {adding && <ActionGuard action="file.ensure" host={host.id}><NewFile onIntent={setIntent} /></ActionGuard>}

      <Section title={t("Files")} count={known ? list.length : undefined} span={12} flush>
        {!files.data ? (
          <Empty>{t("Loading…")}</Empty>
        ) : !list.length ? (
          <EmptyState action={!adding && <ActionGuard action="file.ensure" host={host.id}><button onClick={() => setAdding(true)}>{t("Manage a file")}</button></ActionGuard>}>
            {t("The panel does not manage any file on this host yet. A managed file is written from here, compared with what the host has at every report, and kept in versions.")}
          </EmptyState>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Path")}</th><th>{t("State")}</th><th>{t("Mode")}</th><th>{t("Last change")}</th><th>{t("Actions")}</th></tr>
            </thead>
            <tbody>
              {list.map((file) => (
                <tr key={file.path} className={selected === file.path ? "selected" : undefined}>
                  <td>
                    <button
                      type="button"
                      className="hm-link hm-mono"
                      onClick={() => setSelected(selected === file.path ? "" : file.path)}
                    >
                      {file.path}
                    </button>
                  </td>
                  {/* Drift is an established divergence, not a default one: a
                      file the host did not read is neither matching nor
                      drifted. */}
                  <td>
                    {file.unavailable_reason ? (
                      <span className="badge unknown">{file.unavailable_reason}</span>
                    ) : !file.exists ? (
                      <span className="badge error">{t("missing on host")}</span>
                    ) : file.drift ? (
                      <span className="badge warn">{t("changed outside the panel")}</span>
                    ) : file.drift_unknown_reason ? (
                      // The panel holds no fingerprint of content from a
                      // secret, so it does not pretend the file matches - it
                      // says what it does not check.
                      <span className="badge unknown" title={file.drift_unknown_reason}>
                        {t("content not compared")}
                      </span>
                    ) : (
                      <span className="badge ok">{t("matches")}</span>
                    )}
                  </td>
                  <td className="hm-mono">
                    {file.observed_mode || file.mode || "—"}
                    {file.mode && file.observed_mode && file.mode.replace(/^0+/, "") !== file.observed_mode.replace(/^0+/, "") && (
                      <span className="badge unknown"> {t("want {mode}", { mode: file.mode })}</span>
                    )}
                  </td>
                  <td>
                    <Time value={file.updated_at} /> <span className="source">{t("by {who}", { who: file.updated_by })}</span>
                  </td>
                  <td>
                    <div className="operations">
                      <ActionGuard action="file.read" host={host.id} explain>
                        <button
                          className="secondary"
                          title={t("Ask the host for the file as it is now: its checksum, mode and owner refresh in this list once the job reports back.")}
                          onClick={() =>
                            request.mutate({ action: "file.read", payload: { file: { path: file.path } } })
                          }
                        >
                          {t("Read from host")}
                        </button>
                      </ActionGuard>
                      <ActionGuard action="file.remove" host={host.id}>
                        <button
                          className="hm-danger"
                          title={t("Deletes the file on the host and stops managing it; the versions stay in the history.")}
                          onClick={() =>
                            setIntent({
                              action: "file.remove",
                              label: t("Stop managing and remove"),
                              description: t("{path} will be removed from {host} and the panel will stop tracking it. Its history stays.", { path: file.path, host: host.hostname }),
                              payload: {
                                file: { path: file.path, expected_sha256: file.observed_sha256 ?? "" },
                              },
                            })
                          }
                        >
                          {t("Remove")}
                        </button>
                      </ActionGuard>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>

      {selected && (
        <History
          hostID={host.id}
          hostname={host.hostname}
          file={list.find((file) => file.path === selected)}
          onIntent={setIntent}
        />
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

/**
 * The file's version history together with a difference preview.
 */
function History({
  hostID, hostname, file, onIntent,
}: {
  hostID: string;
  hostname: string;
  file?: ManagedFile;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const [comparison, setComparison] = useState("");

  const history = useQuery({
    queryKey: ["file-history", hostID, file?.path],
    queryFn: () =>
      api.get<{ items: Version[] }>(
        `/api/v1/hosts/${hostID}/files/history?path=${encodeURIComponent(file?.path ?? "")}`,
      ),
    enabled: Boolean(file?.path),
  });

  const current = useQuery({
    queryKey: ["file-version", file?.desired_sha256],
    queryFn: () => api.get<{ content: string }>(`/api/v1/files/versions/${file?.desired_sha256}`),
    enabled: Boolean(file?.desired_sha256),
  });

  const chosen = useQuery({
    queryKey: ["file-version", comparison],
    queryFn: () => api.get<{ content: string }>(`/api/v1/files/versions/${comparison}`),
    enabled: comparison !== "",
  });

  if (!file) return null;

  return (
    <>
      <Section title={<span className="hm-mono">{file.path}</span>} count={(history.data?.items ?? []).length} flush>
        <Table>
          <thead><tr><th>{t("Version")}</th><th className="hm-num">{t("Size")}</th><th>{t("Applied")}</th><th>{t("By")}</th><th>{t("Actions")}</th></tr></thead>
          <tbody>
            {(history.data?.items ?? []).map((version) => (
              <tr key={`${version.sha256 || version.secret_name}-${version.applied_at}`}>
                <td className="hm-mono">
                  {/* An entry from a secret has no content in the panel: we
                      show which secret version was deployed, because that is
                      all the panel knows. */}
                  {version.sha256
                    ? version.sha256.slice(0, 12)
                    : `${version.secret_name}@v${version.secret_version}`}
                  {version.sha256 && version.sha256 === file.desired_sha256 && (
                    <span className="badge ok"> {t("current")}</span>
                  )}
                </td>
                <td className="hm-num" title={version.sha256 ? t("{n} bytes", { n: version.size_bytes }) : undefined}>{version.sha256 ? bytes(version.size_bytes) : "—"}</td>
                <td><Time value={version.applied_at} /></td>
                <td>{version.applied_by}</td>
                <td>
                  <div className="operations">
                    <button className="secondary" onClick={() => setComparison(version.sha256 ?? "")} disabled={!version.sha256}>
                      {t("Compare")}
                    </button>
                    <ActionGuard action="file.rollback" host={hostID}>
                      <button
                        className="secondary"
                        disabled={!version.sha256 || (version.sha256 === file.desired_sha256 && !file.drift)}
                        onClick={() =>
                          onIntent({
                            action: "file.rollback",
                            label: t("Roll back file"),
                            description: t("{path} on {host} goes back to version {version} from {when}.", {
                              path: file.path, host: hostname, version: (version.sha256 ?? "").slice(0, 12), when: absoluteTime(version.applied_at),
                            }),
                            payload: {
                              file: {
                                path: file.path,
                                version_sha256: version.sha256,
                                expected_sha256: file.observed_sha256 ?? "",
                                mode: file.mode ?? "",
                              },
                            },
                          })
                        }
                      >
                        {t("Roll back")}
                      </button>
                    </ActionGuard>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      <HostVersions hostID={hostID} hostname={hostname} file={file} onIntent={onIntent} />

      {comparison && chosen.data && current.data && (
        <Section
          title={t("Difference")}
          description={t("Left: version {version}. Right: what the panel expects now.", { version: comparison.slice(0, 12) })}
        >
          <Difference before={chosen.data.content} after={current.data.content} />
        </Section>
      )}
    </>
  );
}

/**
 * The copies of the file the host itself kept.
 */
function HostVersions({
  hostID, hostname, file, onIntent,
}: {
  hostID: string;
  hostname: string;
  file: ManagedFile;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const versions = file.host_versions ?? [];
  if (!versions.length) return null;

  const refusals: Record<string, string> = {
    from_secret: t("The content came from the secret store, so the host does not report its checksum. The copy is there, but the panel cannot name it."),
    no_checksum: t("The host reports no checksum for this version."),
  };

  return (
    <Section
      title={t("Versions kept on the host")}
      count={versions.length}
      description={t("What the file was before each write, kept by the host itself. A return puts back exactly this content, with the permissions it had.")}
      flush
    >
      <Table>
        <thead>
          <tr>
            <th>{t("Version")}</th>
            <th className="hm-num">{t("Size")}</th>
            <th>{t("Mode")}</th>
            <th>{t("Kept")}</th>
            <th>{t("Ordered by")}</th>
            <th>{t("Actions")}</th>
          </tr>
        </thead>
        <tbody>
          {versions.map((version) => {
            const refusal = hostVersionRefusal(version);
            return (
              <tr key={`${version.sha256 ?? "secret"}-${version.kept_at}`}>
                <td className="hm-mono">
                  {version.sha256 ? version.sha256.slice(0, 12) : t("not named")}
                  {version.from_secret && <span className="badge unknown"> {t("from a secret")}</span>}
                </td>
                <td className="hm-num" title={t("{n} bytes", { n: version.size_bytes })}>{bytes(version.size_bytes)}</td>
                <td className="hm-mono">{version.mode || "—"}</td>
                <td><Time value={version.kept_at} /></td>
                <td>{version.ordered_by || "—"}</td>
                <td>
                  <div className="operations">
                    <ActionGuard action="file.rollback" host={hostID}>
                      <button
                        className="secondary"
                        disabled={refusal !== ""}
                        title={refusal ? refusals[refusal] : t("The host writes back exactly this copy, through the same validator as any other write.")}
                        onClick={() =>
                          onIntent({
                            action: "file.rollback",
                            label: t("Restore this version"),
                            description: t("{path} on {host} goes back to the copy the host kept on {when}, with the mode {mode}.", {
                              path: file.path, host: hostname,
                              when: absoluteTime(version.kept_at), mode: version.mode || "—",
                            }),
                            payload: hostRollbackPayload(file, version),
                          })
                        }
                      >
                        {t("Restore")}
                      </button>
                    </ActionGuard>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </Section>
  );
}

/**
 * A line-by-line difference preview.
 */
function Difference({ before, after }: { before: string; after: string }) {
  const old = before.split("\n");
  const fresh = after.split("\n");
  const rows: { sign: string; text: string }[] = [];

  let i = 0;
  let j = 0;
  while (i < old.length || j < fresh.length) {
    if (i < old.length && j < fresh.length && old[i] === fresh[j]) {
      rows.push({ sign: " ", text: old[i] });
      i += 1;
      j += 1;
      continue;
    }
    // A line that appears further on the other side is an addition or a
    // removal; the rest is shown as a change in place.
    if (i < old.length && !fresh.includes(old[i])) {
      rows.push({ sign: "-", text: old[i] });
      i += 1;
      continue;
    }
    if (j < fresh.length && !old.includes(fresh[j])) {
      rows.push({ sign: "+", text: fresh[j] });
      j += 1;
      continue;
    }
    if (i < old.length) {
      rows.push({ sign: "-", text: old[i] });
      i += 1;
    }
    if (j < fresh.length) {
      rows.push({ sign: "+", text: fresh[j] });
      j += 1;
    }
  }

  return (
    <pre className="hm-diff">
      {rows.map((row, index) => (
        <div key={index} className={row.sign === "+" ? "add" : row.sign === "-" ? "del" : undefined}>
          {row.sign} {row.text}
        </div>
      ))}
    </pre>
  );
}

/** The form for the first write of a file. */
function NewFile({ onIntent }: { onIntent: (intent: Intent) => void }) {
  const t = useT();
  const [path, setPath] = useState("");
  const [content, setContent] = useState("");
  const [mode, setMode] = useState("644");
  const [fingerprint, setFingerprint] = useState("");
  const [secret, setSecret] = useState("");

  // Plain content and content from the store exclude each other: otherwise
  // it is unclear what really lands in the file.
  const fromSecret = secret.trim() !== "";

  return (
    <Section
      title={t("Manage a file")}
      description={t("A file that already exists needs the checksum of the content you reviewed — read it first. Without that, a change someone made after you looked would vanish under this write.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Path")} wide>
            <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/etc/example.conf" />
          </Field>
          <Field label={t("Mode")} narrow help={t("Octal, as chmod takes it.")}>
            <input value={mode} onChange={(e) => setMode(e.target.value)} placeholder="0644" />
          </Field>
          <Field label={t("Expected sha256")} help={t("For a file that already exists: the checksum of the content you reviewed. Leave empty for a new file.")}>
            <input value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} placeholder="e3b0c442…" />
          </Field>
          <Field
            label={t("From a secret")}
            help={fromSecret ? t("The value never travels in the job: the host fetches it from the store when it starts the operation. The panel keeps no copy and no checksum of it, so it will not be able to tell you later whether somebody changed this file on the host — only which secret version was deployed.") : t("Leave empty to write the content typed below.")}
          >
            <input
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="repo.token"
            />
          </Field>
          {!fromSecret && (
            <Field label={t("Content")} wide>
              <textarea rows={10} value={content} onChange={(e) => setContent(e.target.value)} />
            </Field>
          )}
        </Fields>
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                action: "file.ensure",
                label: t("Write file"),
                description: fromSecret
                  ? t("{path} will be written with the value of secret {secret}, mode {mode}. The value is fetched by the host at execution time and is stored nowhere else.", { path, secret, mode })
                  : t("{path} will be written with {lines} lines, mode {mode}. The host validates the content first where it knows how.", { path, lines: content.split("\n").length, mode }),
                payload: {
                  file: fromSecret
                    ? {
                        path,
                        content_secret: { name: secret.trim() },
                        mode,
                        expected_sha256: fingerprint,
                      }
                    : { path, content, mode, expected_sha256: fingerprint },
                },
              })
            }
            disabled={!path || (!content && !fromSecret)}
          >
            {t("Write")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
