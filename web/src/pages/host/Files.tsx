import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { useHost } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

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
};

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
 *
 * This is not root's file manager: the path range is set by the host
 * administrator, and files with password hashes, private keys and sudo
 * rules are not editable here at all - each of those things has a module of
 * its own.
 */
export function Files() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [selected, setSelected] = useState("");
  const [adding, setAdding] = useState(false);

  const files = useQuery({
    queryKey: ["managed-files", host.id],
    queryFn: () => api.get<{ items: ManagedFile[] }>(`/api/v1/hosts/${host.id}/files`),
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
      setAdding(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["managed-files", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (files.error) return <ErrorBox error={files.error} />;
  const list = files.data?.items ?? [];

  return (
    <>
      <p className="subtitle">
        {t("Files the panel manages, with the content it expects and the content the host actually has. Paths are limited by the host's own allowlist, and password files, private keys and sudo rules are never editable here.")}
      </p>

      <div className="filters">
        <button onClick={() => setAdding((open) => !open)}>
          {adding ? t("Cancel") : t("Manage a file")}
        </button>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {adding && <NewFile onIntent={setIntent} />}

      {!list.length ? (
        <Empty>{t("The panel does not manage any file on this host yet.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Path")}</th><th>{t("State")}</th><th>{t("Mode")}</th><th>{t("Last change")}</th><th>{t("Actions")}</th></tr>
          </thead>
          <tbody>
            {list.map((file) => (
              <tr key={file.path}>
                <td>
                  <a href="#" onClick={(e) => { e.preventDefault(); setSelected(selected === file.path ? "" : file.path); }}>
                    {file.path}
                  </a>
                </td>
                {/* Drift is an established divergence, not a default one: a
                    file the host did not read is neither matching nor
                    drifted. */}
                <td>
                  {file.unavailable_reason ? (
                    <span className="badge unknown">{file.unavailable_reason}</span>
                  ) : !file.exists ? (
                    <span className="badge unknown">{t("missing on host")}</span>
                  ) : file.drift ? (
                    <span className="badge unknown">{t("changed outside the panel")}</span>
                  ) : file.drift_unknown_reason ? (
                    // The panel holds no fingerprint of content from a
                    // secret, so it does not pretend the file matches - it
                    // says what it does not check.
                    <span className="badge unknown" title={file.drift_unknown_reason}>
                      {t("content not compared")}
                    </span>
                  ) : (
                    t("matches")
                  )}
                </td>
                <td>
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
                    <button
                      onClick={() =>
                        request.mutate({ action: "file.read", payload: { file: { path: file.path } } })
                      }
                    >
                      {t("Read")}
                    </button>
                    <button
                      className="secondary"
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
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

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
    </>
  );
}

/**
 * The file's version history together with a difference preview.
 *
 * The return is to a specific version, not "undo the last change": the
 * operator picks the content they saw.
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
      <h2>{file.path}</h2>
      <table>
        <thead><tr><th>{t("Version")}</th><th>{t("Size")}</th><th>{t("Applied")}</th><th>{t("By")}</th><th>{t("Actions")}</th></tr></thead>
        <tbody>
          {(history.data?.items ?? []).map((version) => (
            <tr key={`${version.sha256 || version.secret_name}-${version.applied_at}`}>
              <td className="source">
                {/* An entry from a secret has no content in the panel: we
                    show which secret version was deployed, because that is
                    all the panel knows. */}
                {version.sha256
                  ? version.sha256.slice(0, 12)
                  : `${version.secret_name}@v${version.secret_version}`}
                {version.sha256 && version.sha256 === file.desired_sha256 && (
                  <span className="badge"> {t("current")}</span>
                )}
              </td>
              <td>{version.sha256 ? `${version.size_bytes} B` : "—"}</td>
              <td><Time value={version.applied_at} /></td>
              <td>{version.applied_by}</td>
              <td>
                <div className="operations">
                  <button onClick={() => setComparison(version.sha256 ?? "")} disabled={!version.sha256}>
                    {t("Compare")}
                  </button>
                  <button
                    className="secondary"
                    disabled={!version.sha256 || (version.sha256 === file.desired_sha256 && !file.drift)}
                    onClick={() =>
                      onIntent({
                        action: "file.rollback",
                        label: t("Roll back file"),
                        description: t("{path} on {host} goes back to version {version} from {when}.", {
                          path: file.path, host: hostname, version: (version.sha256 ?? "").slice(0, 12), when: new Date(version.applied_at).toLocaleString(),
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
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {comparison && chosen.data && current.data && (
        <>
          <h2>{t("Difference")}</h2>
          <p className="subtitle">
            {t("Left: version {version}. Right: what the panel expects now.", { version: comparison.slice(0, 12) })}
          </p>
          <Difference before={chosen.data.content} after={current.data.content} />
        </>
      )}
    </>
  );
}

/**
 * A line-by-line difference preview.
 *
 * A simple split into lines is enough for configuration files: the
 * operator asks which line changed, not about a change halfway through a
 * word.
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
    <pre style={{ marginTop: 8, maxHeight: 420, overflowY: "auto" }}>
      {rows.map((row, index) => (
        <div
          key={index}
          style={{
            color: row.sign === "+" ? "#3fa34d" : row.sign === "-" ? "#c0392b" : undefined,
          }}
        >
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
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("Manage a file")}</h2>
      <p className="subtitle" style={{ margin: 0 }}>
        {t("A file that already exists needs the checksum of the content you reviewed — read it first. Without that, a change someone made after you looked would vanish under this write.")}
      </p>
      <label>
        {t("From a secret (leave empty to write the content below)")}
        <input
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder="repo.token"
        />
      </label>
      {fromSecret && (
        <p className="subtitle" style={{ margin: 0 }}>
          {t("The value never travels in the job: the host fetches it from the store when it starts the operation. The panel keeps no copy and no checksum of it, so it will not be able to tell you later whether somebody changed this file on the host — only which secret version was deployed.")}
        </p>
      )}
      <div className="filters">
        <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/etc/example.conf" style={{ minWidth: 280 }} />
        <input value={mode} onChange={(e) => setMode(e.target.value)} placeholder={t("Mode")} style={{ width: 100 }} />
        <input value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} placeholder={t("Expected sha256 (existing file)")} style={{ minWidth: 260 }} />
      </div>
      {!fromSecret && (
        <label>
          {t("Content")}
          <textarea rows={10} value={content} onChange={(e) => setContent(e.target.value)} />
        </label>
      )}
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
    </div>
  );
}
