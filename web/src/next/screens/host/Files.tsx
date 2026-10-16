import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { absoluteTime, bytes, relativeTime } from "../../../lib/format";
import type { Host } from "../../../lib/types";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Banner, Bars, Button, Card, Diff, Empty, Field, Fields, Kpi, Note, Pill, Problem,
  Table, type Segment,
} from "../../kit";
import {
  Confirm, Guard, JobLine, ReadOnlyNotice, useOrder, type Intent,
} from "./Power";

/**
 * The host's configuration files.
 *
 * Files the panel manages, with the content it expects and the content
 * the host actually has. Paths are limited by the host's own allowlist,
 * and password files, private keys and sudo rules are never editable
 * here. Drift is an established divergence, never a default one: a file
 * the host could not read is neither matching nor drifted.
 */

/**
 * A copy of the file the host itself kept before a write took its place.
 * The panel's own history covers only what the panel sent.
 */
type HostVersion = {
  // No checksum means a version whose content came from the secret store:
  // the host keeps the copy but does not name it, because the checksum of
  // a short secret is a hint about it.
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
  /** The versions the host keeps of this file, newest first. */
  host_versions?: HostVersion[];
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

/**
 * Why a version the host keeps cannot be ordered back, or an empty string
 * when it can.
 */
export function hostVersionRefusal(version: HostVersion): "" | "from_secret" | "no_checksum" {
  if (version.from_secret) return "from_secret";
  if (!version.sha256) return "no_checksum";
  return "";
}

/** The order that puts a version the host kept back in place. */
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

/** A line-by-line difference, as the text of a patch anybody can read. */
export function differenceText(before: string, after: string): string {
  const old = before.split("\n");
  const fresh = after.split("\n");
  const rows: string[] = [];
  let i = 0;
  let j = 0;
  while (i < old.length || j < fresh.length) {
    if (i < old.length && j < fresh.length && old[i] === fresh[j]) {
      rows.push(`  ${old[i]}`);
      i += 1;
      j += 1;
      continue;
    }
    // A line that appears further on the other side is an addition or a
    // removal; the rest is shown as a change in place.
    if (i < old.length && !fresh.includes(old[i])) {
      rows.push(`- ${old[i]}`);
      i += 1;
      continue;
    }
    if (j < fresh.length && !old.includes(fresh[j])) {
      rows.push(`+ ${fresh[j]}`);
      j += 1;
      continue;
    }
    if (i < old.length) {
      rows.push(`- ${old[i]}`);
      i += 1;
    }
    if (j < fresh.length) {
      rows.push(`+ ${fresh[j]}`);
      j += 1;
    }
  }
  return rows.join("\n");
}

/** The changes this module offers; when every one is refused, it says so once. */
const FILE_CHANGES = ["file.ensure", "file.remove", "file.rollback"];

export function Files({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [selected, setSelected] = useState("");
  const [adding, setAdding] = useState(false);
  const [comparison, setComparison] = useState("");

  const files = useQuery({
    queryKey: ["managed-files", host.id],
    queryFn: () => api.get<{ items: ManagedFile[] }>(`/api/v1/hosts/${host.id}/files`),
  });

  const order = useOrder(host, () => {
    setIntent(null);
    setAdding(false);
    void queryClient.invalidateQueries({ queryKey: ["managed-files", host.id] });
  });

  const list = files.data?.items ?? [];
  // The list is unknown until it loads; then every file is in one of four
  // states, and a file the host could not read is in the unknown one.
  const known = files.data ? list : undefined;
  const unreadable = (file: ManagedFile) => Boolean(file.unavailable_reason) || Boolean(file.drift_unknown_reason);
  const countWhere = (test: (file: ManagedFile) => boolean) =>
    known === undefined ? undefined : known.filter(test).length;
  const drifted = countWhere((file) => file.exists && file.drift);
  const missing = countWhere((file) => !file.unavailable_reason && !file.exists);

  const states: Segment[] = [
    { label: t("as expected"), value: countWhere((file) => file.exists && !file.drift && !unreadable(file)), tone: "ok" },
    { label: t("changed outside the panel"), value: drifted, tone: "warn" },
    { label: t("missing on host"), value: missing, tone: "error" },
    { label: t("unknown"), value: countWhere(unreadable), tone: "unknown" },
  ];

  const editors = Object.entries(list.reduce<Record<string, number>>((into, file) => {
    into[file.updated_by] = (into[file.updated_by] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const file = list.find((one) => one.path === selected);

  const history = useQuery({
    queryKey: ["file-history", host.id, file?.path],
    queryFn: () => api.get<{ items: Version[] }>(
      `/api/v1/hosts/${host.id}/files/history?path=${encodeURIComponent(file?.path ?? "")}`),
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

  if (files.error) return <Problem>{String(files.error)}</Problem>;

  const hostVersions = file?.host_versions ?? [];
  const refusals: Record<string, string> = {
    from_secret: t("The content came from the secret store, so the host does not report its checksum. The copy is there, but the panel cannot name it."),
    no_checksum: t("The host reports no checksum for this version."),
  };

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={FILE_CHANGES} />
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {order.job && <JobLine job={order.job} hostID={host.id} />}

      <Board screen={FILES_SCREEN} catalogue={HOST_FILES} drawn={{
        managed: (
          <Kpi
            icon="files"
            label={t("Managed files")}
            value={known === undefined ? null : known.length}
            note={t("written from here, compared at every report")}
          />
        ),
        drifted: (
          <Kpi
            icon="files"
            label={t("Changed outside the panel")}
            value={drifted ?? null}
            tone={drifted ? "warn" : "ok"}
          />
        ),
        missing: (
          <Kpi
            icon="files"
            label={t("Missing on host")}
            value={missing ?? null}
            tone={missing ? "error" : "ok"}
          />
        ),
        states: (
          <Card
            title={t("What the host has")}
            note={t("What the host has against what the panel expects.")}
          >
            <Band segments={states} testId="file-states" />
          </Card>
        ),
        content: (
          <Card title={t("Content")} note={t("Where the content comes from, and who last wrote it.")}>
            {known === undefined ? <Empty>{t("Nothing has been read yet.")}</Empty> : (
              <>
                <Bars items={[
                  { label: t("from the panel"), value: countWhere((one) => !one.desired_secret) ?? 0, tone: "info" },
                  { label: t("from a secret"), value: countWhere((one) => Boolean(one.desired_secret)) ?? 0, tone: "info" },
                  { label: t("with a validator"), value: countWhere((one) => Boolean(one.validator)) ?? 0, tone: "ok" },
                ]} />
                {editors.length > 0 && (
                  <>
                    <Note>{t("Last changed by")}</Note>
                    <Bars items={editors.map(([who, count]) => ({ label: who, value: count }))} />
                  </>
                )}
              </>
            )}
          </Card>
        ),
        add: adding ? (
          <Guard action="file.ensure" host={host.id} explain>
            <NewFile host={host} onIntent={setIntent} onClose={() => setAdding(false)} />
          </Guard>
        ) : undefined,
        list: (
          <Card
            title={t("Files")}
            note={known === undefined ? undefined : t("{n} managed on this host.", { n: known.length })}
            tools={(
              <Guard action="file.ensure" host={host.id}>
                <Button kind="quiet" testId="manage-file" onClick={() => setAdding((open) => !open)}>
                  {adding ? t("Cancel") : t("Manage a file")}
                </Button>
              </Guard>
            )}
            flush
          >
            <Table
              rows={list}
              keyOf={(one) => one.path}
              loading={files.isLoading}
              testId="managed-files"
              rowTestId={(one) => `file-${one.path}`}
              empty={t("The panel does not manage any file on this host yet. A managed file is written from here, compared with what the host has at every report, and kept in versions.")}
              columns={[
                { key: "path", head: t("Path"), tight: true, cell: (one) => (
                  <Button
                    kind="word"
                    testId={`open-${one.path}`}
                    onClick={() => { setSelected(selected === one.path ? "" : one.path); setComparison(""); }}
                  >
                    {one.path}
                  </Button>
                ) },
                // Drift is an established divergence, not a default one.
                { key: "state", head: t("State"), cell: (one) => (
                  one.unavailable_reason ? <Pill tone="unknown">{one.unavailable_reason}</Pill>
                    : !one.exists ? <Pill tone="error">{t("missing on host")}</Pill>
                    : one.drift ? <Pill tone="warn">{t("changed outside the panel")}</Pill>
                    : one.drift_unknown_reason
                      // The panel holds no fingerprint of content from a
                      // secret, so it does not pretend the file matches - it
                      // says what it does not check.
                      ? <Pill tone="unknown" title={one.drift_unknown_reason}>{t("content not compared")}</Pill>
                      : <Pill tone="ok">{t("matches")}</Pill>
                ) },
                { key: "mode", head: t("Mode"), tight: true, cell: (one) => (
                  <>
                    {one.observed_mode || one.mode || "—"}
                    {one.mode && one.observed_mode
                      && one.mode.replace(/^0+/, "") !== one.observed_mode.replace(/^0+/, "")
                      && <Pill tone="unknown">{t("want {mode}", { mode: one.mode })}</Pill>}
                  </>
                ) },
                { key: "changed", head: t("Last change"), minor: true, cell: (one) => (
                  <span title={absoluteTime(one.updated_at)}>
                    {relativeTime(one.updated_at)} {t("by {who}", { who: one.updated_by })}
                  </span>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <>
                    <Guard action="file.read" host={host.id} explain>
                      <Button
                        kind="quiet"
                        testId={`read-${one.path}`}
                        title={t("Ask the host for the file as it is now: its checksum, mode and owner refresh in this list once the job reports back.")}
                        onClick={() => order.request.mutate({ action: "file.read", payload: { file: { path: one.path } } })}
                      >
                        {t("Read from host")}
                      </Button>
                    </Guard>
                    <Guard action="file.remove" host={host.id}>
                      <Button
                        kind="danger"
                        testId={`remove-${one.path}`}
                        title={t("Deletes the file on the host and stops managing it; the versions stay in the history.")}
                        onClick={() => setIntent({
                          action: "file.remove",
                          label: t("Stop managing and remove"),
                          danger: true,
                          description: t("{path} will be removed from {host} and the panel will stop tracking it. Its history stays.", {
                            path: one.path, host: host.hostname,
                          }),
                          payload: { file: { path: one.path, expected_sha256: one.observed_sha256 ?? "" } },
                        })}
                      >
                        {t("Remove")}
                      </Button>
                    </Guard>
                  </>
                ) },
              ]}
            />
          </Card>
        ),
        history: file ? (
          <Card title={t("Versions the panel wrote")} note={file.path} flush>
            <Table
              rows={history.data?.items ?? []}
              keyOf={(one) => `${one.sha256 || one.secret_name}-${one.applied_at}`}
              loading={history.isLoading}
              testId="file-history"
              empty={t("The panel has written no version of this file yet.")}
              columns={[
                { key: "version", head: t("Version"), tight: true, cell: (one) => (
                  <>
                    {/* An entry from a secret has no content in the panel:
                        we show which secret version was deployed, because
                        that is all the panel knows. */}
                    {one.sha256 ? one.sha256.slice(0, 12) : `${one.secret_name}@v${one.secret_version}`}
                    {one.sha256 && one.sha256 === file.desired_sha256 && <Pill tone="ok">{t("current")}</Pill>}
                  </>
                ) },
                { key: "size", head: t("Size"), num: true, cell: (one) => (one.sha256 ? bytes(one.size_bytes) : "—") },
                { key: "applied", head: t("Applied"), cell: (one) => (
                  <span title={absoluteTime(one.applied_at)}>{relativeTime(one.applied_at)}</span>
                ) },
                { key: "by", head: t("By"), minor: true, cell: (one) => one.applied_by },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <>
                    <Button
                      kind="quiet"
                      disabled={!one.sha256}
                      testId={`compare-${one.sha256 ?? "secret"}`}
                      onClick={() => setComparison(one.sha256 ?? "")}
                    >
                      {t("Compare")}
                    </Button>
                    <Guard action="file.rollback" host={host.id}>
                      <Button
                        kind="quiet"
                        disabled={!one.sha256 || (one.sha256 === file.desired_sha256 && !file.drift)}
                        testId={`rollback-${one.sha256 ?? "secret"}`}
                        onClick={() => setIntent({
                          action: "file.rollback",
                          label: t("Roll back file"),
                          description: t("{path} on {host} goes back to version {version} from {when}.", {
                            path: file.path, host: host.hostname,
                            version: (one.sha256 ?? "").slice(0, 12), when: absoluteTime(one.applied_at),
                          }),
                          payload: {
                            file: {
                              path: file.path,
                              version_sha256: one.sha256,
                              expected_sha256: file.observed_sha256 ?? "",
                              mode: file.mode ?? "",
                            },
                          },
                        })}
                      >
                        {t("Roll back")}
                      </Button>
                    </Guard>
                  </>
                ) },
              ]}
            />
          </Card>
        ) : undefined,
        kept: file && hostVersions.length > 0 ? (
          <Card
            title={t("Versions kept on the host")}
            note={t("What the file was before each write, kept by the host itself. A return puts back exactly this content, with the permissions it had.")}
            flush
          >
            <Table
              rows={hostVersions}
              keyOf={(one) => `${one.sha256 ?? "secret"}-${one.kept_at}`}
              testId="host-versions"
              columns={[
                { key: "version", head: t("Version"), tight: true, cell: (one) => (
                  <>
                    {one.sha256 ? one.sha256.slice(0, 12) : t("not named")}
                    {one.from_secret && <Pill tone="unknown">{t("from a secret")}</Pill>}
                  </>
                ) },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                { key: "mode", head: t("Mode"), tight: true, cell: (one) => one.mode || "—" },
                { key: "kept", head: t("Kept"), cell: (one) => (
                  <span title={absoluteTime(one.kept_at)}>{relativeTime(one.kept_at)}</span>
                ) },
                { key: "by", head: t("Ordered by"), minor: true, cell: (one) => one.ordered_by || "—" },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => {
                  const refusal = hostVersionRefusal(one);
                  return (
                    <Guard action="file.rollback" host={host.id}>
                      <Button
                        kind="quiet"
                        disabled={refusal !== ""}
                        testId={`restore-${one.kept_at}`}
                        title={refusal
                          ? refusals[refusal]
                          : t("The host writes back exactly this copy, through the same validator as any other write.")}
                        onClick={() => setIntent({
                          action: "file.rollback",
                          label: t("Restore this version"),
                          description: t("{path} on {host} goes back to the copy the host kept on {when}, with the mode {mode}.", {
                            path: file.path, host: host.hostname,
                            when: absoluteTime(one.kept_at), mode: one.mode || "—",
                          }),
                          payload: hostRollbackPayload(file, one),
                        })}
                      >
                        {t("Restore")}
                      </Button>
                    </Guard>
                  );
                } },
              ]}
            />
          </Card>
        ) : undefined,
        difference: comparison && chosen.data && current.data ? (
          <Card
            title={t("Difference")}
            note={t("Left: version {version}. Right: what the panel expects now.", { version: comparison.slice(0, 12) })}
          >
            {/* A patch read as plain text is a patch nobody reads: what
                goes in and what comes out carry the product's own
                colours, as they did in the panel being replaced. */}
            <Diff
              label={t("Difference")}
              text={differenceText(chosen.data.content, current.data.content)}
              testId="file-difference"
            />
          </Card>
        ) : undefined,
      }} />

      {intent && (
        <Confirm
          key={`${intent.action}-${intent.label}`}
          host={host}
          intent={intent}
          busy={order.request.isPending}
          onConfirm={(reason, confirmation) => order.request.mutate({
            action: intent.action,
            reason,
            target_confirmation: confirmation,
            payload: intent.payload,
          })}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}

/** The form for the first write of a file. */
function NewFile({ host, onIntent, onClose }: {
  host: Host;
  onIntent: (intent: Intent) => void;
  onClose: () => void;
}) {
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
    <Card
      title={t("Manage a file")}
      note={t("A file that already exists needs the checksum of the content you reviewed — read it first. Without that, a change someone made after you looked would vanish under this write.")}
      tools={<Button kind="quiet" onClick={onClose} testId="new-file-cancel">{t("Cancel")}</Button>}
    >
      <Fields>
        <Field label={t("Path")} wide>
          <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/etc/example.conf" data-testid="new-path" />
        </Field>
        <Field label={t("Mode")} hint={t("Octal, as chmod takes it.")}>
          <input value={mode} onChange={(event) => setMode(event.target.value)} placeholder="0644" data-testid="new-mode" />
        </Field>
        <Field
          label={t("Expected sha256")}
          hint={t("For a file that already exists: the checksum of the content you reviewed. Leave empty for a new file.")}
        >
          <input value={fingerprint} onChange={(event) => setFingerprint(event.target.value)} placeholder="e3b0c442…" data-testid="new-sha" />
        </Field>
        <Field
          label={t("From a secret")}
          hint={fromSecret
            ? t("The value never travels in the job: the host fetches it from the store when it starts the operation. The panel keeps no copy and no checksum of it, so it will not be able to tell you later whether somebody changed this file on the host — only which secret version was deployed.")
            : t("Leave empty to write the content typed below.")}
        >
          <input value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="repo.token" data-testid="new-secret" />
        </Field>
        {!fromSecret && (
          <Field label={t("Content")} wide>
            <textarea rows={10} value={content} onChange={(event) => setContent(event.target.value)} data-testid="new-content" />
          </Field>
        )}
      </Fields>
      <Button
        testId="new-write"
        disabled={!path || (!content && !fromSecret)}
        onClick={() => onIntent({
          action: "file.ensure",
          label: t("Write file"),
          description: fromSecret
            ? t("{path} will be written with the value of secret {secret}, mode {mode}. The value is fetched by the host at execution time and is stored nowhere else.", { path, secret, mode })
            : t("{path} will be written with {lines} lines, mode {mode}. The host validates the content first where it knows how.", {
                path, lines: content.split("\n").length, mode,
              }),
          payload: {
            file: fromSecret
              ? { path, content_secret: { name: secret.trim() }, mode, expected_sha256: fingerprint }
              : { path, content, mode, expected_sha256: fingerprint },
          },
        })}
      >
        {t("Write")}
      </Button>
      <Note>{t("It will be written to {host}.", { host: host.hostname })}</Note>
    </Card>
  );
}

/** The name this module's arrangement is stored under. */
export const FILES_SCREEN = "next_host_files";

/** The containers this module can draw, and the shape each ships with. */
export const HOST_FILES: BoardEntry[] = [
  { key: "managed", title: "Managed files", width: 4, height: 1 },
  { key: "drifted", title: "Changed outside the panel", width: 4, height: 1 },
  { key: "missing", title: "Missing on host", width: 4, height: 1 },
  { key: "states", title: "What the host has", width: 7, height: 2 },
  { key: "content", title: "Content", width: 5, height: 2 },
  { key: "add", title: "Manage a file", width: 12, height: 4 },
  { key: "list", title: "Files", width: 12, height: 4 },
  { key: "history", title: "Versions the panel wrote", width: 7, height: 3 },
  { key: "kept", title: "Versions kept on the host", width: 5, height: 3 },
  { key: "difference", title: "Difference", width: 12, height: 3 },
];
