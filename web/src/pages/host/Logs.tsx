import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Empty } from "../../components/ui";
import { useHost } from "./shared";
import { useJournalPreview } from "../../lib/stream";
import { useT } from "../../i18n";

type JournalResult = { lines?: string[]; truncated?: boolean };
type FileResult = {
  path?: string;
  lines?: string[];
  truncated?: boolean;
  size_bytes?: number;
  allowlist?: string;
};

type Attempt = { status?: string; error_code?: string; message?: string; detail?: Record<string, unknown> };

/**
 * The host's logs.
 *
 * A read is always on request and always bounded: the journal by a line
 * count, a file additionally by the host administrator's allowlist. The
 * panel does not index logs - it leads from host to host instead of
 * querying the whole fleet at once.
 */
export function Logs() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [source, setSource] = useState<"journal" | "file">("journal");
  const [preview, setPreview] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [unit, setUnit] = useState("");
  const [priority, setPriority] = useState("");
  const [since, setSince] = useState("");
  const [path, setPath] = useState("/var/log/syslog");
  const [lineCount, setLineCount] = useState(200);
  const [lines, setLines] = useState<string[] | null>(null);
  const [footer, setFooter] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const stream = useJournalPreview(preview, paused);

  // The preview goes over the same stream as operation progress, so one
  // connection per tab is enough.
  const follow = useMutation({
    mutationFn: async () => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "journal.follow",
        payload: {
          journal: {
            unit: unit || undefined,
            lines: 50,
            max_priority: priority ? Number(priority) : undefined,
            follow_seconds: 300,
          },
        },
      });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      return job;
    },
    onSuccess: (job) => {
      setErrorMessage("");
      setLines(null);
      setPaused(false);
      setPreview(`/api/v1/jobs/${job.id}/events`);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  const read = useMutation({
    mutationFn: async () => {
      const body =
        source === "journal"
          ? {
              action: "journal.read",
              payload: {
                journal: {
                  unit: unit || undefined,
                  lines: lineCount,
                  max_priority: priority ? Number(priority) : undefined,
                  since: since || undefined,
                },
              },
            }
          : { action: "logfile.read", payload: { logfile: { path, lines: lineCount } } };

      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });

      // The read goes through a job, so the screen waits for its result.
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise((done) => setTimeout(done, 1500));
        const attempts = await api.get<{ items: Attempt[] }>(`/api/v1/jobs/${job.id}/attempts`);
        const last = attempts.items[attempts.items.length - 1];
        if (!last?.status) continue;
        return last;
      }
      throw new Error(t("The host did not answer in time."));
    },
    onSuccess: (attempt) => {
      setErrorMessage("");
      const detail = attempt.detail as (JournalResult & FileResult) | undefined;
      if (attempt.status !== "succeeded") {
        setLines(null);
        // A refusal carries the reason: the operator is to know whether the
        // file is missing or outside the allowed range.
        setErrorMessage(attempt.message || attempt.error_code || t("The host refused the read."));
        return;
      }
      setLines(detail?.lines ?? []);
      const parts: string[] = [];
      if (detail?.truncated) parts.push(t("output truncated"));
      if (detail?.size_bytes) parts.push(t("file {n} KiB", { n: Math.round(detail.size_bytes / 1024) }));
      if (detail?.allowlist) parts.push(`${t("allowlist")}: ${detail.allowlist}`);
      setFooter(parts.join(" · "));
    },
    onError: (error) => {
      setLines(null);
      setErrorMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <>
      <div className="form">
        <div className="filters">
          <label className="toggle">
            <input
              type="radio"
              checked={source === "journal"}
              onChange={() => { setSource("journal"); setLines(null); }}
            />
            journald
          </label>
          <label className="toggle">
            <input
              type="radio"
              checked={source === "file"}
              onChange={() => { setSource("file"); setLines(null); }}
            />
            {t("log file")}
          </label>
        </div>

        {source === "journal" ? (
          <div className="filters">
            <input placeholder={t("unit (optional)")} value={unit} onChange={(e) => setUnit(e.target.value)} />
            <select value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">{t("any priority")}</option>
              <option value="3">{t("error and above")}</option>
              <option value="4">{t("warning and above")}</option>
              <option value="6">{t("info and above")}</option>
            </select>
            <input placeholder={t("since, e.g. -1h")} value={since} onChange={(e) => setSince(e.target.value)} />
          </div>
        ) : (
          <div className="filters">
            <input
              placeholder="/var/log/syslog"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              style={{ minWidth: 320 }}
            />
          </div>
        )}

        <div className="filters">
          <label className="toggle">
            {t("lines")}
            <input
              type="number"
              min={1}
              max={2000}
              value={lineCount}
              onChange={(e) => setLineCount(Number(e.target.value))}
              style={{ width: 90 }}
            />
          </label>
          <button onClick={() => read.mutate()} disabled={read.isPending || host.connection_state !== "online"}>
            {read.isPending ? t("Reading…") : t("Read")}
          </button>
          {/* The live preview applies to the journal only: a file has no
              events that could be followed without polling the host in a
              loop. */}
          {source === "journal" && !preview && (
            <button
              className="secondary"
              onClick={() => follow.mutate()}
              disabled={follow.isPending || host.connection_state !== "online"}
            >
              {follow.isPending ? t("Starting…") : t("Follow")}
            </button>
          )}
          {preview && (
            <>
              <button className="secondary" onClick={() => setPaused((state) => !state)}>
                {paused ? t("Resume") : t("Pause")}
              </button>
              <button className="secondary" onClick={() => setPreview(null)}>{t("Stop")}</button>
            </>
          )}
        </div>
        {/* A file read is bounded by a range that belongs to the host, not
            to the panel. */}
        {source === "file" && (
          <p className="source" style={{ margin: 0 }}>
            {t("Only paths on the host's allowlist can be read, and symlinks are not followed.")}
          </p>
        )}
      </div>

      {errorMessage && <p className="page-error" style={{ marginTop: 12 }}>{errorMessage}</p>}

      {preview && (
        <>
          <h2>{t("Live")}</h2>
          {/* The limit is visible: the operator is to know that the preview
              ends on its own and that some lines may be skipped. */}
          <p className="subtitle">
            {t("Streaming for up to 5 minutes, capped at 32 KiB/s.")}
            {paused && ` ${t("Paused — the host keeps sending, the screen does not.")}`}
            {stream.dropped > 0 && ` ${t("{n} lines dropped by the rate limit.", { n: stream.dropped })}`}
          </p>
          {stream.lines.length === 0 ? (
            <Empty>{t("Waiting for the first lines…")}</Empty>
          ) : (
            <pre style={{ marginTop: 8, maxHeight: 520, overflowY: "auto" }}>
              {stream.lines.join("\n")}
            </pre>
          )}
        </>
      )}

      {lines !== null && !preview && (
        <>
          <h2>{t("Output")}</h2>
          {lines.length === 0 ? (
            <Empty>{t("Nothing matched.")}</Empty>
          ) : (
            <pre style={{ marginTop: 8, maxHeight: 520, overflowY: "auto" }}>{lines.join("\n")}</pre>
          )}
          {footer && <p className="source" style={{ marginTop: 8 }}>{footer}</p>}
        </>
      )}
    </>
  );
}
