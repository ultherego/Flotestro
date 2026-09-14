import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Empty } from "../../components/ui";
import {
  Fact, Facts, Field, Fields, Foot, Form, FormActions, Message, ModuleHeader, ModulePage, Section, Summary, Widgets,
  countWhere, useHost,
} from "./shared";
import { useJournalPreview } from "../../lib/stream";
import { readsPrefill } from "../Reads";
import { useT } from "../../i18n";

type JournalResult = { lines?: string[]; truncated?: boolean };
type FileResult = {
  path?: string;
  lines?: string[];
  truncated?: boolean;
  size_bytes?: number;
  allowlist?: string;
};

type Attempt = {
  status?: string;
  error_code?: string;
  message?: string;
  detail?: Record<string, unknown>;
  // A journal read prints its lines on stdout; a file read carries them in
  // the detail.
  stdout?: string;
};

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
  // The job behind the live preview: stopping the preview cancels it, so
  // the host does not keep the journal open for the rest of the timeout
  // after the operator has stopped watching.
  const [previewJob, setPreviewJob] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  // The unit detail on the Services tab hands over the unit and the cursor
  // of its last journal line, so the read here starts where that ended.
  const [params] = useSearchParams();
  const [unit, setUnit] = useState(params.get("unit") ?? "");
  const [cursor, setCursor] = useState(params.get("cursor") ?? "");
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
      setPreviewJob(job.id);
      setPreview(`/api/v1/jobs/${job.id}/events`);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  const stop = useMutation({
    mutationFn: async () => {
      // Closing the stream is not enough: the follow is a task on the host,
      // and only a cancellation of the job interrupts it there.
      if (previewJob) {
        await api.post(`/api/v1/jobs/${previewJob}/cancel`, { reason: "preview stopped from the panel" });
      }
    },
    onSettled: () => {
      setPreview(null);
      setPreviewJob(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
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
                  after_cursor: cursor || undefined,
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
      // The journal comes back as text, the file as a list of lines.
      setLines(detail?.lines ?? splitLines(attempt.stdout));
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

  // The lines on screen, from the live stream or the last read, sorted
  // by what they say of themselves. Nothing read means nothing to count.
  const output = preview ? stream.lines : lines ?? undefined;
  const severe = /\b(emerg|alert|crit|fatal|panic|error|err|fail(ed|ure)?)\b/i;
  const warning = /\bwarn(ing)?\b/i;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Logs")}
        description={t("The journal and log files, read from the host on request and always bounded.")}
      />
      <Message text={errorMessage} error />

      <Widgets>
      {/* What the lines on screen say of themselves, by the words in them:
          a rough sort, but it says at a glance whether the read is worth
          reading line by line. */}
      <Summary
        title={t("Lines on screen")}
        description={t("The lines of the last read or the live stream, by the severity words in them.")}
        span={8}
        segments={[
          { label: t("errors"), value: countWhere(output, (line) => severe.test(line)), tone: "error" },
          { label: t("warnings"), value: countWhere(output, (line) => !severe.test(line) && warning.test(line)), tone: "warn" },
          { label: t("other"), value: countWhere(output, (line) => !severe.test(line) && !warning.test(line)), tone: "neutral" },
          { label: t("dropped"), value: preview ? stream.dropped : undefined, tone: "unknown" },
        ]}
      />
      <Section title={t("Reading")} span={4} flush>
        <Facts>
          <Fact label={t("Source")}>{source === "journal" ? t("journal") : t("file")}</Fact>
          <Fact label={source === "journal" ? t("Unit") : t("Path")}>
            <span className="hm-mono">{source === "journal" ? unit || t("all units") : path}</span>
          </Fact>
          <Fact label={t("Limit")}>{preview ? t("5 minutes, 32 KiB/s") : t("{n} lines", { n: lineCount })}</Fact>
          <Fact label={t("State")}>
            {preview
              ? <span className={paused ? "badge warn" : "badge ok"}>{paused ? t("paused") : t("live")}</span>
              : lines !== null
                ? <span className="badge">{t("read")}</span>
                : <span className="badge unknown">{t("nothing read yet")}</span>}
          </Fact>
        </Facts>
      </Section>

      <Section
        title={t("Read")}
        span={12}
        tools={
          <>
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
          </>
        }
      >
        <Form>
          {source === "journal" ? (
            <Fields>
              <Field label={t("Unit")}>
                <input placeholder={t("unit (optional)")} value={unit} onChange={(e) => setUnit(e.target.value)} />
              </Field>
              <Field label={t("Severity")}>
                <select value={priority} onChange={(e) => setPriority(e.target.value)}>
                  <option value="">{t("any priority")}</option>
                  <option value="3">{t("error and above")}</option>
                  <option value="4">{t("warning and above")}</option>
                  <option value="6">{t("info and above")}</option>
                </select>
              </Field>
              <Field label={t("Since")}>
                <input placeholder={t("since, e.g. -1h")} value={since} onChange={(e) => setSince(e.target.value)} />
              </Field>
              {/* A cursor is the position the unit detail ended at; the
                  read continues from there until the operator clears it. */}
              {cursor && (
                <Field label={t("After cursor")} wide help={t("Continues right after the last line shown in the unit detail.")}>
                  <div className="operations">
                    <span className="hm-mono" title={cursor}>{cursor.slice(0, 40)}…</span>
                    <button className="secondary" onClick={() => setCursor("")}>{t("Clear")}</button>
                  </div>
                </Field>
              )}
              <Field label={t("lines")} narrow>
                <input
                  type="number"
                  min={1}
                  max={2000}
                  value={lineCount}
                  onChange={(e) => setLineCount(Number(e.target.value))}
                />
              </Field>
            </Fields>
          ) : (
            <Fields>
              <Field label={t("log file")} wide help={t("Only paths on the host's allowlist can be read, and symlinks are not followed.")}>
                <input
                  placeholder="/var/log/syslog"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                />
              </Field>
              <Field label={t("lines")} narrow>
                <input
                  type="number"
                  min={1}
                  max={2000}
                  value={lineCount}
                  onChange={(e) => setLineCount(Number(e.target.value))}
                />
              </Field>
            </Fields>
          )}

          <FormActions>
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
                <button className="secondary" onClick={() => stop.mutate()} disabled={stop.isPending}>
                  {t("Stop")}
                </button>
              </>
            )}
            {/* The same read on a handful of hosts at once: the form on
                the reads page opens with this query filled in, and the
                lines of every host come back merged into one timeline. */}
            {!preview && (
              <Link
                className="button"
                to={readsPrefill(
                  source === "journal" ? "journal.read" : "logfile.read",
                  source === "journal"
                    ? {
                        journal: {
                          unit: unit || undefined,
                          lines: lineCount,
                          max_priority: priority ? Number(priority) : undefined,
                          since: since || undefined,
                        },
                      }
                    : { logfile: { path, lines: lineCount } },
                )}
              >
                {t("Read the same on more hosts")}
              </Link>
            )}
          </FormActions>
        </Form>
      </Section>

      {/* The limit is visible: the operator is to know that the preview
          ends on its own and that some lines may be skipped. */}
      {preview && (
        <Section
          title={t("Live")}
          span={12}
          description={
            <>
              {t("Streaming for up to 5 minutes, capped at 32 KiB/s.")}
              {paused && ` ${t("Paused — the host keeps sending, the screen does not.")}`}
              {stream.dropped > 0 && ` ${t("{n} lines dropped by the rate limit.", { n: stream.dropped })}`}
            </>
          }
        >
          {stream.lines.length === 0 ? (
            <Empty>{t("Waiting for the first lines…")}</Empty>
          ) : (
            <pre className="hm-log">
              {stream.lines.join("\n")}
            </pre>
          )}
        </Section>
      )}

      {lines !== null && !preview && (
        <Section title={t("Output")} count={lines.length} span={12} flush>
          {lines.length === 0 ? (
            <Empty>{t("Nothing matched.")}</Empty>
          ) : (
            <div className="hm-section-body">
              <pre className="hm-log">{lines.join("\n")}</pre>
            </div>
          )}
          {footer && <Foot><span>{footer}</span></Foot>}
        </Section>
      )}
      </Widgets>
    </ModulePage>
  );
}

/** The lines of a text result; nothing read is an empty list, not a line. */
function splitLines(text?: string): string[] {
  if (!text) return [];
  return text.replace(/\n$/, "").split("\n");
}
