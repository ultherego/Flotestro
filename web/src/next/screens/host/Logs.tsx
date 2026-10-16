import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { awaitJob } from "../../../lib/jobs";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { useJournalPreview } from "../../../lib/stream";
import type { Attempt, Capabilities, Host, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { readsPrefill } from "../Reads";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Find, Note,
  Pill, Problem, Readout, Row, Stack, type Segment,
} from "../../kit";

/**
 * The journal and the log files of one machine, read on request and always
 * bounded.
 *
 * Three different kinds of nothing live on this screen and the panel may
 * not merge them: the lines the view could not carry, the messages journald
 * suppressed on the host before anything could carry them, and a count the
 * agent is too old to take at all. The first two are numbers; the third is
 * an em dash with a reason, and never a nought.
 */

/** The reads this module offers; when every one is refused, it says so once. */
const LOG_READS = ["journal.read", "logfile.read", "journal.follow"];

type JournalResult = { lines?: string[]; truncated?: boolean };

type FileResult = {
  path?: string;
  lines?: string[];
  truncated?: boolean;
  size_bytes?: number;
  allowlist?: string;
};

/**
 * The window of a job on the host: from the delivery of its last attempt to
 * its end plus a margin, in UTC, and the unit its payload names.
 */
export type JobWindow = { since: string; until: string; unit?: string };

/** The margin after the end of a job: a unit still logs a moment after the restart returned. */
const WINDOW_MARGIN_SECONDS = 30;

/** The window of a job from its record and its attempts. */
export function jobWindow(job: Job | undefined, attempts: Attempt[] | undefined, now = Date.now()): JobWindow | null {
  if (!job) return null;
  const last = attempts?.length ? attempts[attempts.length - 1] : undefined;
  const start = last?.dispatched_at ?? last?.created_at;
  if (!start) return null;
  const end = job.finished_at ?? last?.finished_at;
  const until = end ? new Date(end).getTime() : now;
  const payload = (job.payload ?? {}) as { unit?: { unit?: string }; journal?: { unit?: string } };
  return {
    since: utcStamp(new Date(start).getTime()),
    until: utcStamp(until + WINDOW_MARGIN_SECONDS * 1000),
    unit: payload.unit?.unit || payload.journal?.unit || undefined,
  };
}

/** A moment as journalctl takes it, in UTC. */
export function utcStamp(millis: number): string {
  const at = new Date(millis);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}` +
    ` ${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}:${pad(at.getUTCSeconds())} UTC`;
}

/** The lines that carry the searched text, by index, case-insensitively. */
export function findMatches(lines: string[] | undefined, query: string): number[] {
  const needle = query.toLowerCase();
  if (!lines || needle.trim() === "") return [];
  const hits: number[] = [];
  lines.forEach((line, index) => {
    if (line.toLowerCase().includes(needle)) hits.push(index);
  });
  return hits;
}

/**
 * The name of the file a download saves the lines under: the host, the
 * source and the moment, with a path's slashes turned into dashes so the
 * name is one file name and not a directory.
 */
export function logFileName(hostname: string, source: string, millis: number): string {
  const stamp = utcStamp(millis).replace(" UTC", "").replace(/[-: ]/g, "");
  const part = source.replace(/^\/+/, "").replace(/[/\s]+/g, "-") || "all";
  return `${hostname}-${part}-${stamp}.log`;
}

/**
 * Whether the agent of the host applies a boot identifier to a journal read,
 * and the reason when it does not.
 */
export function bootFilterSupport(
  capabilities: Capabilities | undefined,
  t: (text: string) => string,
): { supported: boolean; reason?: string } {
  const journald = (capabilities ?? []).find((one) => one.name === "journald");
  if (!journald || !journald.available) {
    return { supported: false, reason: t("This host has no journald adapter; the journal cannot be filtered by boot.") };
  }
  if (journald.features?.boot_filter !== true) {
    return { supported: false, reason: t("The agent of this host cannot filter the journal by boot; it would answer with every boot. Read by time instead, or upgrade the agent.") };
  }
  return { supported: true };
}

/**
 * Whether the agent of the host counts the messages journald suppressed at
 * the source, and the reason when it does not.
 */
export function suppressionCountSupport(
  capabilities: Capabilities | undefined,
  t: (text: string) => string,
): { supported: boolean; reason?: string } {
  const journald = (capabilities ?? []).find((one) => one.name === "journald");
  if (!journald || !journald.available) {
    return { supported: false, reason: t("This host has no journald adapter; nothing here counts the messages the host never recorded.") };
  }
  if (journald.features?.suppression_notice !== true) {
    return { supported: false, reason: t("The agent of this host does not count the messages journald suppressed; a view from it says unknown, never zero. Upgrade the agent.") };
  }
  return { supported: true };
}

/** How long a live view lasts and how much of the past it opens with. */
export const FOLLOW_SECONDS = 300;
export const FOLLOW_BACKLOG = 50;
/** How long the screen waits for the summary the host writes when a view ends. */
export const SUMMARY_TRIES = 4;

/** The journal payload of a live view. */
export function followPayload(filters: {
  unit?: string;
  priority?: string;
  since?: string;
  cursor?: string;
  boot?: string;
}): Record<string, unknown> {
  return {
    unit: filters.unit || undefined,
    lines: FOLLOW_BACKLOG,
    max_priority: filters.priority ? Number(filters.priority) : undefined,
    follow_seconds: FOLLOW_SECONDS,
    since: filters.since || undefined,
    after_cursor: filters.cursor || undefined,
    boot_id: filters.boot || undefined,
  };
}

/** What the panel says about the lines a live view could not carry. */
export function droppedNotice(dropped: number, t: Translate): string {
  if (!dropped || dropped <= 0) return "";
  return t("{n} lines were dropped while you watched; the host wrote them faster than the view could carry.", { n: dropped });
}

/** What a live view leaves behind on its job: the counts of its summary. */
export type FollowSummary = {
  lines_sent?: number;
  lines_dropped?: number;
  host_suppressed?: number;
  host_suppressed_unknown_reason?: string;
};

/** The summary of a live view, or nothing when its job carried none. */
export function followSummary(stdout: string | undefined): FollowSummary | null {
  if (!stdout) return null;
  try {
    const parsed = JSON.parse(stdout) as FollowSummary & { kind?: string };
    return parsed?.kind === "journal_follow" ? parsed : null;
  } catch {
    // A summary that cannot be read says nothing; it must not read as zero.
    return null;
  }
}

/** Why a view could not see journald's own notice, as the agent names it. */
export function suppressionReason(reason: string, t: (text: string) => string): string {
  if (reason === "priority_filter") return t("the priority filter hides journald's own notice");
  return t("the filters of this view hide journald's own notice");
}

/**
 * What the host itself never recorded: a count, a zero that means the view
 * saw no notice, or unknown with the reason. Never the dropped lines of the
 * view, which are a different loss.
 */
export function suppressedNotice(
  summary: FollowSummary | null,
  support: { supported: boolean; reason?: string },
  t: Translate,
): { count?: number; text: string } {
  const count = summary?.host_suppressed;
  if (typeof count === "number") {
    return {
      count,
      text: count > 0
        ? t("journald suppressed {n} messages on the host; they were never written and are in no view.", { n: count })
        : t("journald suppressed nothing while you watched: this view would have carried its notice, and there was none."),
    };
  }
  const reason = summary?.host_suppressed_unknown_reason;
  if (reason) {
    return { text: t("How many messages the host never recorded is unknown: {reason}.", { reason: suppressionReason(reason, t) }) };
  }
  return { text: support.reason ?? t("How many messages the host never recorded is unknown; this view said nothing about it.") };
}

/**
 * A boot identifier as the address carries it: the bare lowercase form the
 * journal uses, or empty for a value that is not one.
 */
export function bootParam(value: string | null): string {
  const bare = (value ?? "").trim().toLowerCase().replace(/-/g, "");
  return /^[0-9a-f]{32}$/.test(bare) ? bare : "";
}

/** The lines of a text result; nothing read is an empty list, not a line. */
function splitLines(text?: string): string[] {
  if (!text) return [];
  return text.replace(/\n$/, "").split("\n");
}

/** A count of what satisfies a test, or undefined where the list itself is unknown. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

const SEVERE = /\b(emerg|alert|crit|fatal|panic|error|err|fail(ed|ure)?)\b/i;
const WARNING = /\bwarn(ing)?\b/i;

export function Logs({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [source, setSource] = useState<"journal" | "file">("journal");
  const [preview, setPreview] = useState<string | null>(null);
  // The job behind the live preview: stopping the preview cancels it, so the
  // host does not keep the journal open for the rest of the timeout after
  // the operator has stopped watching.
  const [previewJob, setPreviewJob] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  // What the last live view could not carry.
  const [watched, setWatched] = useState<number | null>(null);
  // What the host never recorded during the last live view: a count, or
  // unknown with its reason. It is set only once the summary has been read.
  const [hostGap, setHostGap] = useState<{ count?: number; text: string } | null>(null);
  // The unit detail on the Services module hands over the unit and the
  // cursor of its last journal line, so the read starts where that ended.
  const [params, setParams] = useSearchParams();
  const [unit, setUnit] = useState(params.get("unit") ?? "");
  const [cursor, setCursor] = useState(params.get("cursor") ?? "");
  // The Power module links here with one boot of the host; the filter stays
  // in the address, so the view of one boot is a thing to hand over.
  const boot = bootParam(params.get("boot"));
  const bootFilter = bootFilterSupport(host.capabilities, t);
  const suppressionCount = suppressionCountSupport(host.capabilities, t);
  const clearBoot = () => {
    const next = new URLSearchParams(params);
    next.delete("boot");
    setParams(next, { replace: true });
  };
  const [priority, setPriority] = useState("");
  const [since, setSince] = useState("");
  // A job bounds the read to its window on the host: the jobs list links
  // here with the job, and the operator may also paste one.
  const [jobId, setJobId] = useState(params.get("job") ?? "");
  const [path, setPath] = useState("/var/log/syslog");
  const [lineCount, setLineCount] = useState(200);
  const [lines, setLines] = useState<string[] | null>(null);
  const [footer, setFooter] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  // The search runs over the lines on screen, not on the host: the read is
  // bounded already, and the operator narrows what came back.
  const [search, setSearch] = useState("");
  const [matchIndex, setMatchIndex] = useState(0);
  // A journal line is long, and a reader chasing a stack trace wants it
  // folded rather than scrolled sideways. The panel being replaced wrapped
  // by default and let the choice be made; so does this one.
  const [wrap, setWrap] = useState(true);

  const stream = useJournalPreview(preview, paused);

  const access = useModuleAccess(host.id, LOG_READS);
  const mayRead = useAllowed(host.id, source === "journal" ? "journal.read" : "logfile.read");
  const mayFollow = useAllowed(host.id, "journal.follow");

  // The job and its attempts give the window; both are read once the
  // identifier looks like one, so a half-typed identifier asks nothing.
  const boundJob = jobId.trim().length >= 32 ? jobId.trim() : "";
  const jobRecord = useQuery({
    queryKey: ["job", boundJob],
    queryFn: () => api.get<Job>(`/api/v1/jobs/${boundJob}`),
    enabled: !!boundJob,
  });
  const jobAttempts = useQuery({
    queryKey: ["job-attempts", boundJob],
    queryFn: () => api.get<{ items: Attempt[] }>(`/api/v1/jobs/${boundJob}/attempts`),
    enabled: !!boundJob,
  });
  const bounds = boundJob ? jobWindow(jobRecord.data, jobAttempts.data?.items) : null;
  const windowUnit = unit || bounds?.unit || "";

  // The preview goes over the same stream as operation progress, so one
  // connection per tab is enough.
  const follow = useMutation({
    mutationFn: async () => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "journal.follow",
        // The same narrowing the read takes, without the end of the range:
        // the window of a job is a closed range and belongs to a read; a
        // live view ends by its own time limit.
        payload: {
          journal: followPayload({
            unit: windowUnit,
            priority,
            since,
            cursor,
            boot: boot && bootFilter.supported ? boot : "",
          }),
        },
      });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      return job;
    },
    onSuccess: (job) => {
      setErrorMessage("");
      setLines(null);
      setPaused(false);
      setWatched(null);
      setHostGap(null);
      setPreviewJob(job.id);
      setPreview(`/api/v1/jobs/${job.id}/events`);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  const stop = useMutation({
    // The screen stops watching at once; the summary of the view comes
    // after, once the host has written it.
    onMutate: () => {
      setPreview(null);
      setWatched(stream.dropped);
    },
    mutationFn: async () => {
      // Closing the stream is not enough: the follow is a task on the host,
      // and only a cancellation of the job interrupts it there.
      if (!previewJob) return undefined;
      await api.post(`/api/v1/jobs/${previewJob}/cancel`, { reason: "preview stopped from the panel" });
      // What journald suppressed at the source is only in the summary of
      // the view: the stream carries the lines, not the host's own gap.
      return awaitJob<Record<string, unknown>>(api, previewJob, { tries: SUMMARY_TRIES });
    },
    onSettled: (attempt) => {
      setPreviewJob(null);
      setHostGap(suppressedNotice(followSummary(attempt?.stdout), suppressionCount, t));
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
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
                  unit: windowUnit || undefined,
                  lines: lineCount,
                  max_priority: priority ? Number(priority) : undefined,
                  // A job's window wins over a typed range: the read is
                  // about that operation, and the range would widen it.
                  since: bounds?.since ?? (since || undefined),
                  until: bounds?.until,
                  after_cursor: cursor || undefined,
                  // The boot goes to the host only where the agent applies
                  // it; the button is off otherwise, and the server refuses
                  // the read anyway.
                  boot_id: boot && bootFilter.supported ? boot : undefined,
                },
              },
            }
          : { action: "logfile.read", payload: { logfile: { path, lines: lineCount } } };

      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });

      // The read goes through a job, so the screen waits for its result.
      const last = await awaitJob<Record<string, unknown>>(api, job.id);
      if (!last) throw new Error(t("The host did not answer in time."));
      return last;
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

  // The lines on screen, from the live stream or the last read. Nothing
  // read means nothing to count, which is a dash and not a nought.
  const output = preview ? stream.lines : lines ?? undefined;
  const matches = findMatches(output, search);
  const current = matches.length > 0 ? ((matchIndex % matches.length) + matches.length) % matches.length : -1;
  const currentLine = current >= 0 ? matches[current] : -1;

  const text = (output ?? []).join("\n") + (output?.length ? "\n" : "");
  const download = () => {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = logFileName(host.hostname, source === "journal" ? (windowUnit || "journal") : path, Date.now());
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  };

  const readOnly = access.known && !access.anyAllowed
    ? access.permissions.length > 0 && access.reasons.length === 0
      ? t("You can read this module; changing it needs the permission {permissions}.", {
          permissions: access.permissions.join(", "),
        })
      : t("You can read this module; changing it is not possible here: {reasons}", {
          reasons: [
            ...access.reasons,
            ...access.permissions.map((one) => t("missing permission {permission}", { permission: one })),
          ].join("; "),
        })
    : "";

  const counts: Segment[] = [
    { label: t("errors"), value: countWhere(output, (line) => SEVERE.test(line)), tone: "error" },
    { label: t("warnings"), value: countWhere(output, (line) => !SEVERE.test(line) && WARNING.test(line)), tone: "warn" },
    { label: t("other"), value: countWhere(output, (line) => !SEVERE.test(line) && !WARNING.test(line)), tone: "neutral" },
    { label: t("dropped"), value: preview ? stream.dropped : undefined, tone: "unknown" },
    // A count the host answered with stands, zero included; a count it
    // could not answer with stays a dash and never borrows the one above.
    ...(hostGap ? [{ label: t("suppressed by the host"), value: hostGap.count, tone: "unknown" as const }] : []),
  ];

  const jobHint = boundJob
    ? jobRecord.error
      ? t("No such job, or it is out of your scope.")
      : bounds
        ? t("Bounded to the job {action} ({state}); the unit comes from the job unless typed above.", {
            action: jobRecord.data?.action_type ?? "", state: jobRecord.data?.state ?? "",
          })
        : jobRecord.data && jobAttempts.data
          ? t("The job has not been delivered to the host yet, so it has no window.")
          : t("Reading the job…")
    : t("Paste a job identifier to read what the host wrote while that operation ran.");

  const prefill = readsPrefill(
    source === "journal" ? "journal.read" : "logfile.read",
    source === "journal"
      ? {
          journal: {
            unit: windowUnit || undefined,
            lines: lineCount,
            max_priority: priority ? Number(priority) : undefined,
            since: bounds?.since ?? (since || undefined),
            until: bounds?.until,
          },
        }
      : { logfile: { path, lines: lineCount } },
  );

  return (
    <Board screen={HOST_LOGS_SCREEN} catalogue={HOST_LOGS} drawn={{
      notices: (
        <Stack>
          {readOnly && <Banner tone="info">{readOnly}</Banner>}
          {errorMessage && <Problem>{errorMessage}</Problem>}
          {/* A view that has ended still says what it could not carry: the
              gap belongs to the lines that came back, not to the moment
              they stopped arriving. */}
          {!preview && watched !== null && watched > 0 && (
            <Banner tone="warn">{droppedNotice(watched, t)}</Banner>
          )}
          {/* A second gap, and not the same one: these messages never
              reached the host's journal at all, so they are in no view and
              in no read. */}
          {!preview && hostGap && <Banner tone="unknown">{hostGap.text}</Banner>}
        </Stack>
      ),
      counts: (
        <Card
          title={t("Lines on screen")}
          note={t("The lines of the last read or the live stream, by the severity words in them.")}
        >
          <Band segments={counts} testId="line-counts" />
        </Card>
      ),
      reading: (
        <Card title={t("Reading")}>
          <Facts>
            <Fact label={t("Source")}>{source === "journal" ? t("journal") : t("file")}</Fact>
            <Fact label={source === "journal" ? t("Unit") : t("Path")}>
              <span className="fl-mono">{source === "journal" ? unit || t("all units") : path}</span>
            </Fact>
            <Fact label={t("Limit")}>
              {preview ? t("5 minutes, 32 KiB/s") : t("{n} lines", { n: lineCount })}
            </Fact>
            {source === "journal" && boot && (
              <Fact label={t("Boot")}>
                <span className="fl-mono" title={boot}>{`${boot.slice(0, 8)}…`}</span>
              </Fact>
            )}
            {bounds && (
              <Fact label={t("Window")}>
                <span className="fl-mono">{`${bounds.since} – ${bounds.until}`}</span>
              </Fact>
            )}
            <Fact label={t("State")}>
              {preview
                ? <Pill tone={paused ? "warn" : "ok"}>{paused ? t("paused") : t("live")}</Pill>
                : lines !== null
                  ? <Pill tone="neutral">{t("read")}</Pill>
                  : <Pill tone="unknown">{t("nothing read yet")}</Pill>}
            </Fact>
          </Facts>
        </Card>
      ),
      read: (
        <Card
          title={t("Read")}
          note={t("The journal and log files, read from the host on request and always bounded.")}
          tools={
            <Row>
              <Check checked={source === "journal"} onChange={() => { setSource("journal"); setLines(null); }}>
                journald
              </Check>
              <Check checked={source === "file"} onChange={() => { setSource("file"); setLines(null); }}>
                {t("log file")}
              </Check>
            </Row>
          }
        >
          <Stack>
            {source === "journal" ? (
              <Fields>
                <Field label={t("Unit")} hint={t("Empty reads the whole journal.")}>
                  <input
                    placeholder="sshd.service"
                    value={unit}
                    onChange={(event) => setUnit(event.target.value)}
                    data-testid="unit"
                  />
                </Field>
                <Field label={t("Severity")}>
                  <select value={priority} onChange={(event) => setPriority(event.target.value)} data-testid="priority">
                    <option value="">{t("any priority")}</option>
                    <option value="3">{t("error and above")}</option>
                    <option value="4">{t("warning and above")}</option>
                    <option value="6">{t("info and above")}</option>
                  </select>
                </Field>
                <Field
                  label={t("Since")}
                  hint={t("As journalctl takes it: -1h, yesterday, 2026-09-15 10:00 — in the host's clock.")}
                >
                  <input
                    placeholder="-1h"
                    value={bounds ? bounds.since : since}
                    disabled={!!bounds}
                    onChange={(event) => setSince(event.target.value)}
                    data-testid="since"
                  />
                </Field>
                {/* A job bounds the read to its window on the host: from the
                    delivery of its last attempt to its end and a little
                    after, and to the unit its payload names. */}
                <Field label={t("Job")} wide hint={jobHint}>
                  <input
                    placeholder={t("job identifier (optional)")}
                    value={jobId}
                    onChange={(event) => setJobId(event.target.value)}
                    data-testid="job"
                  />
                </Field>
                {/* One boot of the host, from the Power module. The filter
                    is shown as such, and where the agent cannot apply it
                    the reason stands in its place: the read is not sent as
                    if the filter held. */}
                {boot && (
                  <Field
                    label={t("Boot")}
                    wide
                    hint={bootFilter.supported
                      ? t("Only the lines of this boot of the host; clear the filter to read across boots.")
                      : bootFilter.reason}
                  >
                    <Row>
                      <span className="fl-mono" title={boot} data-testid="boot-filter">{boot}</span>
                      {!bootFilter.supported && <Pill tone="warn">{t("not applied")}</Pill>}
                      <Button kind="quiet" onClick={clearBoot} testId="clear-boot">{t("Clear")}</Button>
                      <Link to={`/next/hosts/${host.id}/power`}>{t("boots on the Power module")}</Link>
                    </Row>
                  </Field>
                )}
                {/* A cursor is the position the unit detail ended at; the
                    read continues from there until the operator clears it. */}
                {cursor && (
                  <Field
                    label={t("After cursor")}
                    wide
                    hint={t("Continues right after the last line shown in the unit detail.")}
                  >
                    <Row>
                      <span className="fl-mono" title={cursor}>{`${cursor.slice(0, 40)}…`}</span>
                      <Button kind="quiet" onClick={() => setCursor("")} testId="clear-cursor">{t("Clear")}</Button>
                    </Row>
                  </Field>
                )}
                <Field label={t("Lines")} hint={t("The newest ones; at most 2000.")}>
                  <input
                    type="number"
                    min={1}
                    max={2000}
                    value={lineCount}
                    onChange={(event) => setLineCount(Number(event.target.value))}
                    data-testid="line-count"
                  />
                </Field>
              </Fields>
            ) : (
              <Fields>
                <Field
                  label={t("Log file")}
                  wide
                  hint={t("Only paths on the host's allowlist can be read, and symlinks are not followed.")}
                >
                  <input
                    placeholder="/var/log/syslog"
                    value={path}
                    onChange={(event) => setPath(event.target.value)}
                    data-testid="path"
                  />
                </Field>
                <Field label={t("Lines")} hint={t("The last ones of the file; at most 2000.")}>
                  <input
                    type="number"
                    min={1}
                    max={2000}
                    value={lineCount}
                    onChange={(event) => setLineCount(Number(event.target.value))}
                    data-testid="line-count"
                  />
                </Field>
              </Fields>
            )}

            <Actions>
              {/* The read is the one button of the card: refused, it stays
                  on the screen disabled with the reason. The follow is a
                  second order of its own and simply goes away when it is
                  refused. */}
              {(mayRead.allowed || mayRead.known) && (
                <Button
                  onClick={() => read.mutate()}
                  disabled={!mayRead.allowed || read.isPending || host.connection_state !== "online"
                    || (source === "journal" && !!boot && !bootFilter.supported)}
                  title={!mayRead.allowed
                    ? mayRead.reason || t("This action is not available.")
                    : source === "journal" && boot && !bootFilter.supported ? bootFilter.reason : undefined}
                  testId="read"
                >
                  {read.isPending ? t("Reading…") : t("Read")}
                </Button>
              )}
              {/* The live preview applies to the journal only: a file has no
                  events that could be followed without polling the host in
                  a loop. */}
              {source === "journal" && !preview && mayFollow.allowed && (
                <Button
                  kind="quiet"
                  title={t("A live stream of the journal with these filters, for a bounded time; lines the host cannot send in time are dropped and counted.")}
                  onClick={() => follow.mutate()}
                  disabled={follow.isPending || host.connection_state !== "online"}
                  testId="follow"
                >
                  {follow.isPending ? t("Starting…") : t("Follow")}
                </Button>
              )}
              {preview && (
                <>
                  <Button kind="quiet" onClick={() => setPaused((state) => !state)} testId="pause">
                    {paused ? t("Resume") : t("Pause")}
                  </Button>
                  <Button kind="quiet" onClick={() => stop.mutate()} disabled={stop.isPending} testId="stop">
                    {t("Stop")}
                  </Button>
                </>
              )}
              {/* The same read on a handful of hosts at once: the form on
                  the reads screen opens with this query filled in, and the
                  lines of every host come back merged into one timeline. */}
              {!preview && (
                <Link
                  className="fl-btn fl-quiet"
                  title={t("Opens the reads screen with this query filled in; the lines of every chosen host come back in one timeline.")}
                  to={prefill}
                >
                  {t("Read the same on more hosts")}
                </Link>
              )}
            </Actions>
            {!mayRead.allowed && !mayRead.pending && mayRead.known && (
              <Note>{mayRead.reason || t("This action is not available.")}</Note>
            )}
            {boundJob && jobRecord.data && (
              <Note>
                <Link to={`/next/hosts/${host.id}/jobs`}>{t("open the operations")}</Link>
                {" · "}
                <Button kind="word" onClick={() => setJobId("")} testId="clear-job">{t("Clear")}</Button>
              </Note>
            )}
          </Stack>
        </Card>
      ),
      output: (
        <Card
          title={preview ? t("Live") : t("Output")}
          note={preview
            ? `${t("Streaming for up to 5 minutes, capped at 32 KiB/s.")}`
              + (paused ? ` ${t("Paused — the host keeps sending, the screen does not.")}` : "")
              + (stream.dropped > 0 ? ` ${droppedNotice(stream.dropped, t)}` : "")
            : lines !== null ? t("{n} lines", { n: lines.length }) : undefined}
          tools={
            <Row>
              <Find
                value={search}
                onChange={(value) => { setSearch(value); setMatchIndex(0); }}
                placeholder={t("Find in the output")}
                testId="search"
              />
              {search.trim() !== "" && (
                <span className="fl-note" data-testid="match-count">
                  {matches.length > 0
                    ? t("{n} of {total} matches", { n: current + 1, total: matches.length })
                    : t("0 matches")}
                </span>
              )}
              <Button
                kind="quiet"
                disabled={matches.length === 0}
                onClick={() => setMatchIndex((value) => value - 1)}
                title={t("Previous match")}
                testId="previous-match"
              >
                ↑
              </Button>
              <Button
                kind="quiet"
                disabled={matches.length === 0}
                onClick={() => setMatchIndex((value) => value + 1)}
                title={t("Next match")}
                testId="next-match"
              >
                ↓
              </Button>
              <Check checked={wrap} onChange={setWrap}>{t("wrap lines")}</Check>
              <Button kind="quiet" disabled={!output?.length} onClick={download} testId="download">
                {t("Download")}
              </Button>
            </Row>
          }
          foot={footer && !preview ? footer : undefined}
        >
          {!output
            ? <Empty icon="logs">{t("Nothing read yet. Ask the host for a bounded range of its journal, or for a file on its allowlist.")}</Empty>
            : output.length === 0
              ? <Empty icon="logs">{preview ? t("Waiting for the first lines…") : t("Nothing matched.")}</Empty>
              : (
                <Stack>
                  {/* What is sought is marked where it occurs: a search that
                      can only say which line matched makes the reader do the
                      finding a second time. */}
                  <Readout
                    label={preview ? t("The stream, newest at the foot") : t("What the host sent")}
                    value={output.join("\n")}
                    lines={24}
                    highlight={search}
                    atLine={currentLine >= 0 ? currentLine : undefined}
                    wrap={wrap}
                    testId="log-output"
                  />
                </Stack>
              )}
        </Card>
      ),
    }} />
  );
}

/** The name this screen's arrangement is stored under. */
export const HOST_LOGS_SCREEN = "next_host_logs";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_LOGS: BoardEntry[] = [
  { key: "notices", title: "Notices", width: 12, height: 1 },
  { key: "counts", title: "Lines on screen", width: 8, height: 2 },
  { key: "reading", title: "Reading", width: 4, height: 2 },
  { key: "read", title: "Read", width: 5, height: 5 },
  { key: "output", title: "Output", width: 7, height: 5 },
];
