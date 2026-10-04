import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { readEventStream } from "./eventstream";

/** The progress of an operation in flight. Undetermined values are omitted, not zeroed. */
export type Progress = {
  job_id: string;
  step?: number;
  total?: number;
  percent?: number;
  message?: string;
};

/**
 * The operation progress stream. The stream carries only the signal
 * "something changed"; the content is always the API answer.
 */
export function useProgressStream(path: string | null, keys: unknown[][]) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!path) return;
    const refresh = () => {
      for (const key of keys) {
        queryClient.invalidateQueries({ queryKey: key });
      }
    };
    // Read with fetch and not with EventSource: EventSource carries no header,
    // so on a session signed in with a token - every installation before an
    // identity provider - the stream was answered 401 and the screen fell back
    // to polling without saying why.
    const controller = new AbortController();
    void readEventStream(path, (event) => {
      // "ready" refreshes too: the screen may have missed changes before the
      // stream opened.
      if (event.event === "job" || event.event === "timeline" || event.event === "ready") {
        refresh();
      }
    }, controller.signal);

    return () => controller.abort();
    // The query keys are constant within a screen; the dependency is the path.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, queryClient]);
}

/** A turn of an installation order, as the stream announces it. */
export type EnrollmentTurn = {
  request_id: string;
  change: "created" | "redeemed" | "refused" | "revoked";
  site?: string;
  environment?: string;
  kind?: string;
  host_id?: string;
  code?: string;
};

/**
 * The turns of one installation order, from the fleet stream.
 */
export function useEnrollmentStream(requestId: string | null, keys: unknown[][]) {
  const queryClient = useQueryClient();
  const [connected, setConnected] = useState(false);
  const [lastTurn, setLastTurn] = useState<EnrollmentTurn | null>(null);

  useEffect(() => {
    if (!requestId) {
      setConnected(false);
      setLastTurn(null);
      return;
    }
    const refresh = () => {
      for (const key of keys) {
        queryClient.invalidateQueries({ queryKey: key });
      }
    };
    const controller = new AbortController();
    void readEventStream("/api/v1/events", (event) => {
      if (event.event === "ready") {
        refresh();
        return;
      }
      if (event.event !== "enrollment") return;
      try {
        const data = JSON.parse(event.data);
        const turn: EnrollmentTurn | undefined = data.enrollment;
        if (!turn || turn.request_id !== requestId) return;
        setLastTurn(turn);
        refresh();
      } catch {
        // An unreadable turn is skipped: the poll still reads the order.
      }
      // A stream that broke is opened again by the reader; until it answers,
      // the poll is the only source and the screen is told so.
    }, controller.signal, setConnected);

    return () => {
      controller.abort();
      setConnected(false);
    };
    // The query keys are constant within a screen; the dependency is the order.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestId, queryClient]);

  return { connected, lastTurn };
}

/**
 * The polling interval for the aggregate views that have no stream of their
 * own.
 */
export const REFRESH_INTERVAL = 5000;

/** A shorter interval for operation lists, where progress before one's eyes counts. */
export const OPERATIONS_INTERVAL = 2000;

/**
 * The progress of operations in flight, straight from the stream. Progress
 * is transient: it is not in the API and cannot be read after the fact.
 */
export function useProgress(path: string | null): Map<string, Progress> {
  const [progress, setProgress] = useState<Map<string, Progress>>(new Map());
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!path) {
      setProgress(new Map());
      return;
    }
    const controller = new AbortController();
    void readEventStream(path, (event) => {
      if (event.event === "progress") {
        try {
          const data = JSON.parse(event.data);
          const report: Progress = { job_id: data.job_id, ...(data.progress ?? {}) };
          setProgress((previous) => new Map(previous).set(report.job_id, report));
        } catch {
          // An unreadable report is skipped: the preview must not topple the screen.
        }
        return;
      }
      if (event.event !== "job") return;
      // The end of an operation ends its bar - otherwise it would stay on the
      // screen and suggest something is still running.
      try {
        const data = JSON.parse(event.data);
        if (["succeeded", "failed", "canceled", "expired", "rejected"].includes(data.state)) {
          setProgress((previous) => {
            const copy = new Map(previous);
            copy.delete(data.job_id);
            return copy;
          });
        }
      } catch {
        // as above
      }
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    }, controller.signal);

    return () => controller.abort();
  }, [path, queryClient]);

  return progress;
}

/** A piece of the journal preview straight from the stream. */
export type LogChunk = { lines: string[]; dropped?: number };

/**
 * The live journal preview. The lines are transient: they are not in the API
 * and cannot be read after the fact.
 */
export function useJournalPreview(path: string | null, paused: boolean) {
  const [lines, setLines] = useState<string[]>([]);
  const [dropped, setDropped] = useState(0);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    if (!path) return;
    setLines([]);
    setDropped(0);
    const controller = new AbortController();
    void readEventStream(path, (event) => {
      if (event.event !== "log" || pausedRef.current) return;
      try {
        const data = JSON.parse(event.data);
        const chunk: LogChunk = data.log;
        if (!chunk) return;
        setLines((previous) => {
          const combined = [...previous, ...(chunk.lines ?? [])];
          // The browser buffer has limits too: a preview lasting a quarter
          // of an hour would eat the tab's memory.
          return combined.length > MAX_PREVIEW_LINES
            ? combined.slice(combined.length - MAX_PREVIEW_LINES)
            : combined;
        });
        if (chunk.dropped) setDropped((sum) => sum + chunk.dropped!);
      } catch {
        // An unreadable chunk is skipped: the preview must not topple the screen.
      }
    }, controller.signal);

    return () => controller.abort();
  }, [path]);

  return { lines, dropped };
}

/** How many preview lines the browser keeps. */
export const MAX_PREVIEW_LINES = 5000;
