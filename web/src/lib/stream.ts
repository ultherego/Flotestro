import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

/** The progress of an operation in flight. Undetermined values are omitted, not zeroed. */
export type Progress = {
  job_id: string;
  step?: number;
  total?: number;
  percent?: number;
  message?: string;
};

/**
 * The operation progress stream.
 *
 * The stream carries only the signal "something changed"; the content is
 * always the API answer. If the state travelled over the stream, a screen
 * after a broken connection would show something other than recorded - and
 * the operator would have no way to notice.
 *
 * The browser resumes a broken EventSource itself, so a momentary loss of
 * the connection does not stop the preview for good.
 */
export function useProgressStream(path: string | null, keys: unknown[][]) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!path) return;
    const source = new EventSource(path, { withCredentials: true });

    const refresh = () => {
      for (const key of keys) {
        queryClient.invalidateQueries({ queryKey: key });
      }
    };
    source.addEventListener("job", refresh);
    // Connecting refreshes too: the screen may have missed changes before
    // the stream opened.
    source.addEventListener("ready", refresh);

    return () => source.close();
    // The query keys are constant within a screen; the dependency is the path.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, queryClient]);
}

/**
 * The polling interval for the aggregate views that have no stream of their
 * own. The fleet list and the dashboard change on their own - through the
 * host heartbeats - not only through operator actions.
 */
export const REFRESH_INTERVAL = 5000;

/** A shorter interval for operation lists, where progress before one's eyes counts. */
export const OPERATIONS_INTERVAL = 2000;

/**
 * The progress of operations in flight, straight from the stream.
 *
 * Progress is transient: it is not in the API and cannot be read after the
 * fact. A screen attached halfway through a transaction sees only the next
 * report - and that is enough, because the result is durable in the
 * database anyway.
 */
export function useProgress(path: string | null): Map<string, Progress> {
  const [progress, setProgress] = useState<Map<string, Progress>>(new Map());
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!path) {
      setProgress(new Map());
      return;
    }
    const source = new EventSource(path, { withCredentials: true });

    source.addEventListener("progress", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data);
        const report: Progress = { job_id: data.job_id, ...(data.progress ?? {}) };
        setProgress((previous) => new Map(previous).set(report.job_id, report));
      } catch {
        // An unreadable report is skipped: the preview must not topple the screen.
      }
    });
    // The end of an operation ends its bar - otherwise it would stay on the
    // screen and suggest something is still running.
    source.addEventListener("job", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data);
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
    });

    return () => source.close();
  }, [path, queryClient]);

  return progress;
}

/** A piece of the journal preview straight from the stream. */
export type LogChunk = { lines: string[]; dropped?: number };

/**
 * The live journal preview.
 *
 * The lines are transient: they are not in the API and cannot be read after
 * the fact. A pause stops only appending on the screen - the host keeps
 * sending, and the stream ends on its own after its time limit.
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
    const source = new EventSource(path, { withCredentials: true });

    source.addEventListener("log", (event) => {
      if (pausedRef.current) return;
      try {
        const data = JSON.parse((event as MessageEvent).data);
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
    });

    return () => source.close();
  }, [path]);

  return { lines, dropped };
}

/** How many preview lines the browser keeps. */
export const MAX_PREVIEW_LINES = 5000;
