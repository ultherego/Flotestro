// Waiting for a job from a screen.
//
// A read ordered from the panel answers twice: the order at once, with the
// job, and the host later, with the attempt. A screen that wants the answer
// waits for the attempt.

/** One attempt of a job as a screen reads it: the status, the refusal and the typed detail. */
export type JobAttempt<T = unknown> = {
  status?: string;
  error_code?: string;
  message?: string;
  stdout?: string;
  detail?: T;
};

/** The part of the API client the wait needs; a test hands in a stub. */
type Reader = { get: <T>(path: string) => Promise<T> };

/** How often the attempts are asked for, and how many times before the wait gives up. */
export const JOB_POLL_INTERVAL = 1500;
export const JOB_POLL_TRIES = 30;

/**
 * Waits for the host to answer a job: polls its attempts and returns the
 * last one as soon as it has a status. A refusal is an answer too - the
 * attempt carries the reason, and the caller decides what to show.
 *
 * The wait is bounded: after the last try it returns undefined rather than
 * holding the screen for good. A job waiting for approval, or a host that
 * went away, is then left to the job list.
 */
export async function awaitJob<T = unknown>(
  api: Reader,
  jobID: string,
  { tries = JOB_POLL_TRIES, interval = JOB_POLL_INTERVAL } = {},
): Promise<JobAttempt<T> | undefined> {
  for (let attempt = 0; attempt < tries; attempt++) {
    await new Promise((done) => setTimeout(done, interval));
    const attempts = await api.get<{ items: JobAttempt<T>[] }>(`/api/v1/jobs/${jobID}/attempts`);
    const last = attempts.items[attempts.items.length - 1];
    if (last?.status) return last;
  }
  return undefined;
}
