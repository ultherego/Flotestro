import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { awaitJob, type JobAttempt } from "./jobs";

/* The attempts come from the API; the client is a function each test
   programs. The clock is faked, so a wait of thirty tries takes no time. */
const get = vi.fn();
const api = { get: get as <T>(path: string) => Promise<T> };

beforeEach(() => vi.useFakeTimers());

afterEach(() => {
  vi.useRealTimers();
  get.mockReset();
});

/** A page of attempts as the API answers it. */
function page(...items: JobAttempt[]) {
  return Promise.resolve({ items });
}

describe("awaitJob", () => {
  it("asks for the attempts of the job and returns the last one once it has a status", async () => {
    get.mockReturnValueOnce(page()).mockReturnValueOnce(page({ status: "succeeded", stdout: "{}" }));
    const wait = awaitJob(api, "job-1", { interval: 10 });
    await vi.advanceTimersByTimeAsync(25);
    await expect(wait).resolves.toEqual({ status: "succeeded", stdout: "{}" });
    expect(get).toHaveBeenCalledTimes(2);
    expect(get).toHaveBeenCalledWith("/api/v1/jobs/job-1/attempts");
  });

  it("returns a refusal as the answer rather than throwing it away", async () => {
    get.mockReturnValue(page({ status: "failed", error_code: "unit_not_found", message: "no such unit" }));
    const wait = awaitJob(api, "job-2", { interval: 10 });
    await vi.advanceTimersByTimeAsync(10);
    await expect(wait).resolves.toMatchObject({ status: "failed", error_code: "unit_not_found" });
  });

  it("keeps waiting while an attempt is there but not finished", async () => {
    get.mockReturnValueOnce(page({})).mockReturnValueOnce(page({ status: "succeeded" }));
    const wait = awaitJob(api, "job-3", { interval: 10 });
    await vi.advanceTimersByTimeAsync(20);
    await expect(wait).resolves.toEqual({ status: "succeeded" });
  });

  it("gives up after the last try and says so with undefined, not an error", async () => {
    get.mockReturnValue(page());
    const wait = awaitJob(api, "job-4", { tries: 3, interval: 10 });
    await vi.advanceTimersByTimeAsync(30);
    await expect(wait).resolves.toBeUndefined();
    expect(get).toHaveBeenCalledTimes(3);
  });

  it("lets an error of the API through to the caller", async () => {
    get.mockRejectedValue(new Error("no such job"));
    const wait = awaitJob(api, "job-5", { interval: 10 });
    // The rejection is claimed before the clock moves, so it is not unhandled.
    const outcome = expect(wait).rejects.toThrow("no such job");
    await vi.advanceTimersByTimeAsync(10);
    await outcome;
  });
});
