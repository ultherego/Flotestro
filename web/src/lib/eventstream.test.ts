import { describe, expect, it, vi } from "vitest";
import { readEventStream } from "./eventstream";

function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

describe("readEventStream", () => {
  it("carries the session credentials and reads the frames", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: streamOf(["event: job\ndata: {\"job_id\":\"a\"}\n\n", "event: ready\ndata: {}\n\n"]),
    });
    vi.stubGlobal("fetch", fetchMock);
    const seen: string[] = [];
    const controller = new AbortController();
    const reading = readEventStream("/api/v1/events", (e) => {
      seen.push(e.event);
      if (seen.length === 2) controller.abort();
    }, controller.signal);
    await reading;
    expect(seen).toEqual(["job", "ready"]);
    // The credentials of this session, not only a cookie: the token login
    // sets no cookie at all.
    expect(fetchMock).toHaveBeenCalled();
    const [, options] = fetchMock.mock.calls[0];
    expect(options.credentials).toBe("same-origin");
    expect(options.headers.Accept).toBe("text/event-stream");
    vi.unstubAllGlobals();
  });

  it("keeps a frame a chunk cut in half", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: streamOf(["event: job\nda", "ta: {\"job_id\":\"b\"}\n\n"]),
    });
    vi.stubGlobal("fetch", fetchMock);
    const seen: { event: string; data: string }[] = [];
    const controller = new AbortController();
    await readEventStream("/api/v1/events", (e) => {
      seen.push(e);
      controller.abort();
    }, controller.signal);
    expect(seen).toEqual([{ event: "job", data: '{"job_id":"b"}' }]);
    vi.unstubAllGlobals();
  });

  it("says it is not connected when the stream is refused", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401, body: null });
    vi.stubGlobal("fetch", fetchMock);
    const states: boolean[] = [];
    const controller = new AbortController();
    const reading = readEventStream("/api/v1/events", () => {}, controller.signal, (on) => {
      states.push(on);
      controller.abort();
    });
    await reading;
    expect(states).toEqual([false]);
    vi.unstubAllGlobals();
  });
});
