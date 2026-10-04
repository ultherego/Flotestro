import { fetchWithCredentials } from "./api";

/** One frame of a server-sent event stream: the name and the payload. */
export type StreamEvent = { event: string; data: string };

/**
 * A server-sent event stream opened with the credentials of this session.
 *
 * EventSource cannot carry a header, so the only credential it sends is the
 * session cookie - and that cookie is set on the OIDC callback and nowhere
 * else. On an installation signed in with a token, which is every installation
 * before an identity provider is configured, every stream was answered 401 and
 * the screens fell back to polling without saying why.
 *
 * So the stream is read with fetch, which can carry the token. What this gives
 * up is the browser's own reconnection, so it is done here: a stream that ends
 * is opened again after a pause, until the caller aborts. The pause grows to a
 * ceiling, because a panel that is restarting should not be asked ten times a
 * second.
 */
export async function readEventStream(
  path: string,
  onEvent: (event: StreamEvent) => void,
  signal: AbortSignal,
  onState?: (connected: boolean) => void,
): Promise<void> {
  let pause = 1000;
  const ceiling = 15000;

  while (!signal.aborted) {
    try {
      const response = await fetchWithCredentials(path, {
        signal,
        headers: { Accept: "text/event-stream" },
      });
      if (!response.ok || !response.body) {
        throw new Error(`the stream answered ${response.status}`);
      }
      onState?.(true);
      pause = 1000;
      await readFrames(response.body, onEvent, signal);
    } catch {
      // An aborted read is the caller leaving the screen, not a failure.
      if (signal.aborted) break;
    }
    onState?.(false);
    if (signal.aborted) break;
    await sleep(pause, signal);
    pause = Math.min(pause * 2, ceiling);
  }
}

/** readFrames turns the bytes into frames, keeping what a chunk cut in half. */
async function readFrames(
  body: ReadableStream<Uint8Array>,
  onEvent: (event: StreamEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      // A frame ends with a blank line. Anything after the last one is the
      // beginning of the next frame and waits for the rest of it.
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const parsed = parseFrame(frame);
        if (parsed) onEvent(parsed);
        boundary = buffer.indexOf("\n\n");
      }
    }
  } finally {
    reader.cancel().catch(() => {
      // The stream is being left; a cancel that fails changes nothing.
    });
  }
}

/**
 * parseFrame reads the lines of one frame. A frame with no data line carries
 * nothing - a comment keeping the connection open - and a name is "message"
 * when the frame does not give one, as the protocol says.
 */
function parseFrame(frame: string): StreamEvent | null {
  let event = "";
  const data: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
    if (field === "event") event = value;
    if (field === "data") data.push(value);
  }
  if (data.length === 0) return null;
  return { event: event || "message", data: data.join("\n") };
}

function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}
