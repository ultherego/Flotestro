import { afterEach, describe, expect, it, vi } from "vitest";
import { copyToClipboard } from "./clipboard";

const original = navigator.clipboard;

function withClipboard(value: unknown) {
  Object.defineProperty(navigator, "clipboard", { value, configurable: true });
}

afterEach(() => {
  Object.defineProperty(navigator, "clipboard", { value: original, configurable: true });
});

describe("copyToClipboard", () => {
  it("says no when the browser offers no clipboard", async () => {
    // A panel over plain HTTP: no secure context, no navigator.clipboard. The
    // old code called it optionally and reported success anyway.
    withClipboard(undefined);
    await expect(copyToClipboard("host-1")).resolves.toBe(false);
  });

  it("says no when the write is refused", async () => {
    withClipboard({ writeText: vi.fn().mockRejectedValue(new Error("denied")) });
    await expect(copyToClipboard("host-1")).resolves.toBe(false);
  });

  it("says yes only once the write has finished", async () => {
    let settled = false;
    const writeText = vi.fn().mockImplementation(async () => {
      await Promise.resolve();
      settled = true;
    });
    withClipboard({ writeText });
    const answer = await copyToClipboard("host-1");
    expect(answer).toBe(true);
    expect(settled).toBe(true);
    expect(writeText).toHaveBeenCalledWith("host-1");
  });
});
