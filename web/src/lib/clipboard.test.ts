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
  it("says no when the browser offers no way to copy at all", async () => {
    // Neither the clipboard nor the selection command: the answer is no,
    // because the old code called the clipboard optionally and reported
    // success anyway.
    withClipboard(undefined);
    const had = document.execCommand;
    // @ts-expect-error a browser without the command
    document.execCommand = undefined;
    try {
      await expect(copyToClipboard("host-1")).resolves.toBe(false);
    } finally {
      document.execCommand = had;
    }
  });

  /**
   * A panel over plain HTTP has no navigator.clipboard, which is what a
   * laboratory and a first installation both are, so for a long time the
   * Copy button there did nothing and said "copy by hand". The older way
   * needs no secure context.
   */
  it("copies through the selection where there is no clipboard, and says what the browser said", async () => {
    withClipboard(undefined);
    let copied = "";
    const had = document.execCommand;
    document.execCommand = vi.fn((command: string) => {
      if (command !== "copy") return false;
      copied = (document.querySelector("textarea") as HTMLTextAreaElement).value;
      return true;
    });
    try {
      await expect(copyToClipboard("host-1")).resolves.toBe(true);
      expect(copied).toBe("host-1");
      // Nothing is left on the page afterwards.
      expect(document.querySelector("textarea")).toBeNull();

      document.execCommand = vi.fn(() => false);
      await expect(copyToClipboard("host-1")).resolves.toBe(false);
    } finally {
      document.execCommand = had;
    }
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
