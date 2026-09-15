import { describe, expect, it } from "vitest";
import { blockTone, formatSeconds, STATUS_REFRESH_INTERVAL } from "./Status";

/* The helpers judge the tone and shape the numbers; the page only draws
   what they say, so they are tested on their own, without a screen. */

describe("blockTone", () => {
  it("draws a block the server could not judge as unknown, never as fine", () => {
    expect(blockTone({ ok: null })).toBe("unknown");
    expect(blockTone({ ok: null, attention: "a note" })).toBe("unknown");
  });

  it("draws a failed block red whatever else it says", () => {
    expect(blockTone({ ok: false })).toBe("error");
    expect(blockTone({ ok: false, attention: "a note" })).toBe("error");
  });

  it("draws a fine block amber when it carries a note and green otherwise", () => {
    expect(blockTone({ ok: true, attention: "a consumer fails its deliveries" })).toBe("warn");
    expect(blockTone({ ok: true })).toBe("ok");
    expect(blockTone({ ok: true, attention: "" })).toBe("ok");
  });
});

describe("formatSeconds", () => {
  it("keeps a fraction below ten seconds and drops it above", () => {
    expect(formatSeconds(0.42)).toBe("0.4s");
    expect(formatSeconds(4)).toBe("4.0s");
    expect(formatSeconds(42.6)).toBe("43s");
  });

  it("breaks minutes, hours and days down to the next unit", () => {
    expect(formatSeconds(90)).toBe("1m 30s");
    expect(formatSeconds(3600 + 15 * 60)).toBe("1h 15m");
    expect(formatSeconds(2 * 86400 + 3 * 3600)).toBe("2d 3h");
  });

  it("shows a negative or unreadable value as a dash rather than a number", () => {
    expect(formatSeconds(-1)).toBe("—");
    expect(formatSeconds(Number.NaN)).toBe("—");
  });
});

describe("STATUS_REFRESH_INTERVAL", () => {
  it("refreshes every fifteen seconds", () => {
    expect(STATUS_REFRESH_INTERVAL).toBe(15_000);
  });
});
