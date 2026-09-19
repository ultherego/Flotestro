import { describe, expect, it } from "vitest";
import { BUFFER_RANGES, bufferSummary, historyAddress, type RelayBufferPoint } from "./Relays";

/* The buffer history is the only place the panel can say what a site went
   through while nobody was looking. Everything the card claims about a
   window is computed here, so the claims are checked here - above all the
   two that are easy to get wrong: a drop counter that starts again at
   every restart, and a fill whose limit the relay never reported. */

const point = (over: Partial<RelayBufferPoint>): RelayBufferPoint => ({
  at: "2026-09-18T08:00:00Z",
  bytes_used: 0,
  bytes_used_max: 0,
  bytes_limit: 1000,
  item_count: 0,
  item_count_max: 0,
  dropped_total: 0,
  dropped_delta: 0,
  active_sessions: 0,
  disconnected: false,
  restarted: false,
  samples: 1,
  ...over,
});

describe("historyAddress", () => {
  it("asks one relay for one window", () => {
    expect(historyAddress("r1", "7d")).toBe("/api/v1/relays/r1/buffer-history?range=7d");
  });

  it("offers the windows the raw reports and the rollups can answer", () => {
    expect([...BUFFER_RANGES]).toEqual(["3h", "24h", "7d", "30d", "90d"]);
  });
});

describe("bufferSummary", () => {
  it("sums the drops from the deltas, so a restart neither hides nor negates them", () => {
    const summary = bufferSummary([
      point({ dropped_total: 0, dropped_delta: null }),
      point({ dropped_total: 5, dropped_delta: 5 }),
      // The relay restarted: the counter starts again and the point carries
      // no delta at all.
      point({ dropped_total: 0, dropped_delta: null, restarted: true, instance_id: "second" }),
      point({ dropped_total: 2, dropped_delta: 2, instance_id: "second" }),
    ], 60);
    expect(summary.dropped).toBe(7);
    expect(summary.restarts).toBe(1);
  });

  it("counts the time without an upstream in the step of the window", () => {
    const offline = [point({ disconnected: true }), point({ disconnected: true }), point({})];
    expect(bufferSummary(offline, 60).offlineMinutes).toBe(2);
    // The same three points on a rolled-up window are quarter-hours.
    expect(bufferSummary(offline, 15 * 60).offlineMinutes).toBe(30);
  });

  it("reads the peak fill against the limit and leaves it unknown without one", () => {
    expect(bufferSummary([
      point({ bytes_used: 100, bytes_used_max: 400, bytes_limit: 1000 }),
      point({ bytes_used: 900, bytes_used_max: 950, bytes_limit: 1000 }),
    ], 60).peakPercent).toBe(95);

    // A relay that reported no limit has no share to show. An unknown
    // limit is not a limit of zero, and it is not a quiet buffer either.
    const unknown = bufferSummary([point({ bytes_used: 500, bytes_used_max: 500, bytes_limit: 0 })], 60);
    expect(unknown.peakPercent).toBeUndefined();
  });

  it("says nothing about an empty window", () => {
    expect(bufferSummary([], 60)).toEqual({
      dropped: 0, restarts: 0, peakPercent: undefined, offlineMinutes: 0,
    });
  });
});
