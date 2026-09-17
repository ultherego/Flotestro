import { describe, expect, it } from "vitest";
import { cancelAckLine, hasContent, outputFilename, payloadPairs } from "./Job";

const t = (key: string, params?: Record<string, string | number>) =>
  key.replace(/\{(\w+)\}/g, (_, name: string) => String(params?.[name] ?? ""));

/* The host's answer to a cancel, as the job page words it: one sentence
   per outcome of the protocol, with the phase the host named, and
   nothing before the host answered. */
describe("cancelAckLine", () => {
  it("says nothing until the host answered", () => {
    expect(cancelAckLine({}, t)).toBe("");
    expect(cancelAckLine({ cancel_phase: "accepted" }, t)).toBe("");
  });

  it("names every outcome with the phase the host was in", () => {
    expect(cancelAckLine({ cancel_outcome: "not_started", cancel_phase: "accepted" }, t)).toContain("had not started");
    expect(cancelAckLine({ cancel_outcome: "interrupted", cancel_phase: "started" }, t)).toBe("The host interrupted the task while it was started.");
    expect(cancelAckLine({ cancel_outcome: "not_interruptible", cancel_phase: "mutating" }, t)).toContain("to its end (mutating)");
    expect(cancelAckLine({ cancel_outcome: "already_done" }, t)).toContain("already finished");
  });

  it("does not guess at a word it does not know", () => {
    expect(cancelAckLine({ cancel_outcome: "something_else" }, t)).toBe("");
  });
});

/* The helpers the page has always had, guarded next to the new one. */
describe("payloadPairs", () => {
  it("flattens a shallow payload into dotted paths", () => {
    expect(payloadPairs({ unit: { name: "cron.service" }, reason: "x" })).toEqual([
      { path: "unit.name", value: "cron.service" },
      { path: "reason", value: "x" },
    ]);
  });

  it("gives up on a payload that is not an object or is too deep", () => {
    expect(payloadPairs("not json")).toBeNull();
    expect(payloadPairs([1, 2])).toBeNull();
    expect(payloadPairs({ a: { b: { c: { d: 1 } } } })).toBeNull();
  });
});

describe("outputFilename and hasContent", () => {
  it("names the file by the job, the attempt and the stream", () => {
    expect(outputFilename("0123456789abcdef", 2, "stderr")).toBe("job-01234567-attempt-2-stderr.txt");
  });

  it("tells an empty value from a value", () => {
    expect(hasContent({})).toBe(false);
    expect(hasContent(null)).toBe(false);
    expect(hasContent({ os_family: "debian" })).toBe(true);
  });
});
