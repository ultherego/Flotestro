import { describe, expect, it } from "vitest";
import { appliedUnverifiedNote, cancelAckLine, hasContent, outputFilename, payloadPairs, verificationLine } from "./Job";

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

/* The host's reading of itself after the change, as the job page words
   it: which verifier looked, what it expected, what it found, and the
   reason when the two differ. */
describe("verificationLine", () => {
  it("names the verifier, the expectation and the observation", () => {
    expect(verificationLine({ verifier: "unit_state", verified: true, expected: "active", observed: "active" }, t))
      .toBe("unit_state: expected active, observed active");
  });

  it("adds the reason when the state was not observed", () => {
    const line = verificationLine({
      verifier: "unit_state", verified: false, expected: "active", observed: "failed",
      reason: "the unit did not stay active",
    }, t);
    expect(line).toContain("expected active, observed failed");
    expect(line).toContain("the unit did not stay active");
  });

  it("says unknown rather than nothing for a field the host left empty", () => {
    expect(verificationLine({ verifier: "file_content", verified: false }, t)).toContain("unknown");
  });
});

/* A job that failed with applied_unverified says in full words what
   happened: the change landed and nobody saw the state that was ordered. */
describe("appliedUnverifiedNote", () => {
  it("speaks only for that code", () => {
    expect(appliedUnverifiedNote({}, t)).toBe("");
    expect(appliedUnverifiedNote({ result_error_code: "exec_failed" }, t)).toBe("");
  });

  it("says the change was made and the state was not observed", () => {
    const note = appliedUnverifiedNote({ result_error_code: "applied_unverified" }, t);
    expect(note).toContain("The change was made");
    expect(note).toContain("did not show the state");
  });
});
