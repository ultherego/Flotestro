import { describe, expect, it } from "vitest";
import { readinessVerdict } from "./Readiness";

/* The screen exists because "unknown is not zero" was being enforced in every
   module and nowhere shown to the operator. The one way to fail at that here
   is to show a green zero over a fleet whose hosts have said nothing, so that
   is what this holds. */

describe("the verdict at the head of the readiness screen", () => {
  it("is ok only when every host answered and nothing is missing", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 0, gaps: [] })).toBe("ok");
  });

  it("is unknown when a host has reported no adapter, even with no gap found", () => {
    // The gaps are empty because the silent host contributes none: it is not
    // known to be missing anything, which is a different thing from being
    // known to be complete.
    expect(readinessVerdict({ silent: 1, unorderable: 0, gaps: [] })).toBe("unknown");
  });

  it("asks for attention when an operation can be ordered nowhere", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 3, gaps: [{ nowhere: true }] }))
      .toBe("attention");
  });

  it("asks for attention over a gap on some hosts", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 0, gaps: [{ nowhere: false }] }))
      .toBe("attention");
  });

  it("puts attention above unknown: a known gap is not softened by a silent host", () => {
    expect(readinessVerdict({ silent: 2, unorderable: 5, gaps: [{ nowhere: true }] }))
      .toBe("attention");
  });
});
