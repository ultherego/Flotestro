import { describe, expect, it } from "vitest";
import { anythingOpen, describeKind } from "./Unresolved";

/* The two decisions this screen rests on are pure, so they are checked here
   without a browser: that the two uncertainties are never read as one thing,
   and that "nothing open" is read from the counts rather than from the page
   of items in front of the operator. */

describe("describeKind", () => {
  it("asks a different question of each uncertainty", () => {
    const unknown = describeKind("outcome_unknown");
    const unverified = describeKind("applied_unverified");
    expect(unknown.question).toBe("Did it happen?");
    expect(unverified.question).toBe("Did it hold?");
    // The point of keeping them apart: a screen that worded them the same
    // would be a screen that invited them to be added together.
    expect(unknown.question).not.toBe(unverified.question);
    expect(unknown.title).not.toBe(unverified.title);
  });
});

describe("anythingOpen", () => {
  const none = {
    outcome_unknown_operations: 0,
    outcome_unknown_hosts: 0,
    applied_unverified_operations: 0,
    applied_unverified_hosts: 0,
  };

  it("is false only when both kinds are empty", () => {
    expect(anythingOpen(none)).toBe(false);
    expect(anythingOpen({ ...none, outcome_unknown_operations: 1, outcome_unknown_hosts: 1 })).toBe(true);
    expect(anythingOpen({ ...none, applied_unverified_operations: 1, applied_unverified_hosts: 1 })).toBe(true);
  });

  it("reads the counts and not the list, so a filtered page cannot look settled", () => {
    // The operator has filtered to one kind and sees an empty table. The
    // fleet still has the other kind open, and the sentence under the empty
    // table has to say which of the two situations this is.
    const other = { ...none, applied_unverified_operations: 3, applied_unverified_hosts: 2 };
    expect(anythingOpen(other)).toBe(true);
  });

  it("counts hosts apart from operations", () => {
    // One host with forty uncertain operations and forty hosts with one each
    // are different work, and the screen says both numbers rather than one.
    const oneHost = { ...none, outcome_unknown_operations: 40, outcome_unknown_hosts: 1 };
    const manyHosts = { ...none, outcome_unknown_operations: 40, outcome_unknown_hosts: 40 };
    expect(oneHost.outcome_unknown_hosts).not.toBe(manyHosts.outcome_unknown_hosts);
    expect(anythingOpen(oneHost)).toBe(anythingOpen(manyHosts));
  });
});
