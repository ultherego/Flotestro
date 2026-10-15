import { describe, expect, it } from "vitest";
import { anythingOpen, describeKind, readingKind, verifierReading } from "./Unresolved";
import { pageNumbers } from "../components/layout";

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

describe("the verifier's reading", () => {
  const encode = (value: unknown) =>
    btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))));

  it("comes back out of the base64 the server writes it as", () => {
    const raw = encode({ expected: "vm.nr_hugepages=1048576", observed: "vm.nr_hugepages=1205", verified: false });
    expect(verifierReading(raw)).toMatchObject({
      expected: "vm.nr_hugepages=1048576",
      observed: "vm.nr_hugepages=1205",
    });
  });

  it("keeps a path that is not ASCII intact", () => {
    // atob alone gives one byte per character, so this is the case that
    // decides whether the one line an operator reads to find the file is
    // readable at all.
    const raw = encode({ expected: "sha256:aa", observed: "sha256:bb", reason: "the file /srv/ważne/plik.conf differs" });
    expect(verifierReading(raw)?.reason).toContain("/srv/ważne/plik.conf");
  });

  it("is nothing rather than a crash when the host sent something odd", () => {
    for (const raw of ["", "not base64 at all!!", btoa("{"), btoa('"a string"'), null, undefined, 7]) {
      expect(verifierReading(raw)).toBeNull();
    }
  });

  it("takes an object as it is, for the day the server stops encoding it", () => {
    expect(verifierReading({ expected: "a", observed: "b" })).toEqual({ expected: "a", observed: "b" });
  });
});

describe("the reading the server decided", () => {
  it("is taken from the row rather than worked out again", () => {
    // The rule moved into SQL on 15.10: the list is paged and counted on the
    // server, so a screen that classified on its own would put numbers above
    // a list that disagree with it. What the row says wins over what this
    // code would have derived - here the two deliberately differ.
    const reading = { expected: "on", observed: "off" };
    expect(readingKind("applied_unverified", reading, "could_not_read")).toBe("could_not_read");
    expect(readingKind("applied_unverified", null, "did_not_hold")).toBe("did_not_hold");
    expect(readingKind("outcome_unknown", null, "did_not_hold")).toBe("did_not_hold");
  });

  it("falls back to the old derivation for a row that carries none", () => {
    // A panel being upgraded serves rows from before the field: they are
    // classified rather than left blank.
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" })).toBe("did_not_hold");
    expect(readingKind("applied_unverified", { expected: "on", observed: "unknown" })).toBe("could_not_read");
    expect(readingKind("outcome_unknown", null)).toBe("outcome_unknown");
  });

  it("ignores a value it does not know rather than trusting it", () => {
    // The field crosses the wire, so it is host-shaped data in the end: a
    // reading nobody defined is derived instead of displayed.
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" }, "something-else"))
      .toBe("did_not_hold");
  });
});

describe("what a row actually says", () => {
  it("is a conclusion when the host answered and shows something else", () => {
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" })).toBe("did_not_hold");
  });

  it("is the absence of one when the host could not be read", () => {
    // The difference the screen was hiding: "unknown" is not a value the host
    // holds, it is the verifier saying it could not look.
    expect(readingKind("applied_unverified", { expected: "on", observed: "unknown" })).toBe("could_not_read");
    expect(readingKind("applied_unverified", null)).toBe("could_not_read");
    expect(readingKind("applied_unverified", { expected: "on" })).toBe("could_not_read");
  });

  it("never claims a change did not hold when the question is whether it happened", () => {
    expect(readingKind("outcome_unknown", { expected: "on", observed: "off" })).toBe("outcome_unknown");
  });
});

describe("the page numbers", () => {
  it("always offer the first and the last", () => {
    expect(pageNumbers(1, 1)).toEqual([1]);
    expect(pageNumbers(1, 3)).toEqual([1, 2, 3]);
    const far = pageNumbers(10, 30);
    expect(far[0]).toBe(1);
    expect(far[far.length - 1]).toBe(30);
  });

  it("keep the current one in the middle of its neighbours", () => {
    expect(pageNumbers(10, 30)).toEqual([1, "gap", 8, 9, 10, 11, 12, "gap", 30]);
  });

  it("print a single skipped number rather than hide it behind a gap of the same width", () => {
    expect(pageNumbers(4, 20)).toEqual([1, 2, 3, 4, 5, 6, "gap", 20]);
  });

  it("answer nothing for a list with no pages", () => {
    expect(pageNumbers(1, 0)).toEqual([]);
  });
});
