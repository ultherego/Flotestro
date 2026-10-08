import { describe, expect, it } from "vitest";
import { parsePayload, payloadHint } from "./Reads";

/* A payload is an object grouped by name. Text that parses but is not an object
   - a list, a number, a string - used to be reported as "not valid JSON", which
   is the one thing it is not: the operator then reads their own quotes looking
   for a typo that is not there. The API answered the same way until 08.10 and
   was corrected in the same change. */

const t = (text: string) => text;

describe("the payload field of a fan-out read", () => {
  it("accepts an object grouped by name", () => {
    const parsed = parsePayload('{"journal": {"lines": 100}}');
    expect(parsed.error).toBeUndefined();
    expect(parsed.value).toEqual({ journal: { lines: 100 } });
  });

  it("treats an empty field as an empty payload rather than as an error", () => {
    expect(parsePayload("   ")).toEqual({ value: {} });
  });

  it("does not call a list invalid JSON, and says what shape it wants", () => {
    const parsed = parsePayload('[{"journal": {"lines": 100}}]');
    expect(parsed.value).toBeUndefined();
    expect(parsed.shape).toBe(true);
    const said = payloadHint(t, parsed);
    expect(said).not.toContain("not valid JSON");
    expect(said).toContain("grouped by name");
  });

  it("still calls broken JSON broken", () => {
    const parsed = parsePayload('{"journal": {');
    expect(parsed.shape).toBeUndefined();
    expect(payloadHint(t, parsed)).toContain("not valid JSON");
  });

  it("says what the field is for when nothing is wrong", () => {
    expect(payloadHint(t, parsePayload('{"journal": {"lines": 1}}'))).toContain("the host page sends");
  });
});
