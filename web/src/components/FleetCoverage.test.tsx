import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { FleetCoverage, coverageSentence, unknownBreakdown, type Coverage } from "./FleetCoverage";

/* The head of a fleet screen answers the question the old screens got
   wrong: how much of the fleet the numbers below it really describe. A
   host nobody has heard from has to be visible as unknown - never folded
   into a zero - and an answer that covers only part of the fleet has to
   say so where the reader cannot miss it. */

const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? `{${key}}`));

const whole: Coverage = {
  total_hosts: 1001, evaluated_hosts: 300, unknown_hosts: 701,
  unknown_reasons: { no_observation: 690, stale_observation: 11 },
};

afterEach(cleanup);

describe("coverageSentence", () => {
  it("says how much of the fleet the numbers describe and how much they do not", () => {
    expect(coverageSentence(whole, t)).toBe("300 of 1001 hosts evaluated · 701 unknown");
  });

  it("names the unknown hosts even when nothing was evaluated at all", () => {
    expect(coverageSentence({ total_hosts: 12, evaluated_hosts: 0, unknown_hosts: 12 }, t))
      .toBe("0 of 12 hosts evaluated · 12 unknown");
  });
});

describe("unknownBreakdown", () => {
  it("names the reasons, the largest group first, in words rather than codes", () => {
    expect(unknownBreakdown(whole, t)).toBe("690 never reported this, 11 last report too old to trust");
  });

  it("passes a reason it does not know through rather than hiding the hosts", () => {
    expect(unknownBreakdown({ ...whole, unknown_reasons: { something_new: 4 } }, t)).toBe("4 something_new");
  });

  it("says nothing when the view could not tell the reasons apart", () => {
    expect(unknownBreakdown({ total_hosts: 3, evaluated_hosts: 3, unknown_hosts: 0 }, t)).toBe("");
  });
});

describe("the coverage line", () => {
  it("shows the unknown hosts and no badge when the answer is whole", () => {
    render(<FleetCoverage coverage={whole} />);
    expect(screen.getByTestId("fleet-coverage")).toHaveTextContent("300 of 1001 hosts evaluated · 701 unknown");
    expect(screen.queryByTestId("fleet-partial")).toBeNull();
  });

  it("shows a badge and the reason when the answer is only part of the fleet", () => {
    render(<FleetCoverage coverage={{ ...whole, partial: true, partial_reason: "time_budget" }} />);
    expect(screen.getByTestId("fleet-partial")).toHaveTextContent("partial answer");
    expect(screen.getByTestId("fleet-coverage")).toHaveTextContent("ran out of its time budget");
  });

  it("shows a reason it does not know rather than a badge with nothing behind it", () => {
    render(<FleetCoverage coverage={{ ...whole, partial: true, partial_reason: "something_new" }} />);
    expect(screen.getByTestId("fleet-coverage")).toHaveTextContent("something_new");
  });

  it("draws nothing before the server has answered", () => {
    render(<FleetCoverage />);
    expect(screen.queryByTestId("fleet-coverage")).toBeNull();
  });
});
