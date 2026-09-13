import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import type { ErrorGuide } from "../lib/errors";
import { TARGET_STATES } from "../lib/targets";
import { ConnectionState, ErrorCode, JobState, OptionalFlag, OptionalNumber } from "./ui";

/* The guide comes from the server once per session; the component reads
   it through a hook, which is replaced here by a fixed map. The map is
   hoisted with the mock, because the mock factory runs while the
   component module is being imported, before this file's own body. */
const GUIDES = vi.hoisted(() => new Map<string, ErrorGuide>([
  ["E_LOCK_HELD", {
    code: "E_LOCK_HELD",
    stage: "apply",
    retry: "automatic",
    meaning: "Another package operation holds the lock.",
    action: "Wait for it to finish.",
    counts_as_failure: false,
  }],
  ["E_PRECONDITION", {
    code: "E_PRECONDITION",
    stage: "plan",
    retry: "after_change",
    meaning: "A precondition of the operation does not hold on the host.",
    action: "Change the host, then order again.",
    counts_as_failure: true,
  }],
]));

vi.mock("../lib/errors", () => ({
  useErrorGuides: () => GUIDES,
}));

afterEach(cleanup);

describe("ErrorCode", () => {
  it("renders a dash without a code", () => {
    const { container } = render(<ErrorCode code={null} />);
    expect(container).toHaveTextContent("—");
    expect(container.querySelector("code")).toBeNull();
  });

  it("shows the guide of a known code on hover", () => {
    const { container } = render(<ErrorCode code="E_LOCK_HELD" />);
    const code = container.querySelector("code");
    expect(code).toHaveTextContent("E_LOCK_HELD");
    const title = code?.getAttribute("title") ?? "";
    expect(title).toContain("Another package operation holds the lock.");
    expect(title).toContain("Next: Wait for it to finish.");
    expect(title).toContain("Retry: retried automatically");
  });

  it("marks a code that does not count as a failure as a source note", () => {
    const { container: quiet } = render(<ErrorCode code="E_LOCK_HELD" />);
    expect(quiet.querySelector("code")).toHaveClass("source");
    cleanup();
    const { container: failure } = render(<ErrorCode code="E_PRECONDITION" />);
    expect(failure.querySelector("code")).not.toHaveClass("source");
    expect(failure.querySelector("code")?.getAttribute("title")).toContain("Retry: retry after the named change");
  });

  it("keeps an unknown code visible, without a guide", () => {
    const { container } = render(<ErrorCode code="E_NOBODY_KNOWS" />);
    const code = container.querySelector("code");
    expect(code).toHaveTextContent("E_NOBODY_KNOWS");
    expect(code).not.toHaveAttribute("title");
  });
});

/**
 * The states JobState classifies by name. They are listed here as the
 * component lists them; a state added to the component without a
 * meaning shows a badge with nothing on hover, and this list is what
 * catches it.
 */
const JOB_STATES = [
  // succeeded
  "succeeded", "completed", "active",
  // failed
  "failed", "timed_out", "expired", "partially_applied",
  // not a failure: the host took no part
  "ineligible", "skipped", "no_change",
  // waiting
  "awaiting_approval", "queued", "planned", "planning", "paused", "awaiting_budget",
];

describe("JobState and its meanings", () => {
  it.each(TARGET_STATES)("explains the target state %s on hover", (state) => {
    const { container } = render(<JobState state={state} />);
    const badge = container.querySelector(".badge");
    expect(badge).not.toBeNull();
    expect(badge?.getAttribute("title") ?? "").not.toBe("");
  });

  it.each(JOB_STATES)("explains the job state %s on hover", (state) => {
    const { container } = render(<JobState state={state} />);
    const badge = container.querySelector(".badge");
    expect(badge?.getAttribute("title") ?? "").not.toBe("");
  });

  it("colours the outcome, not the identifier", () => {
    const tone = (state: string) => {
      const { container } = render(<JobState state={state} />);
      const className = container.querySelector(".badge")?.className ?? "";
      cleanup();
      return className.trim();
    };
    expect(tone("succeeded")).toBe("badge ok");
    expect(tone("failed")).toBe("badge error");
    expect(tone("timed_out")).toBe("badge error");
    // Incapability and a skip are not failures: no red.
    expect(tone("ineligible")).toBe("badge unknown");
    expect(tone("skipped")).toBe("badge unknown");
    expect(tone("awaiting_approval")).toBe("badge warn");
    expect(tone("running")).toBe("badge");
  });

  it("names the state for the operator and keeps an unknown one as it came", () => {
    const { container: known } = render(<JobState state="awaiting_approval" />);
    expect(known).toHaveTextContent("awaiting approval");
    cleanup();
    const { container: unknown } = render(<JobState state="something_new" />);
    expect(unknown).toHaveTextContent("something_new");
    expect(unknown.querySelector(".badge")).not.toHaveAttribute("title");
  });
});

describe("the unknown-is-not-zero widgets", () => {
  it("shows a missing number as unknown, a zero as zero", () => {
    const { container: missing } = render(<OptionalNumber value={null} />);
    expect(missing.querySelector(".badge.unknown")).toHaveTextContent("unknown");
    cleanup();
    const { container: zero } = render(<OptionalNumber value={0} />);
    expect(zero).toHaveTextContent("0");
    expect(zero.querySelector(".badge")).toBeNull();
    cleanup();
    const { container: some } = render(<OptionalNumber value={3} warnFrom={1} />);
    expect(some.querySelector(".badge.warn")).toHaveTextContent("3");
  });

  it("shows a missing flag as unknown", () => {
    const { container: missing } = render(<OptionalFlag value={undefined} />);
    expect(missing.querySelector(".badge.unknown")).toHaveTextContent("unknown");
    cleanup();
    const { container: yes } = render(<OptionalFlag value={true} />);
    expect(yes.querySelector(".badge.warn")).toHaveTextContent("yes");
    cleanup();
    const { container: no } = render(<OptionalFlag value={false} />);
    expect(no).toHaveTextContent("no");
  });

  it("gives the unknown connection state a look of its own", () => {
    const { container: unknown } = render(<ConnectionState state="unknown" />);
    expect(unknown.querySelector(".badge")).toHaveClass("unknown");
    cleanup();
    const { container: online } = render(<ConnectionState state="online" />);
    expect(online.querySelector(".badge")).toHaveClass("ok");
  });
});
