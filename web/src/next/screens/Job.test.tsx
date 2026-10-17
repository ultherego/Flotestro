import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../components/Toast";
import {
  Job, appliedUnverifiedNote, cancelAckLine, hasContent, outputFilename, payloadPairs,
  verificationLine, OUTPUT_PREVIEW,
} from "./Job";

/**
 * One operation on one host. What is held here is what an operator's hand
 * rests on: the approval carries the hash of the payload that was on the
 * screen, a cancel does not happen on one click, a refusal is shown in
 * words, and a figure the fleet never reported is a dash and never a
 * nought.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** When set, every POST is refused with this message. */
let refusal: string | null = null;

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key the path begins with wins: "/api/v1/jobs/j1"
        // also begins "/api/v1/jobs/j1/attempts", and a short key
        // answering a longer path hands the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key || answers[key] === null) {
          return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
        }
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return refusal
          ? Promise.reject(new actual.ApiError(409, "payload_changed", refusal))
          : Promise.resolve({});
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

// The progress of what is in flight arrives over a stream this test has no
// business opening; everything asserted here comes from the API answers.
vi.mock("../../lib/stream", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/stream")>();
  return { ...actual, useProgress: () => new Map(), useProgressStream: () => undefined };
});

const job = (over: Record<string, unknown>) => ({
  id: "j1", host_id: "h1", hostname: "agent-arch", action_type: "unit.restart",
  state: "succeeded", payload: { unit: { name: "sshd.service" } },
  payload_hash: "abc123def4567890", requires_approval: false,
  required_approvals: 1, collected_approvals: 0, created_by: "tszymanski",
  result_status: "success", expires_at: "2026-10-16T12:00:00Z",
  created_at: "2026-10-16T08:00:00Z", finished_at: "2026-10-16T08:01:00Z",
  ...over,
});

const attempt = (over: Record<string, unknown>) => ({
  id: "a1", attempt_number: 1, status: "succeeded", exit_code: 0, replayed: false,
  created_at: "2026-10-16T08:00:30Z",
  ...over,
});

/**
 * One job is read in four sub-tabs since 17.10 - the order, the result,
 * the attempts and the approvals - so a test reads the one it is about,
 * by the address a link to it would carry.
 */
function draw(tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[tab ? `/jobs/j1?tab=${tab}` : "/jobs/j1"]}>
        <ToastProvider>
          <Routes><Route path="/jobs/:id" element={children} /></Routes>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Job />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  refusal = null;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("one job", () => {
  it("says what was asked, of which host, and what came back", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({}),
      "/api/v1/jobs/j1/attempts": { items: [attempt({})], count: 1 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByRole("heading", { name: /unit\.restart/ })).toBeInTheDocument());
    expect(screen.getAllByRole("link", { name: "agent-arch" })[0]).toHaveAttribute("href", "/hosts/h1");
    expect(screen.getAllByText("succeeded").length).toBeGreaterThan(0);
    // The payload is the text the hash covers, so it stands verbatim.
    expect(screen.getByTestId("payload")).toHaveTextContent("sshd.service");
  });

  it("draws a figure nobody reported as a dash, never as a nought", async () => {
    Object.assign(answers, {
      // No timeout, no result, no attempts answer at all.
      "/api/v1/jobs/j1": job({ result_status: undefined, timeout_seconds: undefined }),
      "/api/v1/jobs/j1/attempts": null,
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-timeout")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-timeout")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-timeout")).not.toHaveTextContent("0");
    // The attempts never arrived, so their number is unknown rather than none.
    await waitFor(() => expect(screen.getByTestId("kpi-attempts")).toHaveTextContent("—"));
  });

  it("approves exactly the payload the screen showed, by its hash", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ state: "awaiting_approval", requires_approval: true }),
      "/api/v1/jobs/j1/attempts": { items: [], count: 0 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("approve")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve"));
    // The dialog shows the payload before the consent is given.
    expect(screen.getByTestId("approve-payload")).toHaveTextContent("sshd.service");
    fireEvent.click(screen.getByTestId("confirm-approve"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j1/approve");
    expect(posted[0].body).toEqual({ payload_hash: "abc123def4567890", reason: undefined });
  });

  it("will not cancel without a reason the trail can keep", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ state: "awaiting_approval", requires_approval: true }),
      "/api/v1/jobs/j1/attempts": { items: [], count: 0 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("cancel")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("cancel"));
    expect(screen.getByTestId("confirm-cancel")).toBeDisabled();
    // Seven characters are not enough; the trail keeps eight.
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "too few" } });
    expect(screen.getByTestId("confirm-cancel")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the change window closed" } });
    expect(screen.getByTestId("confirm-cancel")).toBeEnabled();
    fireEvent.click(screen.getByTestId("confirm-cancel"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j1/cancel");
    expect(posted[0].body).toEqual({ reason: "the change window closed" });
  });

  it("shows a refusal in the words the server used, and keeps the dialog open", async () => {
    refusal = "the payload changed since it was read";
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ state: "awaiting_approval", requires_approval: true }),
      "/api/v1/jobs/j1/attempts": { items: [], count: 0 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("approve")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve"));
    fireEvent.click(screen.getByTestId("confirm-approve"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("the payload changed since it was read"));
    expect(screen.getByTestId("approve-payload")).toBeInTheDocument();
  });

  it("offers the order again only on a job that ended without doing its work", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ state: "failed", result_status: "failure", result_error_code: "unit_not_found" }),
      "/api/v1/jobs/j1/attempts": { items: [], count: 0 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("order-again")).toBeInTheDocument());
    expect(screen.getByTestId("order-again").getAttribute("href")).toContain("action=unit.restart");
    expect(screen.queryByTestId("approve")).toBeNull();
  });

  it("cuts a long output and hands over the whole of it on request", async () => {
    const long = "line\n".repeat(1200);
    expect(long.length).toBeGreaterThan(OUTPUT_PREVIEW);
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({}),
      "/api/v1/jobs/j1/attempts": { items: [attempt({ stdout: long })], count: 1 },
      "/api/v1/errors": { items: [] },
    });
    draw("attempts");
    await waitFor(() => expect(screen.getByTestId("output-stdout")).toBeInTheDocument());
    expect(screen.getByTestId("output-stdout").textContent?.length).toBeLessThan(long.length);
    fireEvent.click(screen.getByTestId("more-stdout"));
    expect(screen.getByTestId("output-stdout").textContent?.length).toBe(long.length);
  });

  it("puts the host's own reading of itself beside the result", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ state: "failed", result_error_code: "applied_unverified" }),
      "/api/v1/jobs/j1/attempts": {
        items: [attempt({
          verification: { verifier: "unit_health", verified: false, expected: "active", observed: "failed", reason: "start limit hit" },
        })],
        count: 1,
      },
      "/api/v1/errors": { items: [] },
    });
    draw("result");
    await waitFor(() => expect(screen.getAllByText("not observed").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/expected active, observed failed/)[0]).toBeInTheDocument();
    // A change made and not observed is said before anything else.
    expect(screen.getByRole("status")).toHaveTextContent("repeating the operation would repeat a change that already happened");
  });

  it("says a refusal of the job itself rather than drawing an empty screen", async () => {
    Object.assign(answers, { "/api/v1/jobs/j1": null });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("no such thing"));
  });

  it("names the campaign and the fan-out the job belongs to inside the new panel", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ campaign_id: "c9", fanout_id: "f7" }),
      "/api/v1/jobs/j1/attempts": { items: [], count: 0 },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByRole("link", { name: "c9" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "c9" })).toHaveAttribute("href", "/campaigns/c9");
    expect(screen.getByRole("link", { name: "f7" })).toHaveAttribute("href", "/reads/f7");
  });

  it("draws the plan the host computed, with the packages it names", async () => {
    Object.assign(answers, {
      "/api/v1/jobs/j1": job({ action_type: "packages.upgrade" }),
      "/api/v1/jobs/j1/attempts": {
        items: [attempt({
          detail: {
            kind: "package_plan", mode: "upgrade", manager: "apt", plan_hash: "deadbeefdeadbeef",
            changes: [{ name: "openssl", current_version: "3.0.1", candidate_version: "3.0.2", security: true }],
          },
        })],
        count: 1,
      },
      "/api/v1/errors": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("plan-changes")).toBeInTheDocument());
    const row = within(screen.getByTestId("plan-changes")).getByText("openssl").closest("tr") as HTMLElement;
    expect(row).toHaveTextContent("3.0.1");
    expect(row).toHaveTextContent("3.0.2");
    expect(within(row).getByText("security")).toBeInTheDocument();
  });
});

describe("what the screen reads out of a job", () => {
  it("turns a payload into a field per leaf, and gives up where JSON is the honest form", () => {
    expect(payloadPairs({ unit: { name: "sshd.service", mode: "replace" } })).toEqual([
      { path: "unit.name", value: "sshd.service" },
      { path: "unit.mode", value: "replace" },
    ]);
    // A list of objects is a table of its own; the JSON stands instead.
    expect(payloadPairs({ rules: [{ port: 22 }] })).toBeNull();
    expect(payloadPairs("not json at all")).toBeNull();
    expect(payloadPairs([1, 2, 3])).toBeNull();
  });

  it("says what the host answered to a cancel, and nothing when it has not", () => {
    const t = (text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? ""));
    expect(cancelAckLine({ cancel_outcome: "not_started" }, t)).toContain("will not start");
    expect(cancelAckLine({ cancel_outcome: "interrupted", cancel_phase: "downloading" }, t)).toContain("downloading");
    expect(cancelAckLine({}, t)).toBe("");
  });

  it("reads a verification as one line, and says unknown where the host said nothing", () => {
    const t = (text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? ""));
    expect(verificationLine({ verifier: "unit_health", verified: true, expected: "active", observed: "active" }, t))
      .toBe("unit_health: expected active, observed active");
    expect(verificationLine({ verified: false, reason: "start limit hit" }, t))
      .toBe("unknown: expected unknown, observed unknown — start limit hit");
  });

  it("warns only about a change that landed without being observed", () => {
    const t = (text: string) => text;
    expect(appliedUnverifiedNote({ result_error_code: "applied_unverified" }, t)).not.toBe("");
    expect(appliedUnverifiedNote({ result_error_code: "unit_not_found" }, t)).toBe("");
    expect(appliedUnverifiedNote({}, t)).toBe("");
  });

  it("treats an empty object as nothing said", () => {
    expect(hasContent({})).toBe(false);
    expect(hasContent(null)).toBe(false);
    expect(hasContent({ needs: "x" })).toBe(true);
  });

  it("names an output file by the job, the attempt and the stream", () => {
    expect(outputFilename("abcdef1234567890", 2, "stderr")).toBe("job-abcdef12-attempt-2-stderr.txt");
  });
});
