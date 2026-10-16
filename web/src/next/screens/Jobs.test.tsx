import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import { Jobs, jobTone, orderAgainAddress, prettyJSON, reasonAccepted } from "./Jobs";
import { ToastProvider } from "../../components/Toast";

/**
 * What is held here is the behaviour an operator's day rests on: the list
 * narrows on the server, a figure nobody reported is a dash, an approval
 * carries the hash of the payload that was on screen, and nothing
 * destructive happens on one click.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key that the path begins with wins: "/api/v1/jobs"
        // also begins "/api/v1/jobs/x/attempts", and a short key answering
        // a longer path hands the screen somebody else's document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        // An Error standing in the table is a refusal, so a test can ask
        // what the screen does when a read comes back as one.
        const value = answers[key];
        if (value instanceof Error) return Promise.reject(value);
        return Promise.resolve(value);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({});
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

// The progress of what is in flight arrives over a stream this test has
// no business opening; the rows are read from the list either way.
vi.mock("../../lib/stream", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/stream")>();
  return { ...actual, useProgress: () => new Map() };
});

const job = (over: Record<string, unknown>) => ({
  id: "j1", host_id: "h1", hostname: "agent-arch", action_type: "unit.restart",
  state: "succeeded", payload: { unit: { name: "sshd.service" } }, payload_hash: "abc123def456789",
  requires_approval: false, required_approvals: 1, collected_approvals: 0,
  created_by: "tszymanski", result_status: "success",
  expires_at: "2026-10-16T12:00:00Z", created_at: "2026-10-16T08:00:00Z",
  finished_at: "2026-10-16T08:01:00Z",
  ...over,
});

const layout = { widgets: [], present: false, revision: 0 };
const noActivity = { hours: [], succeeded: [], failed: [], other: [] };

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Jobs />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the job list", () => {
  it("draws a job as its operation, its host, its state and where each of them leads", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [job({})], count: 1 },
      "/api/v1/settings/layout": layout,
      "/api/v1/fleet/activity": noActivity,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
    const row = screen.getByTestId("job-j1");
    expect(within(row).getByText("unit.restart").closest("a")).toHaveAttribute("href", "/next/jobs/j1");
    expect(within(row).getByRole("link", { name: "agent-arch" })).toHaveAttribute("href", "/next/hosts/h1");
    expect(within(row).getByText("succeeded")).toBeInTheDocument();
  });

  it("says what nobody reported is unknown, and never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": {
        items: [job({ id: "j2", state: "running", result_status: undefined, finished_at: undefined, approved_by: undefined })],
        count: 1,
      },
      "/api/v1/settings/layout": layout,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j2")).toBeInTheDocument());
    const row = screen.getByTestId("job-j2");
    // A job still running has no result and no finishing time: three
    // dashes, and not a single nought anywhere on the row.
    expect(row.querySelectorAll(".fl-faint")).toHaveLength(3);
    expect(within(row).queryByText("0")).toBeNull();
  });

  it("counts the states of what the server returned", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": {
        items: [job({}), job({ id: "j3", state: "awaiting_approval", requires_approval: true })],
        count: 2,
      },
      "/api/v1/settings/layout": layout,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j3")).toBeInTheDocument());
    const band = screen.getByTestId("job-states");
    expect(band).toHaveTextContent("Awaiting approval");
    expect(band).toHaveTextContent("Succeeded");
    const card = band.closest(".fl-card") as HTMLElement;
    expect(card.querySelector(".fl-card-note")).toHaveTextContent("among the 2 listed");
  });

  it("narrows on the server, not in the browser", async () => {
    Object.assign(answers, { "/api/v1/jobs": { items: [job({})], count: 1 }, "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("state"), { target: { value: "failed" } });
    await waitFor(() => expect(asked.some((one) => one.includes("state=failed"))).toBe(true));
    // What is drawn afterwards is the server's answer to the new question;
    // nothing was sieved out of the page already in hand.
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
  });

  it("asks the server for the typed host name as well", async () => {
    Object.assign(answers, { "/api/v1/jobs": { items: [], count: 0 }, "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByTestId("hostname")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("hostname"), { target: { value: "agent-deb" } });
    await waitFor(() => expect(asked.some((one) => one.includes("hostname=agent-deb"))).toBe(true));
  });

  it("says an empty list is empty rather than drawing a head over nothing", async () => {
    Object.assign(answers, { "/api/v1/jobs": { items: [], count: 0 }, "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByText("No job matches this.")).toBeInTheDocument());
  });
});

describe("deciding on a job", () => {
  const waiting = (over: Record<string, unknown> = {}) => job({
    id: "j9", state: "awaiting_approval", requires_approval: true,
    result_status: undefined, finished_at: undefined, ...over,
  });

  it("approves against the hash of the payload it put on screen, and sends the reason", async () => {
    Object.assign(answers, { "/api/v1/jobs": { items: [waiting()], count: 1 }, "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByTestId("approve-j9")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve-j9"));
    // The payload is read before it is consented to, so the dialog shows it.
    expect(screen.getByTestId("payload")).toHaveTextContent("sshd.service");
    expect(posted).toHaveLength(0);
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ordered in ticket 4121" } });
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j9/approve");
    expect(posted[0].body).toEqual({ payload_hash: "abc123def456789", reason: "ordered in ticket 4121" });
  });

  it("will not approve a destructive operation until a reason is typed", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [waiting({ action_type: "disk.wipe" })], count: 1 },
      "/api/v1/settings/layout": layout,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("approve-j9")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve-j9"));
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "short" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the disk is being returned" } });
    expect(screen.getByTestId("confirm")).toBeEnabled();
  });

  it("asks before it cancels, and records the reason it was given", async () => {
    Object.assign(answers, { "/api/v1/jobs": { items: [waiting()], count: 1 }, "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByTestId("cancel-j9")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("cancel-j9"));
    // One click on a destructive control changes nothing: it puts the
    // question on screen and waits for the reason the trail keeps.
    expect(posted).toHaveLength(0);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "wrong host, ordered again" } });
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j9/cancel");
    expect(posted[0].body).toEqual({ reason: "wrong host, ordered again" });
  });

  it("decides a ticked set job by job, so the trail holds one record for each", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [waiting(), waiting({ id: "j10", hostname: "agent-deb" })], count: 2 },
      "/api/v1/settings/layout": layout,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-all")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-all"));
    fireEvent.click(screen.getByTestId("approve-ticked"));
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the change window is open" } });
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(posted).toHaveLength(2));
    expect(posted.map((one) => one.path)).toEqual(["/api/v1/jobs/j9/approve", "/api/v1/jobs/j10/approve"]);
  });

  it("offers the order again only where the job is over and did not do its work", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [job({ id: "j11", state: "failed", result_status: "failure" })], count: 1 },
      "/api/v1/settings/layout": layout,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j11")).toBeInTheDocument());
    const again = within(screen.getByTestId("job-j11")).getByRole("link", { name: "Order again" });
    expect(again.getAttribute("href")).toContain("action=unit.restart");
    expect(again.getAttribute("href")).toContain("host_id=h1");
  });
});

describe("the attempts of a job, read on the list", () => {
  const attempt = (over: Record<string, unknown> = {}) => ({
    id: "a1", attempt_number: 1, status: "failed", exit_code: 1, replayed: false,
    message: "the unit would not start", stdout: "", stderr: "Job for nginx.service failed.",
    ...over,
  });

  function listing(over: Record<string, unknown> = {}) {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [job({ state: "failed", result_status: undefined })], count: 1 },
      "/api/v1/settings/layout": layout,
      "/api/v1/fleet/activity": noActivity,
      ...over,
    });
  }

  it("reads the attempts of the row that was opened, and says what the host came back with", async () => {
    listing({ "/api/v1/jobs/j1/attempts": { items: [attempt()], count: 1 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
    // Nothing is read until somebody asks for it.
    expect(asked.some((one) => one.includes("/attempts"))).toBe(false);

    fireEvent.click(screen.getByTestId("attempts-j1"));
    await waitFor(() => expect(asked).toContain("/api/v1/jobs/j1/attempts"));
    await waitFor(() => expect(screen.getByTestId("attempt-stderr")).toBeInTheDocument());
    expect(screen.getByTestId("attempt-stderr")).toHaveTextContent("Job for nginx.service failed.");
    expect(screen.getByText("the unit would not start")).toBeInTheDocument();
    expect(screen.getByText("attempt 1")).toBeInTheDocument();
    // And the list is still there: the attempts are read without leaving it.
    expect(screen.getByTestId("job-j1")).toBeInTheDocument();
    // The whole of it is one link away.
    expect(screen.getByRole("link", { name: /Open the job/ })).toHaveAttribute("href", "/next/jobs/j1");
  });

  it("closes again, and reads nothing it was not asked to", async () => {
    listing({ "/api/v1/jobs/j1/attempts": { items: [attempt()], count: 1 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("attempts-j1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("attempts-j1"));
    await waitFor(() => expect(screen.getByTestId("attempt-stderr")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("hide-attempts"));
    await waitFor(() => expect(screen.queryByTestId("attempt-stderr")).not.toBeInTheDocument());
  });

  it("says a job nobody has attempted has no attempts, rather than drawing an empty card", async () => {
    listing({ "/api/v1/jobs/j1/attempts": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("attempts-j1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("attempts-j1"));
    await waitFor(() => expect(screen.getByText("No execution attempts.")).toBeInTheDocument());
  });

  it("shows the refusal of the read instead of an empty card that looks like a job that did nothing", async () => {
    listing({ "/api/v1/jobs/j1/attempts": new ApiError(403, "forbidden", "you may not read this job's output") });
    draw();
    await waitFor(() => expect(screen.getByTestId("attempts-j1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("attempts-j1"));
    await waitFor(() => expect(screen.getByText(/you may not read this job's output/)).toBeInTheDocument());
    expect(screen.queryByText("No execution attempts.")).not.toBeInTheDocument();
  });

  it("keeps an exit code nobody reported an em dash, never a clean nought", async () => {
    listing({
      "/api/v1/jobs/j1/attempts": {
        items: [attempt({ exit_code: undefined, status: undefined, stderr: "" })], count: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("attempts-j1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("attempts-j1"));
    const code = await screen.findByText("Exit code");
    expect(code.closest(".fl-fact")).toHaveTextContent("—");
    expect(code.closest(".fl-fact")).not.toHaveTextContent("0");
  });
});

describe("the words and colours of a job", () => {
  it("keeps what waits for a person apart from what failed and from what was stopped", () => {
    expect(jobTone("awaiting_approval")).toBe("warn");
    expect(jobTone("failed")).toBe("error");
    expect(jobTone("timed_out")).toBe("error");
    expect(jobTone("canceled")).toBe("unknown");
    expect(jobTone("rejected")).toBe("unknown");
    expect(jobTone("succeeded")).toBe("ok");
    expect(jobTone("running")).toBe("info");
  });

  it("holds a reason to the length the control plane records", () => {
    expect(reasonAccepted("short")).toBe(false);
    expect(reasonAccepted("        ")).toBe(false);
    expect(reasonAccepted("long enough")).toBe(true);
  });

  it("reads a payload that arrived as text as well as one that arrived as an object", () => {
    expect(prettyJSON({ a: 1 })).toContain("\"a\": 1");
    expect(prettyJSON("{\"a\":1}")).toContain("\"a\": 1");
    // What is not JSON is shown as it came rather than swallowed.
    expect(prettyJSON("not json")).toBe("not json");
    expect(prettyJSON(null)).toBe("");
  });

  it("writes the order again with the operation, the payload and the one host", () => {
    const address = orderAgainAddress({
      action_type: "unit.restart", payload: { unit: { name: "sshd" } }, host_id: "h1", hostname: "agent-arch",
    });
    expect(address.startsWith("/bulk?")).toBe(true);
    const written = new URLSearchParams(address.slice("/bulk?".length));
    expect(written.get("action")).toBe("unit.restart");
    expect(written.get("host_id")).toBe("h1");
    expect(written.get("name")).toBe("unit.restart again on agent-arch");
    expect(written.get("payload")).toContain("sshd");
  });
});
