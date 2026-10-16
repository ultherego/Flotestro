import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host, Job } from "../../../lib/types";
import { Jobs, campaignLabel, cancellable } from "./Jobs";

/**
 * The jobs of one machine, and the two decisions that cannot be taken
 * back. An approval carries the hash of the payload that was on screen; a
 * cancel carries a reason the trail keeps, and neither happens on one
 * click. A list nobody has read yet counts to dashes, not to none.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key the path begins with wins: "/api/v1/jobs" also
        // begins "/api/v1/jobs/j1/attempts", and a short key answering a
        // longer path hands the screen somebody else's document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
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

// The progress of what is in flight arrives over a stream this test has no
// business opening; the rows are read from the list either way.
vi.mock("../../../lib/stream", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/stream")>();
  return { ...actual, useProgress: () => new Map() };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
} as unknown as Host;

const job = (over: Record<string, unknown> = {}) => ({
  id: "j1", host_id: "h1", hostname: "agent-arch", action_type: "unit.restart",
  state: "succeeded", payload: { unit: { name: "sshd.service" } }, payload_hash: "abc123def456789",
  requires_approval: false, required_approvals: 1, collected_approvals: 0,
  created_by: "tszymanski", result_status: "succeeded",
  expires_at: "2026-10-16T12:00:00Z", created_at: "2026-10-16T08:00:00Z",
  finished_at: "2026-10-16T08:01:00Z",
  ...over,
}) as unknown as Job;

const layout = { widgets: [], present: false, revision: 0 };
const contracts = { count: 1, items: [{ action: "unit.restart", cancel_mode: "safe" }] };

function draw(permissions = ["job.cancel", "job.approve"]) {
  Object.assign(answers, { "/api/v1/whoami": { permissions } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Jobs host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the jobs module of a host", () => {
  it("asks the server for this host's jobs only, and draws where each leads", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": { count: 1, items: [job()] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
    expect(asked.some((one) => one.includes("host_id=h1"))).toBe(true);
    const row = screen.getByTestId("job-j1");
    expect(within(row).getByText("unit.restart").closest("a")).toHaveAttribute("href", "/next/jobs/j1");
    expect(within(row).getByText("succeeded")).toBeInTheDocument();
  });

  it("narrows on the server, not in the browser", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": { count: 1, items: [job()] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j1")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("state"), { target: { value: "failed" } });
    await waitFor(() => expect(asked.some((one) => one.includes("state=failed"))).toBe(true));
    fireEvent.change(screen.getByTestId("action"), { target: { value: "packages." } });
    // A prefix filtered in the browser would answer over the page that
    // happens to be loaded; it goes to the server as the server names it.
    await waitFor(() => expect(asked.some((one) => one.includes("action_prefix=packages."))).toBe(true));
  });

  it("says what nobody reported is unknown, and never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": {
        count: 1,
        items: [job({ id: "j2", state: "running", result_status: undefined, approved_by: undefined })],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("job-j2")).toBeInTheDocument());
    const row = screen.getByTestId("job-j2");
    // Nobody approved it and the host has sent no result: two dashes, and
    // not a nought anywhere on the row.
    expect(row.querySelectorAll(".fl-faint")).toHaveLength(2);
    expect(within(row).queryByText("0")).toBeNull();
  });

  it("counts nothing before the list is read", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/actions": contracts });
    draw();
    const band = await screen.findByTestId("job-states");
    expect(band).toHaveTextContent("—");
    expect(band.querySelector(".fl-band")).toBeNull();
  });

  it("binds an approval to the hash of the payload that was on screen", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": {
        count: 1,
        items: [job({ id: "j3", state: "awaiting_approval", requires_approval: true, result_status: undefined })],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("approve-j3")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve-j3"));
    // The payload is read before it is consented to, so it is on the
    // dialog and not behind a link.
    expect(screen.getByTestId("payload")).toHaveTextContent("sshd.service");
    expect(screen.getByText(/abc123def456/)).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j3/approve");
    expect(posted[0].body).toMatchObject({ payload_hash: "abc123def456789" });
  });

  it("will not cancel without a reason the trail can keep", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": { count: 1, items: [job({ id: "j4", state: "running", result_status: undefined })] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("cancel-j4")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("cancel-j4"));
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "short" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the restart is looping" } });
    await waitFor(() => expect(screen.getByTestId("confirm")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/jobs/j4/cancel");
    expect(posted[0].body).toEqual({ reason: "the restart is looping" });
  });

  it("offers no decision to somebody who may not take it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": {
        count: 1,
        items: [job({ id: "j5", state: "awaiting_approval", requires_approval: true, result_status: undefined })],
      },
    });
    draw(["host.read"]);
    await waitFor(() => expect(screen.getByTestId("job-j5")).toBeInTheDocument());
    // A button that leads only to a refusal is a fault, not a courtesy.
    expect(screen.queryByTestId("approve-j5")).toBeNull();
    expect(screen.queryByTestId("cancel-j5")).toBeNull();
  });

  it("opens the attempts of a job beside the list, with the way to its journal", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/actions": contracts,
      "/api/v1/jobs": { count: 1, items: [job()] },
      "/api/v1/jobs/j1/attempts": {
        count: 1,
        items: [{
          id: "at1", attempt_number: 1, status: "succeeded", exit_code: 0, replayed: false,
          stdout: "restarted sshd.service",
        }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-j1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-j1"));
    await waitFor(() => expect(screen.getByTestId("stdout-at1")).toBeInTheDocument());
    expect(screen.getByTestId("stdout-at1")).toHaveTextContent("restarted sshd.service");
    expect(screen.getByRole("link", { name: /Read the journal of this job/ }))
      .toHaveAttribute("href", "/next/hosts/h1/logs?job=j1");
  });
});

describe("what the jobs module knows on its own", () => {
  it("names a campaign by what the job's author carries, else by its identifier", () => {
    expect(campaignLabel({ created_by: "campaign:nightly-patch", campaign_id: "c1" })).toBe("nightly-patch");
    expect(campaignLabel({ created_by: "tszymanski", campaign_id: "abcdef0123456789" })).toBe("abcdef01");
    expect(campaignLabel({ created_by: "tszymanski" })).toBe("");
  });

  it("offers a cancel before the host starts, and after only where the operation stops cleanly", () => {
    expect(cancellable(job({ state: "queued" }), undefined)).toBe(true);
    expect(cancellable(job({ state: "awaiting_approval" }), undefined)).toBe(true);
    expect(cancellable(job({ state: "running" }), { cancel_mode: "safe" })).toBe(true);
    expect(cancellable(job({ state: "running" }), { cancel_mode: "checkpoint_only" })).toBe(false);
    expect(cancellable(job({ state: "running" }), undefined)).toBe(false);
    // A job that is over cannot be stopped, whatever its contract says.
    expect(cancellable(job({ state: "succeeded" }), { cancel_mode: "safe" })).toBe(false);
  });
});
