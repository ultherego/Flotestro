import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../components/Toast";
import {
  Campaign, canSkipTarget, cancelOutcomeLine, compensationOffer, eventDescription,
  secretReferences, targetTone, timelineCSV,
} from "./Campaign";

/**
 * One rollout across many hosts. What is held here is what a decision
 * rests on: the counts come from the server's own report and a count that
 * never arrived is a dash, a control never fires on one click, the consent
 * carries the fingerprint of what was on screen, and a refusal is shown in
 * the server's words.
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
        // The longest key the path begins with wins. "/api/v1/campaigns/c1"
        // also begins "/api/v1/campaigns/c1/report": a short key answering
        // a longer path would hand the screen the wrong document, and a
        // campaign record read as a report counts nothing.
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
          ? Promise.reject(new actual.ApiError(409, "stale_plan", refusal))
          : Promise.resolve({ id: "c2" });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

// The streams belong to a running control plane; everything asserted here
// comes from the API answers.
vi.mock("../../lib/stream", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/stream")>();
  return { ...actual, useProgress: () => new Map(), useProgressStream: () => undefined };
});

const campaign = (over: Record<string, unknown>) => ({
  id: "c1", name: "patch the lab", action_type: "packages.upgrade", state: "running",
  payload: { packages: { mode: "upgrade" } },
  canary_size: 1, wave_size: 5, max_concurrent: 2, failure_threshold_percent: 10,
  failure_threshold_absolute: 2, reboot_policy: "never", requires_approval: true,
  offline_policy: "wait", manual_gate: false, connectivity_lost_absolute: 0,
  approval_fingerprint: "fingerprint0123456789", created_by: "tszymanski",
  created_at: "2026-10-16T08:00:00Z",
  ...over,
});

const report = (totals: Record<string, number>, over: Record<string, unknown> = {}) => ({
  state: "running",
  totals,
  waves: [{ wave: 0, is_canary: true, completed: true, totals: { succeeded: 1 } }],
  failures: [],
  ...over,
});

const target = (over: Record<string, unknown>) => ({
  campaign_id: "c1", host_id: "h1", hostname: "agent-arch", wave: 0, state: "succeeded",
  ...over,
});

const actions = {
  items: [{
    action: "packages.upgrade", mutating: true, campaign_mode: "waves", campaign_ready: true,
    risk: "high", cancel_mode: "checkpoint_only", retry_class: "automatic", rollback: "none",
    verification: "plan_recheck",
  }],
  count: 1,
};

/** Everything the screen asks for, answered so one test may replace a part. */
function world(over: Record<string, unknown> = {}) {
  return {
    "/api/v1/actions": actions,
    "/api/v1/errors": { items: [] },
    "/api/v1/campaigns/c1": campaign({}),
    "/api/v1/campaigns/c1/report": report({ succeeded: 3, failed: 1, pending: 2 }),
    "/api/v1/campaigns/c1/approvals": { items: [], count: 0 },
    "/api/v1/campaigns/c1/timeline": { items: [], count: 0 },
    "/api/v1/campaigns/c1/plans": { items: [] },
    "/api/v1/campaigns/c1/targets": { items: [target({})], count: 1, total: 6 },
    "/api/v1/campaigns/c1/steps": { items: [], count: 0, step_order: [] },
    ...over,
  };
}

/**
 * One campaign is read in five sub-tabs since 17.10 - how far it got, the
 * hosts, the order, the approval and the trail - so a test asks for the
 * one it is about by the address a link to it would carry.
 */
function draw(tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[tab ? `/campaigns/c1?tab=${tab}` : "/campaigns/c1"]}>
        <ToastProvider>
          <Routes><Route path="/campaigns/:id" element={children} /></Routes>
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Campaign />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  refusal = null;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("one campaign", () => {
  it("counts the hosts from the server's report, not from the rows it happens to hold", async () => {
    Object.assign(answers, world());
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-done")).toBeInTheDocument());
    // Three succeeded of six targets, although one row is loaded.
    expect(screen.getByTestId("kpi-done")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-failed")).toHaveTextContent("1");
    expect(screen.getByTestId("target-states")).toHaveTextContent("Failed");
    expect(screen.getByRole("heading", { name: /patch the lab/ })).toBeInTheDocument();
  });

  it("says a count the report never gave is unknown, and never a nought", async () => {
    Object.assign(answers, world({ "/api/v1/campaigns/c1/report": null }));
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-done")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-done")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-failed")).toHaveTextContent("—");
    // The band says the states were not counted rather than drawing a
    // campaign in which nothing has happened.
    expect(screen.getByTestId("target-states")).toHaveTextContent("not counted");
  });

  it("asks before it approves, and binds the consent to the fingerprint on screen", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1": campaign({ state: "awaiting_approval" }),
      "/api/v1/campaigns/c1/report": report({ pending: 6 }),
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("approve")).toBeInTheDocument());
    expect(posted).toHaveLength(0);
    fireEvent.click(screen.getByTestId("approve"));
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "change window CHG-1" } });
    fireEvent.change(screen.getByTestId("ticket"), { target: { value: "CHG-1234" } });
    fireEvent.click(screen.getByTestId("confirm-approve"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/campaigns/c1/approve");
    expect(posted[0].body).toEqual({
      approval_fingerprint: "fingerprint0123456789",
      reason: "change window CHG-1",
      change_ticket: "CHG-1234",
    });
  });

  it("refuses the consent while a host carries a plan the panel cannot read", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1": campaign({ state: "awaiting_approval" }),
      "/api/v1/campaigns/c1/plans": {
        items: [{
          plan_hash: "h1", count: 1, hosts: ["agent-fed"], expires_at: "2099-01-01T00:00:00Z", plan: {},
        }],
      },
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("approve")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve"));
    await waitFor(() => expect(screen.getByTestId("confirm-approve")).toBeDisabled());
    expect(screen.getByText(/Approval is blocked/)).toBeInTheDocument();
  });

  it("records a reason with every stop, and stops nothing until the dialog is answered", async () => {
    Object.assign(answers, world());
    draw();
    await waitFor(() => expect(screen.getByTestId("cancel")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("cancel"));
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the release was pulled" } });
    expect(posted).toHaveLength(0);
    fireEvent.click(screen.getByTestId("confirm-stop"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/campaigns/c1/cancel");
    expect(posted[0].body).toEqual({ reason: "the release was pulled" });
  });

  it("shows the server's refusal of a control in its own words", async () => {
    refusal = "the host no longer computes this plan";
    Object.assign(answers, world({ "/api/v1/campaigns/c1": campaign({ state: "awaiting_approval" }) }));
    draw();
    await waitFor(() => expect(screen.getByTestId("approve")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("approve"));
    fireEvent.click(screen.getByTestId("confirm-approve"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("the host no longer computes this plan"));
  });

  it("lets an offline canary go by name, with a reason the trail keeps", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1": campaign({ state: "canary" }),
      "/api/v1/campaigns/c1/targets": {
        items: [target({ state: "queued_offline" })], count: 1, total: 1,
      },
    }));
    draw("hosts");
    await waitFor(() => expect(screen.getByTestId("skip-h1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("skip-h1"));
    expect(screen.getByTestId("confirm-skip")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the machine is in a crate" } });
    fireEvent.click(screen.getByTestId("confirm-skip"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/campaigns/c1/targets/h1/skip");
    expect(posted[0].body).toEqual({ reason: "the machine is in a crate" });
  });

  it("names what waits on a person and drops what waits on nobody", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1": campaign({ state: "manual_gate" }),
      "/api/v1/campaigns/c1/report": report({ succeeded: 1, queued_offline: 2, pending: 3 }),
    }));
    draw();
    await waitFor(() => expect(screen.getByText(/the waves wait for a decision/)).toBeInTheDocument());
    expect(screen.getByText("Hosts waiting for their connection")).toBeInTheDocument();
    // Nothing failed, so "Hosts that failed" is not a row at all.
    expect(screen.queryByText("Hosts that failed")).toBeNull();
  });

  it("narrows the targets on the server", async () => {
    Object.assign(answers, world());
    draw("hosts");
    await waitFor(() => expect(screen.getByTestId("target-state")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("target-state"), { target: { value: "failed" } });
    await waitFor(() => expect(asked.some((one) => one.includes("targets?") && one.includes("state=failed"))).toBe(true));
  });

  it("draws a square per host and tallies what they came back with", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1/targets": {
        items: [target({}), target({ host_id: "h2", hostname: "agent-fed", state: "failed" })],
        count: 2, total: 6,
      },
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("target-squares")).toBeInTheDocument());
    const squares = screen.getByTestId("target-squares");
    expect(squares.querySelectorAll(".fl-square")).toHaveLength(2);
    expect(within(squares).getByTitle("agent-fed · failed")).toBeInTheDocument();
  });

  it("offers the retry only once the campaign has settled with hosts to run again", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1": campaign({ state: "completed_with_issues" }),
      "/api/v1/campaigns/c1/report": report({ succeeded: 4, failed: 2 }),
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("retry")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("retry"));
    expect(screen.getByTestId("confirm-retry")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "the mirror is back" } });
    fireEvent.click(screen.getByTestId("confirm-retry"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/campaigns/c1/retry");
    expect(posted[0].body).toEqual({ reason: "the mirror is back", include_unknown: false });
  });

  it("reads the order the approval binds, payload and all", async () => {
    Object.assign(answers, world());
    draw("order");
    await waitFor(() => expect(screen.getByTestId("order-payload")).toBeInTheDocument());
    expect(screen.getByTestId("order-payload")).toHaveTextContent("upgrade");
    expect(screen.getByText("Canary / wave").closest(".fl-fact")).toHaveTextContent("1 / 5");
    // The contract of the operation is read from the catalogue, never
    // guessed from the name of the operation.
    expect(screen.getByText(/rollback: none/)).toBeInTheDocument();
  });

  it("says a refusal of the campaign itself rather than drawing an empty screen", async () => {
    Object.assign(answers, { "/api/v1/campaigns/c1": null });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("no such thing"));
  });

  it("puts the trail in a feed, newest as the server ordered it, filtered on a kind", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1/timeline": {
        items: [
          { id: 2, aggregate_type: "campaign", event_type: "campaign.paused", occurred_at: "2026-10-16T09:00:00Z", payload: { pause_reason: "threshold" } },
          { id: 1, aggregate_type: "campaign_target", event_type: "target.succeeded", occurred_at: "2026-10-16T08:30:00Z", payload: { host_id: "h1", wave: 0, job_id: "j9" } },
        ],
        count: 2,
      },
    }));
    draw("timeline");
    // The kinds also fill the filter, so the feed itself is what is read.
    const feed = () => document.querySelector(".fl-feed") as HTMLElement;
    await waitFor(() => expect(feed()).not.toBeNull());
    expect(within(feed()).getByText("campaign.paused")).toBeInTheDocument();
    expect(within(feed()).getByRole("link", { name: /target\.succeeded/ }))
      .toHaveAttribute("href", "/jobs/j9");
    fireEvent.change(screen.getByTestId("event-kind"), { target: { value: "campaign.paused" } });
    await waitFor(() => expect(within(feed()).queryByText("target.succeeded")).toBeNull());
  });

  /* The drawing groups the states into three bands, so a wave's own row
     is the only place that says whether the wave is closed and what it
     counted state by state. A wave still letting hosts in and a wave that
     has run every host look the same from their counts alone. */
  it("carries on each wave's row whether it is closed, whether it is the canary, and its counts", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1/report": report({ succeeded: 3, failed: 1, pending: 2 }, {
        waves: [
          { wave: 0, is_canary: true, completed: true, totals: { succeeded: 1 } },
          { wave: 1, is_canary: false, completed: false, totals: { succeeded: 2, failed: 1, pending: 2 } },
        ],
      }),
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("waves")).toBeInTheDocument());

    const canary = screen.getByTestId("wave-0");
    expect(within(canary).getAllByText("yes")).toHaveLength(2);
    expect(canary).toHaveTextContent("succeeded: 1");

    const second = screen.getByTestId("wave-1");
    // The canary column and the closed column are read apart: this wave is
    // neither, and a single "no" would not say which.
    expect(within(second).getAllByText("no")).toHaveLength(2);
    expect(second).toHaveTextContent("succeeded: 2");
    expect(second).toHaveTextContent("failed: 1");
    // The grouped drawing folds pending into "Other"; the row names it.
    expect(second).toHaveTextContent("pending: 2");
  });

  it("says a wave the report put no count against was not counted, and never draws it as noughts", async () => {
    Object.assign(answers, world({
      "/api/v1/campaigns/c1/report": report({ pending: 6 }, {
        waves: [{ wave: 0, is_canary: true, completed: false, totals: {} }],
      }),
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("wave-0")).toBeInTheDocument());
    // The summary cell, not the row: the wave is numbered 0 itself.
    const summary = screen.getByTestId("wave-0").querySelectorAll("td")[3];
    expect(summary).toHaveTextContent("not counted");
    expect(summary).not.toHaveTextContent("0");
  });
});

describe("what the screen reads out of a campaign", () => {
  it("keeps a host nobody heard from apart from one that failed and one left out", () => {
    expect(targetTone("succeeded")).toBe("ok");
    expect(targetTone("no_change")).toBe("ok");
    expect(targetTone("failed")).toBe("error");
    expect(targetTone("unknown")).toBe("warn");
    expect(targetTone("skipped")).toBe("unknown");
    expect(targetTone("running")).toBe("info");
  });

  it("offers a compensation only where one can be planned", () => {
    expect(compensationOffer({ state: "running" })).toEqual({ kind: "not_settled" });
    expect(compensationOffer({ state: "completed", rollback: "none", reverseAction: "file.rollback" }))
      .toEqual({ kind: "no_reverse" });
    expect(compensationOffer({ state: "completed", rollback: "exact_restore", reverseAction: "file.rollback", changedHosts: 0 }))
      .toEqual({ kind: "nothing_changed", reverse: "file.rollback" });
    expect(compensationOffer({ state: "completed", rollback: "exact_restore", reverseAction: "file.rollback", changedHosts: 4 }))
      .toEqual({ kind: "host_by_host", reverse: "file.rollback", changed: 4 });
    expect(compensationOffer({ state: "completed", rollback: "exact_restore", reverseAction: "file.rollback", reverseReady: true, changedHosts: 4 }))
      .toEqual({ kind: "campaign", reverse: "file.rollback", changed: 4 });
  });

  it("says what the host answered to a cancel, and that it has not where it has not", () => {
    const t = (text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? ""));
    expect(cancelOutcomeLine({}, t)).toBe("");
    expect(cancelOutcomeLine({ cancel_requested_at: "now" }, t)).toContain("waiting for the host");
    expect(cancelOutcomeLine({ cancel_outcome: "already_done" }, t)).toContain("already finished");
  });

  it("lets a host be skipped only while it waits for its connection in a live campaign", () => {
    expect(canSkipTarget({ state: "queued_offline" }, "canary")).toBe(true);
    expect(canSkipTarget({ state: "queued_offline" }, "completed")).toBe(false);
    expect(canSkipTarget({ state: "running" }, "canary")).toBe(false);
  });

  it("names the secrets an order refers to without ever carrying their value", () => {
    expect(secretReferences({ ssh: { key_secret: { name: "deploy", version: 3 } } })).toEqual(["deploy@3"]);
    expect(secretReferences({ env_secrets: { A: { name: "token" } } })).toEqual(["token"]);
    expect(secretReferences({ nothing: 1 })).toEqual([]);
  });

  it("gives a wave number to an event only where the host has one", () => {
    expect(eventDescription({
      id: 1, aggregate_type: "campaign_target", event_type: "x", occurred_at: "", payload: { wave: 2, message: "ok" },
    })).toBe("wave 2 · ok");
    // A host taking no part carries wave -1; naming one would invent a
    // place in the rollout it never had.
    expect(eventDescription({
      id: 1, aggregate_type: "campaign_target", event_type: "x", occurred_at: "", payload: { wave: -1, message: "ok" },
    })).toBe("ok");
    expect(eventDescription({ id: 1, aggregate_type: "campaign", event_type: "x", occurred_at: "" })).toBe("—");
  });

  it("guards a trail exported as a spreadsheet against a cell that would run", () => {
    const csv = decodeURIComponent(timelineCSV(
      [{ id: 1, aggregate_type: "campaign", event_type: "=cmd()", occurred_at: "2026-10-16T08:00:00Z" }],
      [],
    ));
    expect(csv).toContain(`"'=cmd()"`);
  });
});
