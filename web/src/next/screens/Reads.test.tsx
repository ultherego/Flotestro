import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import { Reads, jobTone, readsPrefill, refusalMessage } from "./Reads";
import { parsePayload, payloadHint } from "../../pages/Reads";
import { ToastProvider } from "../../components/Toast";

/**
 * A read is a diagnostic ordered on several hosts at once, so the two
 * things worth holding are what the operator is told when it is refused
 * and what the screen does with a host that never took part. A payload is
 * an object grouped by name; text that parses but is not an object - a
 * list, a number - used to be reported as "not valid JSON", which is the
 * one thing it is not.
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
        // The longest key the path begins with answers it. A key of
        // "/api/v1/reads" would otherwise answer "/api/v1/reads/f1" and
        // hand the detail screen the list document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "new" });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const NO_LAYOUT = { widgets: [], present: false, revision: 0 };

const read = (over: Record<string, unknown>) => ({
  id: "f1", action: "journal.read", payload: { journal: { lines: 100 } },
  created_by: "tszymanski", created_at: "2026-10-16T08:00:00Z", host_count: 2,
  counts: { queued: 0, running: 0, succeeded: 2, failed: 0 },
  ...over,
});

function draw(path = "/next/reads") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(
    <Routes>
      <Route path="/next/reads" element={<Reads />} />
      <Route path="/next/reads/:id" element={<Reads />} />
    </Routes>,
    { wrapper },
  );
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the payload field of a fan-out read", () => {
  const t = (text: string) => text;

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
});

describe("what the operator is told when a read is refused", () => {
  const t = (text: string) => text;

  it("says a busy panel is a wait, not a wrong order", () => {
    const said = refusalMessage(new ApiError(429, "fanout_busy", "three already running"), t);
    expect(said).toContain("try again in a moment");
    expect(said).toContain("three already running");
  });

  it("says a selector that names too many hosts has to be narrowed", () => {
    expect(refusalMessage(new ApiError(422, "fanout_too_broad", "48 hosts"), t)).toContain("narrow it");
  });
});

describe("the state of one host of a fan-out", () => {
  it("keeps a host that took no part apart from one that failed", () => {
    expect(jobTone("succeeded")).toBe("ok");
    expect(jobTone("failed")).toBe("error");
    // A skip is not a failure: the host broke nothing, it simply took no
    // part, and the read says nothing at all about that machine.
    expect(jobTone("skipped")).toBe("unknown");
    expect(jobTone("ineligible")).toBe("unknown");
    expect(jobTone("running")).toBe("warn");
  });

  it("carries a read back into the form it was ordered from", () => {
    const address = readsPrefill("journal.read", { journal: { lines: 10 } });
    expect(address.startsWith("/next/reads?action=journal.read")).toBe(true);
    expect(decodeURIComponent(address)).toContain('"lines": 10');
  });
});

describe("the list of reads", () => {
  it("draws a read as its operation, its hosts and how far it has got", async () => {
    Object.assign(answers, {
      "/api/v1/reads": { items: [read({ counts: { queued: 1, running: 0, succeeded: 2, failed: 1 } })] },
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("read-f1")).toBeInTheDocument());
    const row = screen.getByTestId("read-f1");
    expect(within(row).getByRole("link", { name: "journal.read" })).toHaveAttribute("href", "/next/reads/f1");
    expect(row).toHaveTextContent("2 succeeded");
    expect(row).toHaveTextContent("1 failed");
    expect(row).toHaveTextContent("1 queued");
  });

  it("says an empty list is empty rather than drawing a head over nothing", async () => {
    Object.assign(answers, { "/api/v1/reads": { items: [] }, "/api/v1/settings/layout": NO_LAYOUT });
    draw();
    await waitFor(() => expect(screen.getAllByText("No reads yet.").length).toBeGreaterThan(0));
  });

  it("narrows the hosts of the order form on the server", async () => {
    Object.assign(answers, {
      "/api/v1/reads": { items: [] },
      "/api/v1/settings/layout": NO_LAYOUT,
      "/api/v1/actions": { items: [{ action: "journal.read", fanout_limit: 20, mutating: false }] },
      "/api/v1/hosts": { items: [{ id: "h1", hostname: "web-1", connection_state: "online" }] },
      "/api/v1/fleet/activity": { by_site: [], by_environment: [], by_os_family: [], by_connection_state: [] },
    });
    draw();
    fireEvent.click(await screen.findByTestId("new-read"));
    fireEvent.click(await screen.findByRole("button", { name: "hosts by name" }));
    await waitFor(() => expect(screen.getByTestId("read-host-search")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("read-host-search"), { target: { value: "web" } });
    // The box sends the question to the database; filtering the page
    // already loaded would answer a different one and look the same.
    await waitFor(() => expect(asked.some((one) => one.includes("q=web"))).toBe(true));
  });

  it("will not order a read whose payload is not an object", async () => {
    Object.assign(answers, {
      "/api/v1/reads": { items: [] },
      "/api/v1/settings/layout": NO_LAYOUT,
      "/api/v1/actions": { items: [{ action: "journal.read", fanout_limit: 20, mutating: false }] },
      "/api/v1/fleet/activity": { by_site: [], by_environment: [], by_os_family: [], by_connection_state: [] },
    });
    draw();
    fireEvent.click(await screen.findByTestId("new-read"));
    const payload = await screen.findByTestId("read-payload");
    fireEvent.change(payload, { target: { value: "[1, 2]" } });
    expect(screen.getByTestId("order-read")).toBeDisabled();
    expect(screen.getByText(/grouped by name/)).toBeInTheDocument();
  });
});

describe("one fan-out", () => {
  const view = (over: Record<string, unknown>) => read({
    kind: "timeline",
    hosts: [
      {
        job_id: "j1", host_id: "h1", hostname: "web-1", state: "succeeded",
        finished_at: "2026-10-16T08:01:00Z", lines: ["boot"],
      },
    ],
    timeline: [{ host_id: "h1", hostname: "web-1", at: "2026-10-16T08:01:00Z", line: "kernel: hello" }],
    counts: { queued: 0, running: 0, succeeded: 1, failed: 0 },
    ...over,
  });

  it("merges the lines of the hosts that answered into one sequence", async () => {
    Object.assign(answers, {
      "/api/v1/reads/f1": view({}),
      "/api/v1/whoami": { subject: "tszymanski", permissions: [] },
    });
    draw("/next/reads/f1");
    await waitFor(() => expect(screen.getByTestId("read-timeline")).toBeInTheDocument());
    const timeline = screen.getByTestId("read-timeline");
    expect(timeline).toHaveTextContent("web-1");
    expect(timeline).toHaveTextContent("kernel: hello");
  });

  it("lists a host the read never reached, and says it took no part", async () => {
    Object.assign(answers, {
      "/api/v1/reads/f1": view({
        skipped: [{ host_id: "h2", hostname: "db-1", reason: "host_offline", message: "last seen two days ago" }],
      }),
      "/api/v1/whoami": { subject: "tszymanski", permissions: [] },
    });
    draw("/next/reads/f1");
    await waitFor(() => expect(screen.getByTestId("fanout-db-1")).toBeInTheDocument());
    const row = screen.getByTestId("fanout-db-1");
    // Leaving it out would make the read look as though it covered the
    // fleet it was aimed at.
    expect(within(row).getByText("skipped")).toBeInTheDocument();
    expect(within(row).getByText("host_offline")).toBeInTheDocument();
  });

  it("offers to withdraw the open hosts only to somebody who may cancel a job", async () => {
    Object.assign(answers, {
      "/api/v1/reads/f1": view({
        counts: { queued: 1, running: 0, succeeded: 1, failed: 0 },
        hosts: [
          { job_id: "j1", host_id: "h1", hostname: "web-1", state: "succeeded", lines: [] },
          { job_id: "j2", host_id: "h2", hostname: "web-2", state: "queued" },
        ],
      }),
      "/api/v1/whoami": { subject: "tszymanski", permissions: ["job.cancel"] },
    });
    draw("/next/reads/f1");
    fireEvent.click(await screen.findByTestId("withdraw"));
    // The reason travels with every job into the trail, so there is no
    // withdrawing without one.
    expect(screen.getByTestId("withdraw-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("withdraw-reason"), { target: { value: "the leak is found" } });
    fireEvent.click(screen.getByTestId("withdraw-confirm"));
    await waitFor(() => expect(posted.some((one) => one.path === "/api/v1/jobs/j2/cancel")).toBe(true));
    // Only the host still to answer is withdrawn.
    expect(posted.some((one) => one.path === "/api/v1/jobs/j1/cancel")).toBe(false);
  });

  it("draws a structured read host by host rather than as one timeline", async () => {
    Object.assign(answers, {
      "/api/v1/reads/f1": view({
        action: "dns.resolve.test",
        kind: "structured",
        timeline: undefined,
        hosts: [{
          job_id: "j1", host_id: "h1", hostname: "web-1", state: "succeeded",
          detail: { queries: { queries: [{ name: "example.com", addresses: ["93.184.216.34"], took_millis: 12 }] } },
        }],
      }),
      "/api/v1/whoami": { subject: "tszymanski", permissions: [] },
    });
    draw("/next/reads/f1");
    await waitFor(() => expect(screen.getByTestId("dns-queries")).toBeInTheDocument());
    expect(within(screen.getByTestId("dns-queries")).getByText("example.com")).toBeInTheDocument();
    expect(within(screen.getByTestId("dns-queries")).getByText("93.184.216.34")).toBeInTheDocument();
  });
});
