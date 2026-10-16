import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import { Relays, bufferSummary, historyAddress, relayTone, BUFFER_RANGES, type RelayBufferPoint } from "./Relays";
import { ToastProvider } from "../../components/Toast";

/**
 * A relay is read for what it said about itself, which is why the one
 * thing held hardest here is the difference between a spool nobody has
 * reported and an empty one. Everything the window claims about a site -
 * the drops across a restart, the fill without a limit - is computed, so
 * it is checked where it is computed.
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
        // The longest key wins: "/api/v1/relays" would otherwise answer
        // "/api/v1/relays/r1/buffer-history" with the list of relays and
        // hand the screen a document with no points in it at all.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        // An Error standing in the table is a refusal, so a test can ask
        // for the 404 an address naming no relay comes back with.
        const value = answers[key];
        if (value instanceof Error) return Promise.reject(value);
        return Promise.resolve(value);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ sessions_closed: 3 });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const relay = (over: Record<string, unknown>) => ({
  id: "r1", name: "relay-warsaw", site: "warsaw", environment: "prod",
  enrolled_at: "2026-09-01T08:00:00Z", last_seen_at: "2026-10-16T07:59:00Z",
  state: "active", hosts_attested: 4,
  certificate_not_after: "2027-09-01T08:00:00Z", serial: "0a:1b",
  buffer: {
    buffer_bytes: 1024, buffer_max_bytes: 10240, buffered_items: 7,
    buffer_dropped: 0, sessions: 2, relay_version: "0.63.1",
    reported_at: "2026-10-16T07:59:00Z",
  },
  ...over,
});

const point = (over: Partial<RelayBufferPoint>): RelayBufferPoint => ({
  at: "2026-10-16T08:00:00Z",
  bytes_used: 0, bytes_used_max: 0, bytes_limit: 1000,
  item_count: 0, item_count_max: 0,
  dropped_total: 0, dropped_delta: 0,
  active_sessions: 0, disconnected: false, restarted: false, samples: 1,
  ...over,
});

/** Where the panel stands now, so a click can be read as an address. */
function Where() {
  const where = useLocation();
  return <span data-testid="where">{where.pathname}</span>;
}

/**
 * The screen under the two addresses it answers on. The list and the one
 * relay are the same component, so both routes lead to it and the
 * parameter is what decides which the reader gets.
 */
function draw(at = "/relays") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <ToastProvider>
          <Routes>
            <Route path="/relays" element={<Relays />} />
            <Route path="/relays/:id" element={<Relays />} />
          </Routes>
          <Where />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the relays of the sites", () => {
  it("draws a relay as its site, its state and the spool it last reported", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({})], count: 1 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/relays/r1/buffer-history": {
        relay_id: "r1", range: "24h", step_seconds: 60, rollup: false,
        points: [], latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("relay-relay-warsaw")).toBeInTheDocument());
    const row = screen.getByTestId("relay-relay-warsaw");
    expect(row).toHaveTextContent("warsaw");
    expect(within(row).getByText("active")).toHaveClass("fl-ok");
    expect(row).toHaveTextContent("1.0 KiB / 10 KiB");
    expect(row).toHaveTextContent("7 items");
  });

  it("says a spool nobody reported is unknown, and never draws it as empty", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({ id: "r2", name: "relay-krakow", state: "never_seen", buffer: undefined, last_seen_at: undefined, hosts_attested: 0 })], count: 1 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("relay-relay-krakow")).toBeInTheDocument());
    const row = screen.getByTestId("relay-relay-krakow");
    expect(row).toHaveTextContent("— not reported");
    expect(row).toHaveTextContent("— never reported");
    expect(row).not.toHaveTextContent("0 items");
    // And the figure over the fleet is a dash too: no relay has reported a
    // spool, which is not a fleet with nothing waiting in one.
    const waiting = screen.getByTestId("kpi-Items waiting");
    expect(waiting).toHaveAttribute("data-state", "unknown");
    expect(within(waiting).getByText("—")).toBeInTheDocument();
  });

  /**
   * The cards under the list are about one relay. Nothing on the screen
   * said which until the row itself carried the mark, so a reader of a
   * long list had to scroll back to the title of the card to find out
   * what they were looking at.
   */
  it("marks the row the cards below are about, and moves the mark with the choice", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({}), relay({ id: "r2", name: "relay-krakow", site: "krakow" })], count: 2 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/relays/r2": { relay: relay({ id: "r2", name: "relay-krakow", site: "krakow" }), hosts: [] },
      "/api/v1/relays/r1/buffer-history": {
        relay_id: "r1", range: "24h", step_seconds: 60, rollup: false,
        points: [], latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
      "/api/v1/relays/r2/buffer-history": {
        relay_id: "r2", range: "24h", step_seconds: 60, rollup: false,
        points: [], latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("relay-relay-warsaw")).toBeInTheDocument());
    // With no relay in the address the first of the list is the one read.
    expect(screen.getByTestId("relay-relay-warsaw")).toHaveClass("fl-row-marked");
    expect(screen.getByTestId("relay-relay-krakow")).not.toHaveClass("fl-row-marked");

    fireEvent.click(screen.getByTestId("pick-relay-krakow"));
    await waitFor(() => expect(screen.getByTestId("relay-relay-krakow")).toHaveClass("fl-row-marked"));
    expect(screen.getByTestId("relay-relay-warsaw")).not.toHaveClass("fl-row-marked");
  });

  it("narrows by site on the server, with what was typed", async () => {
    Object.assign(answers, { "/api/v1/relays": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("site")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("site"), { target: { value: "warsaw" } });
    await waitFor(() => expect(asked.some((one) => one === "/api/v1/relays?site=warsaw")).toBe(true), { timeout: 3000 });
  });

  it("asks the chosen relay for the chosen window", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({}), relay({ id: "r2", name: "relay-krakow", site: "krakow" })], count: 2 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/relays/r2": {
        relay: relay({ id: "r2", name: "relay-krakow" }),
        hosts: [{
          host_id: "h1", hostname: "agent-arch", site: "krakow", lifecycle_state: "active",
          agent_version: "0.63.1", connected_at: "2026-10-16T07:00:00Z", last_heartbeat_at: "2026-10-16T07:58:00Z",
        }],
      },
      "/api/v1/relays/r1/buffer-history": {
        relay_id: "r1", range: "24h", step_seconds: 60, rollup: false,
        points: [], latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
      "/api/v1/relays/r2/buffer-history": {
        relay_id: "r2", range: "7d", step_seconds: 900, rollup: true,
        points: [point({ bytes_used: 2048, item_count: 3, disconnected: true })],
        latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
    });
    draw();
    // The first of the list is read without being chosen, so the cards
    // under the table are never empty for no reason.
    await waitFor(() => expect(asked.some((one) => one === "/api/v1/relays/r1/buffer-history?range=24h")).toBe(true));
    fireEvent.click(screen.getByTestId("pick-relay-krakow"));
    await waitFor(() => expect(asked.some((one) => one === "/api/v1/relays/r2/buffer-history?range=24h")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    await waitFor(() => expect(asked.some((one) => one === "/api/v1/relays/r2/buffer-history?range=7d")).toBe(true));
    // The hosts behind that relay come from its own document, not from the
    // list the shorter path would have answered with.
    await waitFor(() => expect(screen.getByTestId("attested-agent-arch")).toBeInTheDocument());
    expect(within(screen.getByTestId("attested-agent-arch")).getByRole("link", { name: "agent-arch" }))
      .toHaveAttribute("href", "/hosts/h1");
  });

  it("revokes a relay only with a reason, and sends the reason that was typed", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({})], count: 1 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/whoami": { subject: "tszymanski", kind: "user", roles: [], bindings: [], permissions: ["relay.manage"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("revoke")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("revoke"));
    const confirm = screen.getByTestId("revoke-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("revoke-reason"), { target: { value: "short" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("revoke-reason"), { target: { value: "certificate leaked" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toEqual([
      { path: "/api/v1/relays/r1/revoke", body: { reason: "certificate leaked" } },
    ]));
  });

  it("offers no revocation to a reader who may not manage a relay", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({})], count: 1 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/whoami": { subject: "reader", kind: "user", roles: [], bindings: [], permissions: ["host.read"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("relay-relay-warsaw")).toBeInTheDocument());
    expect(screen.queryByTestId("revoke")).not.toBeInTheDocument();
  });
});

describe("one relay from the address", () => {
  it("opens on the relay the address names, even when the list is narrowed past it", async () => {
    Object.assign(answers, {
      // The list the screen reads is one site's; the relay in the address
      // is not in it, and it is read on its own record all the same.
      "/api/v1/relays": { items: [relay({})], count: 1 },
      "/api/v1/relays/r2": {
        relay: relay({ id: "r2", name: "relay-krakow", site: "krakow", environment: "" }),
        hosts: [{
          host_id: "h9", hostname: "agent-arch", site: "krakow", lifecycle_state: "active",
          agent_version: "0.63.1", connected_at: "2026-10-16T07:00:00Z", last_heartbeat_at: "2026-10-16T07:58:00Z",
        }],
      },
      "/api/v1/relays/r2/buffer-history": {
        relay_id: "r2", range: "24h", step_seconds: 60, rollup: false,
        points: [], latest: null, alerts: [], raw_retention_hours: 48, rollup_retention_days: 30,
      },
    });
    draw("/relays/r2");
    await waitFor(() => expect(screen.getByTestId("attested-agent-arch")).toBeInTheDocument());
    // The card is the relay the address named and not the first of the list.
    expect(screen.getByText("relay-krakow")).toBeInTheDocument();
    expect(asked.some((one) => one === "/api/v1/relays/r2")).toBe(true);
    expect(asked.some((one) => one === "/api/v1/relays/r1")).toBe(false);
  });

  it("says an identifier naming nothing names nothing, and offers the list", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({})], count: 1 },
      "/api/v1/relays/nope": new ApiError(404, "not_found", "no such relay"),
    });
    draw("/relays/nope");
    await waitFor(() => expect(screen.getByText(/No relay with the identifier nope/)).toBeInTheDocument());
    // No card of a relay that is not there, and a way back to the list.
    expect(screen.queryByTestId("relay-relay-warsaw")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All relays" })).toHaveAttribute("href", "/relays");
  });

  it("puts the relay picked from a row in the address, without reloading the panel", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [relay({}), relay({ id: "r2", name: "relay-krakow", site: "krakow" })], count: 2 },
      "/api/v1/relays/r1": { relay: relay({}), hosts: [] },
      "/api/v1/relays/r2": { relay: relay({ id: "r2", name: "relay-krakow", site: "krakow" }), hosts: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-relay-krakow")).toBeInTheDocument());
    expect(screen.getByTestId("where")).toHaveTextContent("/relays");
    fireEvent.click(screen.getByTestId("pick-relay-krakow"));
    // The address is the one thing that changed: the list is still drawn
    // under it, so nothing was reloaded.
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/relays/r2"));
    expect(screen.getByTestId("relay-relay-warsaw")).toBeInTheDocument();
  });
});

describe("the state of a relay", () => {
  it("keeps silence apart from a decision", () => {
    expect(relayTone("active")).toBe("ok");
    // Ten minutes of silence is a site cut off: that is a fault.
    expect(relayTone("silent")).toBe("error");
    // A relay nobody has heard from yet has told us nothing.
    expect(relayTone("never_seen")).toBe("unknown");
    // A revoked relay is not broken; somebody revoked it.
    expect(relayTone("revoked")).toBe("neutral");
  });
});

describe("the window of a spool", () => {
  it("asks one relay for one window", () => {
    expect(historyAddress("r1", "7d")).toBe("/api/v1/relays/r1/buffer-history?range=7d");
    expect([...BUFFER_RANGES]).toEqual(["3h", "24h", "7d", "30d", "90d"]);
  });

  it("sums the drops from the deltas, so a restart neither hides nor negates them", () => {
    const summary = bufferSummary([
      point({ dropped_total: 0, dropped_delta: null }),
      point({ dropped_total: 5, dropped_delta: 5 }),
      // The relay restarted: the counter starts again and the point carries
      // no delta at all.
      point({ dropped_total: 0, dropped_delta: null, restarted: true, instance_id: "second" }),
      point({ dropped_total: 2, dropped_delta: 2, instance_id: "second" }),
    ], 60);
    expect(summary.dropped).toBe(7);
    expect(summary.restarts).toBe(1);
  });

  it("counts the time without an upstream in the step of the window", () => {
    const offline = [point({ disconnected: true }), point({ disconnected: true }), point({})];
    expect(bufferSummary(offline, 60).offlineMinutes).toBe(2);
    // The same three points on a rolled-up window are quarter-hours.
    expect(bufferSummary(offline, 15 * 60).offlineMinutes).toBe(30);
  });

  it("reads the peak fill against the limit and leaves it unknown without one", () => {
    expect(bufferSummary([
      point({ bytes_used: 100, bytes_used_max: 400, bytes_limit: 1000 }),
      point({ bytes_used: 900, bytes_used_max: 950, bytes_limit: 1000 }),
    ], 60).peakPercent).toBe(95);
    // A relay that reported no limit has no share to show. An unknown
    // limit is not a limit of zero, and it is not a quiet spool either.
    expect(bufferSummary([point({ bytes_used: 500, bytes_used_max: 500, bytes_limit: 0 })], 60).peakPercent)
      .toBeUndefined();
  });

  it("says nothing about an empty window", () => {
    expect(bufferSummary([], 60)).toEqual({ dropped: 0, restarts: 0, peakPercent: undefined, offlineMinutes: 0 });
  });
});
