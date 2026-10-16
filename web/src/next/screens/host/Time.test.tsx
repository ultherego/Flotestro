import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Time, timeSourcesOrder, timeZoneOrder } from "./Time";
import { orderReady } from "./Power";

/**
 * A drifted clock looks from the outside like a broken directory, so the
 * module has to name the drift plainly; and a measurement the daemon did
 * not report is not a measurement of nought, because an offset of zero
 * means a clock that agrees.
 */

const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/jobs` must not answer
        // `/api/v1/jobs/job-1/attempts`.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1234abcd", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
} as unknown as Parameters<typeof Time>[0]["host"];

const allowed = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "normal", allowed: true,
  })),
});

function base(payload: unknown) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/inventory/time": {
      host_id: "h1", module: "time", revision: "abcdef123456", source: "agent",
      observed_at: "2026-10-16T08:00:00Z", payload,
    },
    "/api/v1/hosts/h1/actions": allowed("time.config.apply", "time.timezone.set", "time.sync.test"),
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Time host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the clock of a host", () => {
  it("names the drift before anything else on the module", async () => {
    base({ synchronized: true, stratum: 3, offset_seconds: 2.5, sources: [] });
    draw();
    await waitFor(() => expect(screen.getByText(/away from its time source/)).toBeInTheDocument());
    expect(screen.getByTestId("kpi-Offset")).toHaveTextContent("2.500");
  });

  it("says a measurement nobody reported is unknown, never nought", async () => {
    base({ synchronized: null, stratum: null, offset_seconds: null, sources: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Offset")).toBeInTheDocument());
    // An offset of zero is a clock that agrees; a dash is a clock nobody
    // has measured, and the two must not read the same.
    expect(screen.getByTestId("kpi-Offset")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Stratum")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Synchronized")).toHaveTextContent("—");
  });

  it("counts the sources by what the daemon makes of them", async () => {
    base({
      sources: [
        { address: "10.0.0.1", state: "selected" },
        { address: "10.0.0.2", state: "candidate" },
        { address: "10.0.0.3", state: "false ticker" },
        { address: "10.0.0.4", state: "unreachable" },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("time-sources")).toHaveTextContent("10.0.0.3"));
    const band = screen.getByTestId("time-states");
    expect(within(band).getByText("selected")).toBeInTheDocument();
    expect(within(band).getByText("rejected")).toBeInTheDocument();
  });

  it("asks the host to test the servers typed in, and not the panel", async () => {
    base({ sources: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("time-test")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("time-servers"), { target: { value: "ntp1.example.com, ntp2.example.com" } });
    fireEvent.click(screen.getByTestId("time-test"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "time.sync.test",
      payload: { time: { probe: ["ntp1.example.com", "ntp2.example.com"] } },
    });
  });

  it("sets the sources only after the reason and the hostname", async () => {
    base({ sources: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("time-apply")).toBeInTheDocument());
    // An empty list is not a way of clearing the sources, so the registry
    // refuses the order until a server is named.
    expect(screen.getByTestId("time-apply")).toBeDisabled();
    fireEvent.change(screen.getByTestId("time-servers"), { target: { value: "ntp1.example.com" } });
    fireEvent.click(screen.getByTestId("time-apply"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "moving to the site NTP" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "time.config.apply",
      reason: "moving to the site NTP",
      payload: { time: { servers: ["ntp1.example.com"] } },
    });
  });

  it("will not write a daemon whose own file reads no directory", async () => {
    base({
      sources: [],
      write_reason: "chrony.conf includes no directory the panel may write in",
      can_add_source_dir: false,
    });
    draw();
    await waitFor(() => expect(screen.getByText(/includes no directory/)).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("time-servers"), { target: { value: "ntp1.example.com" } });
    // The host's own refusal comes first, whatever the servers say.
    expect(screen.getByTestId("time-apply")).toBeDisabled();
  });

  it("asks separately before it appends a line to somebody else's file", async () => {
    base({
      sources: [],
      write_reason: "chrony.conf includes no directory the panel may write in",
      can_add_source_dir: true,
      config_path: "/etc/chrony/chrony.conf",
    });
    draw();
    await waitFor(() => expect(screen.getByText(/append one line to/)).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("time-servers"), { target: { value: "ntp1.example.com" } });
    expect(screen.getByTestId("time-apply")).toBeDisabled();
    fireEvent.click(screen.getByText(/append one line to/));
    expect(screen.getByTestId("time-apply")).toBeEnabled();
  });

  it("sets a timezone the tz database knows, and refuses one it does not", async () => {
    base({ sources: [], timezone: "UTC" });
    draw();
    await waitFor(() => expect(screen.getByTestId("zone-set")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("time-zone"), { target: { value: "Europe/Warsaw" } });
    fireEvent.click(screen.getByTestId("zone-set"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "the machine moved to Poland" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "time.timezone.set",
      payload: { time: { timezone: "Europe/Warsaw" } },
    });
  });

  it("says a host that has never reported its clock has not reported it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not reported its clock/)).toBeInTheDocument());
  });
});

describe("the orders the time module composes", () => {
  it("sends the servers one per line, as the registry reads them", () => {
    const order = timeSourcesOrder(["ntp1.example.com", "ntp2.example.com"], false, false);
    expect(orderReady(order)).toBe(true);
    expect(order.payload).toMatchObject({ time: { servers: ["ntp1.example.com", "ntp2.example.com"] } });
  });

  it("refuses an empty list: a host without a time source drifts and says nothing", () => {
    expect(orderReady(timeSourcesOrder([], false, false))).toBe(false);
  });

  it("refuses a zone the tz database does not name that way", () => {
    expect(orderReady(timeZoneOrder("Europe/Warsaw"))).toBe(true);
    expect(orderReady(timeZoneOrder("somewhere else"))).toBe(false);
  });
});
