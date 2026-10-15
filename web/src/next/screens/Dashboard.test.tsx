import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Dashboard, DASHBOARD, DASHBOARD_SCREEN } from "./Dashboard";

/**
 * The screen answers one question - is there anything for me to do - and
 * the two ways it can lie about that are what is held here: a count nobody
 * took drawn as a nought, and a wall of noughts drawn as work.
 */

const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        const key = Object.keys(answers).find((one) => path.startsWith(one));
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
    },
  };
});

const summary = {
  hosts: 4, online: 3, offline: 1,
  jobs_awaiting_approval: 2, campaigns_awaiting_approval: 0, campaigns_manual_gate: 0,
  directory_changes_pending: 0, hosts_drifted: 0, operations_unconfirmed: 0,
  pending_enrollment_requests: 0,
  failed_jobs_24h: 0, package_database_broken: 0, agent_certificates_expired: 0,
  degraded_relays: 0, duplicate_identities_24h: 0, agents_unsupported: 0,
  reboot_required: 1, with_failed_units: 0, hosts_with_security_updates: 0,
  helper_capability_legacy: 0, sssd_offline: 0, agent_certificates_expiring: 0,
  relays_buffer_high: 0, enrollment_refusals_1h: 0, agents_behind_latest: 0,
  quarantined_hosts: 0, in_maintenance: 0,
};

const activity = {
  hours: ["2026-10-16T08:00:00Z", "2026-10-16T09:00:00Z"],
  succeeded: [2, 3], failed: [0, 1], other: [0, 0],
  by_connection_state: [{ key: "online", count: 3 }, { key: "offline", count: 1 }],
  by_os_family: [{ key: "debian", count: 2 }, { key: "arch", count: 2 }],
  by_agent_version: [{ key: "0.63.2", count: 4 }],
  by_site: [{ key: "lab", count: 4 }],
  by_environment: [{ key: "test", count: 4 }],
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Dashboard />, { wrapper });
}

afterEach(cleanup);

describe("the arrangement of the fleet dashboard", () => {
  it("is stored under a name the server takes", () => {
    // Lower-case letters, digits and underscores; the server refuses the
    // rest, the read fails, and the screen then offers no way to arrange
    // itself at all - which is how it shipped for an hour with a hyphen.
    expect(DASHBOARD_SCREEN).toMatch(/^[a-z0-9_]+$/);
  });

  it("names every container the screen draws, and no other", () => {
    expect(DASHBOARD.map((one) => one.key)).toEqual([
      "hosts", "online", "waiting", "found", "needs", "answering",
      "availability", "operations", "composition", "campaigns", "failures", "denials",
    ]);
    // Every one of them has a shape to ship with, or the first arrangement
    // of a screen nobody has touched is a guess.
    expect(DASHBOARD.every((one) => one.width >= 1 && one.width <= 12 && (one.height ?? 0) >= 1)).toBe(true);
  });
});

describe("the fleet dashboard", () => {
  it("opens with the four numbers somebody reads from the doorway", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/summary": summary,
      "/api/v1/fleet/activity": activity,
      "/api/v1/campaigns": { items: [] },
      "/api/v1/jobs": { items: [] },
      "/api/v1/audit": { items: [] },
      "/api/v1/security": { checks: [{ failed: 1, unknown: 0 }], unknown_hosts: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Hosts")).toHaveTextContent("4"));
    // Three of the four are counts of state; the first wears the accent and
    // says "start here", which is the one thing the accent is for.
    expect(screen.getByTestId("kpi-Hosts").className).toContain("fl-hero");
    expect(screen.getByTestId("kpi-Online")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-Online")).toHaveTextContent("1 offline");
    // Two approvals wait; one host wants a reboot and one check failed.
    expect(screen.getByTestId("kpi-Waiting on a person")).toHaveTextContent("2");
    expect(screen.getByTestId("kpi-Found on the hosts")).toHaveTextContent("1");
  });

  it("names what is open and counts the rest into one line", async () => {
    draw();
    await waitFor(() => expect(screen.getByText("Jobs awaiting approval")).toBeInTheDocument());
    // The nineteen counters at nought are not nineteen tiles: they are a
    // sentence. That wall of noughts is what the screen was thrown out for.
    expect(screen.getByText(/other checks are clear/)).toBeInTheDocument();
    expect(screen.queryByText("Degraded relays")).toBeNull();
  });

  it("draws a count nobody could take as a dash and says it was not taken", async () => {
    Object.assign(answers, { "/api/v1/security": new Error("the module refused") });
    draw();
    await waitFor(() => expect(screen.getByText("Checks with no answer")).toBeInTheDocument());
    const row = screen.getByText("Checks with no answer").closest(".fl-needs-row");
    expect(row).toHaveTextContent("—");
    expect(row).toHaveTextContent("not counted");
  });

  it("puts what is at zero under the availability band rather than in it", async () => {
    Object.assign(answers, { "/api/v1/security": { checks: [], unknown_hosts: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("availability").querySelectorAll(".fl-band-seg")).toHaveLength(2));
    const band = screen.getByTestId("availability");
    expect(within(band).getAllByRole("listitem")).toHaveLength(2);
    expect(band.querySelector(".fl-quiet-row")).toHaveTextContent("Stale");
  });
});
