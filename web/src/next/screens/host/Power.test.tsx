import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Power, bootLogsPath, dashedBootID, uptimeWords } from "./Power";

/**
 * Power is the module that turns a machine off, so the tests are about
 * the guards rather than about the drawing: nothing goes out without a
 * reason and the machine's own name typed, a shutdown needs its reason
 * before the dialog is even offered, and the override of the inhibitors
 * governs the reboot as well as the shutdown.
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
        // The longest match wins: a short key answering a longer path
        // hands the screen the wrong document.
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
} as unknown as Parameters<typeof Power>[0]["host"];

type Verdict = {
  action: string; permission: string; mutating: boolean; risk: string; allowed: boolean;
  reason_code?: string; missing_permission?: string; reason?: string;
};

const allowed = (...actions: string[]): { version: number; items: Verdict[] } => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "critical", allowed: true,
  })),
});

function base(payload: unknown, actions: { version: number; items: Verdict[] } = allowed("system.reboot", "system.shutdown")) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/inventory/power": {
      host_id: "h1", module: "power", revision: "abcdef123456", source: "agent",
      observed_at: "2026-10-16T08:00:00Z", payload,
    },
    "/api/v1/hosts/h1/actions": actions,
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
  });
}

function draw(over: Record<string, unknown> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Power host={{ ...host, ...over }} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the power module of a host", () => {
  it("reboots with the payload the server expects, once a reason is given", async () => {
    base({ uptime_seconds: 93784, reboot_required: false, inhibitors_known: true, inhibitors: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("reboot")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("reboot"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "kernel upgrade, ticket 42" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "system.reboot",
      reason: "kernel upgrade, ticket 42",
      target_confirmation: "agent-arch",
      payload: { reboot: { delay_seconds: 15, reason: "operator reboot", ignore_inhibitors: false } },
    });
  });

  it("refuses a shutdown nobody gave a reason for, before the dialog is offered", async () => {
    base({ inhibitors_known: true, inhibitors: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("shutdown")).toBeInTheDocument());
    // Nobody will read the panel to find out why the host is dark, so the
    // reason is asked for on the screen and not only in the dialog.
    expect(screen.getByTestId("shutdown")).toBeDisabled();
    fireEvent.change(screen.getByTestId("shutdown-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("shutdown")).toBeDisabled();
    fireEvent.change(screen.getByTestId("shutdown-reason"), { target: { value: "disk replacement, ticket 1234" } });
    expect(screen.getByTestId("shutdown")).toBeEnabled();
  });

  it("carries the operator's reason and the override into the shutdown", async () => {
    base({
      inhibitors_known: true,
      inhibitors: [{ who: "packagekit", mode: "block", why: "updating" }],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("shutdown")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("shutdown-reason"), { target: { value: "disk replacement, ticket 1234" } });
    fireEvent.click(screen.getByText("override inhibitors"));
    fireEvent.click(screen.getByTestId("shutdown"));
    // The dialog says what the override costs before it is confirmed.
    expect(screen.getByText(/will be overridden/)).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "disk replacement, ticket 1234" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "system.shutdown",
      payload: {
        power: {
          mode: "poweroff", delay_seconds: 15,
          reason: "disk replacement, ticket 1234", ignore_inhibitors: true,
        },
      },
    });
  });

  it("says an unreported inhibitor count is unknown, never a nought", async () => {
    base({ uptime_seconds: null, inhibitors_known: false });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Inhibitors")).toBeInTheDocument());
    // A host that did not report its holds is not a host with none: the
    // difference is whether a shutdown would be stopped.
    expect(screen.getByTestId("kpi-Inhibitors")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Uptime")).toHaveTextContent("—");
    expect(screen.getByText(/did not report inhibitors/)).toBeInTheDocument();
  });

  it("leads from every boot to the journal of that boot", async () => {
    base({
      boot_id: "4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01",
      last_boots: [
        { index: 0, boot_id: "4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01", first_entry: "2026-10-15T00:00:00Z", last_entry: "2026-10-16T00:00:00Z" },
        { index: -1, boot_id: "1111111111114111811111111111111c", first_entry: "2026-10-14T00:00:00Z", last_entry: "2026-10-15T00:00:00Z" },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByText("this boot")).toBeInTheDocument());
    const dashed = dashedBootID("4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01");
    expect(screen.getByRole("link", { name: dashed })).toHaveAttribute(
      "href", "/next/hosts/h1/logs?boot=4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01");
  });

  it("names a shutdown somebody else scheduled before anything is ordered here", async () => {
    base({ scheduled_shutdown: { mode: "poweroff", at: "2026-10-16T22:00:00Z" } });
    draw();
    await waitFor(() => expect(screen.getByText(/is already scheduled/)).toBeInTheDocument());
  });

  it("offers nothing to press where the panel would refuse the order", async () => {
    base({ inhibitors_known: true, inhibitors: [] }, {
      version: 1,
      items: [
        { action: "system.reboot", permission: "host.reboot", mutating: true, risk: "critical", allowed: false, reason_code: "permission_denied", missing_permission: "host.reboot", reason: "you may not reboot this host" },
        { action: "system.shutdown", permission: "host.reboot", mutating: true, risk: "critical", allowed: false, reason_code: "permission_denied", missing_permission: "host.reboot", reason: "you may not shut this host down" },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByText(/You can read this module/)).toBeInTheDocument());
    // The control is gone and the refusal stands where it was, so the
    // reader learns that the thing exists and what it would take.
    expect(screen.queryByTestId("reboot")).toBeNull();
    expect(screen.getByText("you may not reboot this host")).toBeInTheDocument();
  });

  it("starts a maintenance window without going through the job queue", async () => {
    base({});
    draw();
    await waitFor(() => expect(screen.getByTestId("window-start")).toBeInTheDocument());
    expect(screen.getByTestId("window-start")).toBeDisabled();
    fireEvent.change(screen.getByTestId("window-reason"), { target: { value: "disk swap" } });
    fireEvent.click(screen.getByTestId("window-start"));
    await waitFor(() => expect(posted).toHaveLength(1));
    // It changes what the panel thinks about the host, so it is a change
    // of the host and not an operation sent to it.
    expect(posted[0].path).toBe("/api/v1/hosts/h1/maintenance");
    expect(posted[0].body).toMatchObject({ duration_minutes: 120, reason: "disk swap" });
  });

  it("says a host that has never reported its boot state has not reported it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not reported its boot state/)).toBeInTheDocument());
  });
});

describe("what the power module reads out of a boot", () => {
  it("prints a boot identifier the way the kernel does", () => {
    expect(dashedBootID("4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01")).toBe("4b1f8d2e-9c7a-4f1b-8e3d-5a6c7b8d9e01");
    // Anything that is not a boot identifier is left as it came.
    expect(dashedBootID("not-an-id")).toBe("not-an-id");
  });

  it("leads to the journal of a boot inside the new panel", () => {
    expect(bootLogsPath("h1", "4B1F8D2E-9C7A-4F1B-8E3D-5A6C7B8D9E01"))
      .toBe("/next/hosts/h1/logs?boot=4b1f8d2e9c7a4f1b8e3d5a6c7b8d9e01");
  });

  it("reads an uptime without arithmetic in one's head", () => {
    expect(uptimeWords(93784)).toBe("1d 2h");
    expect(uptimeWords(7384)).toBe("2h 3m");
    expect(uptimeWords(120)).toBe("2m");
  });
});
