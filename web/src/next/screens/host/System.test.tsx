import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { System, adapterTone, rootPressure } from "./System";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";

/**
 * What the machine is - and, more to the point, what nobody could read
 * about it.
 *
 * The one thing this screen must never do is turn a fact the host refused
 * to read into a fact of none. A container has no DMI tables; that is not
 * a machine with an empty serial number, and the reason has to reach the
 * reader.
 */

const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document -
  // `/api/v1/hosts/h1` would answer the inventory with a host record.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const found = answers[key];
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return {
    ...actual,
    api: { ...actual.api, get: answer, post: () => Promise.resolve({}), put: () => Promise.resolve({}), del: () => Promise.resolve(undefined) },
  };
});

const host = (over: Partial<Host> = {}): Host => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as Host);

const fragment = (payload: Record<string, unknown>) => ({
  host_id: "h1", module: "system", revision: "abcdef1234567890", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

/**
 * The screen is two sub-tabs since 17.10, and the address names which one
 * is open - so a test that reads the kernel history asks for that tab, the
 * way a reader following a link would.
 */
function draw(one: Host = host(), tab?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/hosts/${one.id}/system?tab=${tab}` : `/hosts/${one.id}/system`;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<System host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the platform of one host", () => {
  it("reads the kernel, the release and how long it has been up", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": fragment({
        observed_at: "2026-10-16T08:00:00Z",
        kernel: { release: "6.11.4-arch1-1", architecture: "x86_64" },
        distribution: { pretty_name: "Arch Linux" },
        boot: { uptime_seconds: 3 * 86400 + 4 * 3600 + 5 * 60 },
        virtualization: { kind: "kvm", source: "systemd-detect-virt" },
      }),
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-kernel")).toHaveTextContent("6.11.4-arch1-1"));
    expect(screen.getByTestId("kpi-release")).toHaveTextContent("Arch Linux");
    expect(screen.getByTestId("kpi-uptime")).toHaveTextContent("3 d 4 h 5 min");
    expect(screen.getByTestId("kpi-runs-on")).toHaveTextContent("kvm");
  });

  it("draws an em dash, never a nought, for what the host never reported", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": fragment({ observed_at: "2026-10-16T08:00:00Z" }),
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
    draw();
    // Nothing was reported about the boot, so the uptime is unknown. A
    // nought here would read as a machine that has just come up.
    await waitFor(() => expect(screen.getByTestId("kpi-uptime")).toHaveTextContent("—"));
    expect(screen.getByTestId("kpi-uptime")).toHaveAttribute("data-state", "unknown");
    expect(within(screen.getByTestId("kpi-uptime")).queryByText("0")).toBeNull();
  });

  it("says a fact was not read, and why, instead of showing it empty", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": fragment({
        observed_at: "2026-10-16T08:00:00Z",
        dmi: {},
        missing: { dmi: "the DMI tables are not exposed in a container" },
      }),
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
    draw(host(), "hardware");
    await waitFor(() => expect(screen.getByTestId("not-read")).toBeInTheDocument());
    // The reason travels to the reader twice: on the fact itself and in
    // the list of everything that could not be read.
    expect(screen.getByTestId("not-read")).toHaveTextContent("the DMI tables are not exposed in a container");
    const unknown = screen.getAllByTitle("the DMI tables are not exposed in a container");
    expect(unknown.length).toBeGreaterThan(0);
  });

  it("leads an adapter to the module that stands on it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": fragment({ observed_at: "2026-10-16T08:00:00Z" }),
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
    draw(host({
      capabilities: [
        { name: "systemd", version: 1, available: true, read_only: false },
        { name: "docker", version: 1, available: false, read_only: false, reason: "no docker socket" },
      ],
    }), "capabilities");
    await waitFor(() => expect(screen.getByTestId("adapters")).toBeInTheDocument());
    const table = screen.getByTestId("adapters");
    expect(within(table).getByRole("link", { name: "systemd" })).toHaveAttribute("href", "/hosts/h1/services");
    expect(table).toHaveTextContent("no docker socket");
    expect(table).toHaveTextContent("unavailable");
  });

  it("keeps every platform the panel has seen the host on", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": fragment({ observed_at: "2026-10-16T08:00:00Z" }),
      "/api/v1/hosts/h1/system/history": {
        items: [
          {
            kernel: "6.11.4-arch1-1", distribution: "arch", distribution_version: "",
            first_seen_at: "2026-10-10T00:00:00Z", last_seen_at: "2026-10-16T00:00:00Z",
          },
          {
            kernel: "6.10.9-arch1-1", distribution: "arch", distribution_version: "",
            first_seen_at: "2026-09-01T00:00:00Z", last_seen_at: "2026-10-09T00:00:00Z",
          },
        ],
      },
    });
    draw(host(), "history");
    await waitFor(() => expect(screen.getByTestId("system-history")).toHaveTextContent("6.10.9-arch1-1"));
    expect(screen.getByTestId("system-history")).toHaveTextContent("6.11.4-arch1-1");
  });

  it("says so when the agent sends the basic facts alone", async () => {
    Object.assign(answers, {
      // No observed_at in the payload: an agent from before the platform
      // picture. Nine cards of unknowns would say nothing about why.
      "/api/v1/hosts/h1/inventory/system": fragment({ os: { family: "debian" } }),
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/basic facts only/)).toBeInTheDocument());
  });

  it("says nothing at all when the host has not reported its platform", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/system/history": { items: [] } });
    draw();
    await waitFor(() => expect(screen.getByText("This host has not reported its platform yet.")).toBeInTheDocument());
  });
});

describe("reading a root filesystem", () => {
  it("is unknown when the host reported neither size nor free space", () => {
    expect(rootPressure(undefined, undefined)).toEqual({});
    expect(rootPressure(0, 0)).toEqual({});
  });

  it("turns from well to a warning at four fifths and to a fault at nine tenths", () => {
    expect(rootPressure(100, 50).tone).toBe("ok");
    expect(rootPressure(100, 15).tone).toBe("warn");
    expect(rootPressure(100, 5).tone).toBe("error");
  });
});

describe("reading an adapter", () => {
  it("counts a read-only adapter as present, and says what it cannot do", () => {
    expect(adapterTone({ name: "x", version: 1, available: true, read_only: true }).label).toBe("read only");
    expect(adapterTone({ name: "x", version: 1, available: true, read_only: false }).label).toBe("available");
    expect(adapterTone({ name: "x", version: 1, available: false, read_only: false }).label).toBe("unavailable");
  });
});
