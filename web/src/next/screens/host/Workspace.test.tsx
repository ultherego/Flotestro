import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { HostWorkspace } from "./Workspace";
import { HOST_MODULES } from "./modules";
import { MODULES } from "../../../lib/modules";

/**
 * A host page answers two questions before any module does: which machine
 * is this, and what can be done to it. The rail is the second answer, so
 * what it leaves out matters - a module this host has no backing for stays
 * listed and says why, because left out it reads as a panel that forgot it.
 */

const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/hosts/h1` is a prefix of
        // `/api/v1/hosts/h1/inventory/system`, and answering the second
        // with the first hands the screen a host where its hardware goes.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: ["role=db"], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", os_version: "", architecture: "amd64",
  agent_version: "0.63.2", enrolled_at: "2026-10-01T00:00:00Z",
  reboot_required: false, failed_units: 0, pending_updates: 18, pending_security_updates: 0,
  package_database_broken: false,
  capabilities: [
    { name: "packages", available: true, read_only: false },
    { name: "containers", available: false, read_only: false },
  ],
  identity: {},
};

function draw(at: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
  return render(
    <Routes>
      <Route path="/next/hosts/:id" element={<HostWorkspace />} />
      <Route path="/next/hosts/:id/:module" element={<HostWorkspace />} />
    </Routes>,
    { wrapper },
  );
}

afterEach(cleanup);

describe("the host workspace", () => {
  it("says which machine this is, and whether it answers", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1": host,
      "/api/v1/capabilities": { directory: true, local_users: true, campaign_v2: true },
      "/api/v1/whoami": { subject: "tester", permissions: ["host.read"] },
      "/api/v1/jobs": { items: [] },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw("/next/hosts/h1");
    await waitFor(() => expect(screen.getByRole("heading", { name: "agent-arch" })).toBeInTheDocument());
    expect(screen.getByText("online")).toBeInTheDocument();
    const head = screen.getByRole("heading", { name: "agent-arch" }).closest(".fl-head") as HTMLElement;
    expect(within(head).getByText("192.168.56.70")).toBeInTheDocument();
    expect(within(head).getByText("lab / test")).toBeInTheDocument();
    // A tag leads to the hosts that carry it; that is what a tag is for.
    expect(screen.getByRole("link", { name: "role=db" })).toHaveAttribute("href", "/next/hosts?tag=role%3Ddb");
  });

  it("turns the rail into this host's modules, with the way back", async () => {
    draw("/next/hosts/h1");
    const overview = await screen.findByRole("link", { name: "Overview" });
    const rail = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(rail).getByRole("link", { name: "All hosts" })).toHaveAttribute("href", "/next/hosts");
    expect(overview).toHaveAttribute("href", "/next/hosts/h1/overview");
    // The fleet's own places are not in the rail of a host: two rails side
    // by side would be two answers to "where am I".
    expect(within(rail).queryByRole("link", { name: "Campaigns" })).toBeNull();
  });

  it("lists a module this host has no backing for, dimmed, and says why", async () => {
    draw("/next/hosts/h1");
    // The host reported no container runtime, so the module cannot be
    // opened - but it is on the rail, or nobody would know it exists.
    await screen.findByRole("link", { name: "Overview" });
    // "Containers" is both a heading of the rail and a module under it, so
    // the module is the one that is an item.
    const containers = screen.getAllByText("Containers")
      .map((one) => one.closest(".fl-navitem"))
      .find(Boolean) as HTMLElement;
    expect(containers).toHaveClass("fl-off");
    expect(containers?.getAttribute("title")).toBeTruthy();
    expect(containers?.tagName).not.toBe("A");
  });

  /**
   * Every module the registry names has a screen here.
   *
   * It was the other way round until the modules were written: the test
   * held the panel to saying so where one was missing. Now the registry
   * and the screens are two lists that must agree, and a module added to
   * one without the other is a failure here rather than a blank page in
   * front of an operator.
   */
  it("draws every module the registry names", () => {
    const named = MODULES.map((one) => one.segment).sort();
    const drawn = Object.keys(HOST_MODULES).sort();
    expect(named.filter((one) => !drawn.includes(one))).toEqual([]);
    expect(drawn.filter((one) => !named.includes(one))).toEqual([]);
  });
});

describe("the overview of a host", () => {
  it("draws a figure the host never reported as a dash, never as a nought", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/inventory/system": new Error("never reported") });
    draw("/next/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("kpi-Disk used")).toBeInTheDocument());
    // A nought on a disk reads as "plenty of room" about a machine nobody
    // has asked, which is the one place this matters most.
    expect(screen.getByTestId("kpi-Disk used")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-CPU cores")).toHaveTextContent("—");
  });

  it("reads the hardware the host did report", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/system": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z",
        payload: { hardware: { cpu_cores: 2, memory_bytes: 3113851289, root_fs_bytes: 130000000000, root_fs_free_bytes: 120000000000 } },
      },
    });
    draw("/next/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("kpi-CPU cores")).toHaveTextContent("2"));
    expect(screen.getByTestId("kpi-Disk used")).toHaveTextContent("8");
  });

  it("counts the adapters it has, and says so when it has none to count", async () => {
    draw("/next/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("adapters")).toBeInTheDocument());
    const band = screen.getByTestId("adapters");
    expect(band).toHaveTextContent("available");
    expect(band).toHaveTextContent("unavailable");
  });
});
