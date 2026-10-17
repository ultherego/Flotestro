import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
/** What the head ordered, and what it wrote, in the order it did. */
const posted: { path: string; body: unknown }[] = [];
const written: { path: string; body: unknown }[] = [];

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
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "j1", requires_approval: false });
      },
      put: (path: string, body: unknown) => {
        written.push({ path, body });
        return Promise.resolve({});
      },
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
      <Route path="/hosts/:id" element={<HostWorkspace />} />
      <Route path="/hosts/:id/:module" element={<HostWorkspace />} />
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
      // The overview asks what may be done to this host and what has been
      // done to it; without both, the longest-prefix answer above hands it
      // the host record where a preview and a timeline go.
      "/api/v1/hosts/h1/actions": { version: 1, items: [] },
      "/api/v1/hosts/h1/timeline": { items: [], count: 0, sources: [] },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw("/hosts/h1");
    await waitFor(() => expect(screen.getByRole("heading", { name: "agent-arch" })).toBeInTheDocument());
    expect(screen.getByText("online")).toBeInTheDocument();
    const head = screen.getByRole("heading", { name: "agent-arch" }).closest(".fl-head") as HTMLElement;
    expect(within(head).getByText("192.168.56.70")).toBeInTheDocument();
    expect(within(head).getByText("lab / test")).toBeInTheDocument();
    // A tag leads to the hosts that carry it; that is what a tag is for.
    expect(screen.getByRole("link", { name: "role=db" })).toHaveAttribute("href", "/hosts?tag=role%3Ddb");
  });

  it("turns the rail into this host's modules, with the way back", async () => {
    draw("/hosts/h1");
    const overview = await screen.findByRole("link", { name: "Overview" });
    const rail = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(rail).getByRole("link", { name: "All hosts" })).toHaveAttribute("href", "/hosts");
    expect(overview).toHaveAttribute("href", "/hosts/h1/overview");
    // The fleet's own places are not in the rail of a host: two rails side
    // by side would be two answers to "where am I".
    expect(within(rail).queryByRole("link", { name: "Campaigns" })).toBeNull();
  });

  it("lists a module this host has no backing for, dimmed, and says why", async () => {
    draw("/hosts/h1");
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
    draw("/hosts/h1");
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
    draw("/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("kpi-CPU cores")).toHaveTextContent("2"));
    expect(screen.getByTestId("kpi-Disk used")).toHaveTextContent("8");
  });

  it("counts the adapters it has, and says so when it has none to count", async () => {
    draw("/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("adapters")).toBeInTheDocument());
    const band = screen.getByTestId("adapters");
    expect(band).toHaveTextContent("available");
    expect(band).toHaveTextContent("unavailable");
  });
});

/**
 * The head stands above all twenty-seven modules, so what it can do is
 * what an operator can do from anywhere on a machine: correct its tags,
 * ask it to read its inventory again, take its identifier away whole,
 * and see before anything else that the gateway is turning it away or
 * that somebody has declared a window on it.
 */
describe("the head above every module of a host", () => {
  /** The answers every one of these starts from, whatever ran before. */
  const base = () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1": { ...host, management_address_source: "session" },
      "/api/v1/capabilities": { directory: true, local_users: true, campaign_v2: true },
      "/api/v1/whoami": { subject: "tester", permissions: ["host.read"] },
      "/api/v1/jobs": { items: [] },
      "/api/v1/hosts/h1/actions": { version: 1, items: [] },
      "/api/v1/hosts/h1/timeline": { items: [], count: 0, sources: [] },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
      "/api/v1/hosts/h1/inventory/system": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/system/history": { items: [] },
    });
  };

  beforeEach(() => {
    base();
    posted.length = 0;
    written.length = 0;
  });

  it("writes the tags in place, and offers that to nobody without the permission", async () => {
    draw("/hosts/h1");
    await screen.findByRole("link", { name: "role=db" });
    // A reader sees the tags and no way to change them: the gate is the
    // permission, not a refusal the server gives after the typing.
    expect(screen.queryByTestId("edit-tags")).toBeNull();
    cleanup();

    answers["/api/v1/whoami"] = { subject: "tester", permissions: ["host.read", "host.tag.write"] };
    draw("/hosts/h1");
    fireEvent.click(await screen.findByTestId("edit-tags"));
    const field = screen.getByTestId("tags-input");
    // What it opens with is what the host carries, so a correction is an
    // edit rather than a retyping.
    expect(field).toHaveValue("role=db");
    fireEvent.change(field, { target: { value: "  role=db   tier=gold " } });
    fireEvent.keyDown(field, { key: "Enter" });
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0]).toEqual({
      path: "/api/v1/hosts/h1/tags",
      body: { tags: ["role=db", "tier=gold"] },
    });
  });

  it("takes Escape as leaving the tags as they were", async () => {
    answers["/api/v1/whoami"] = { subject: "tester", permissions: ["host.tag.write"] };
    draw("/hosts/h1");
    fireEvent.click(await screen.findByTestId("edit-tags"));
    fireEvent.change(screen.getByTestId("tags-input"), { target: { value: "role=web" } });
    fireEvent.keyDown(screen.getByTestId("tags-input"), { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("tags-input")).toBeNull());
    expect(written).toEqual([]);
  });

  it("reads the open module's inventory again and says how the job came out", async () => {
    answers["/api/v1/jobs/j1"] = { id: "j1", state: "succeeded", result_message: "inventory refreshed" };
    draw("/hosts/h1/system");
    fireEvent.click(await screen.findByTestId("refresh-module"));
    await waitFor(() => expect(posted).toHaveLength(1));
    // The scope is the registry's: the module that is open lives off the
    // system fragment, so that is the one the host re-reads.
    expect(posted[0]).toEqual({
      path: "/api/v1/hosts/h1/operations",
      body: { action: "inventory.refresh", payload: { inventory: { modules: ["system"] } } },
    });
    // The order is followed to its end: "ordered" leaves the reader
    // watching a page that has not changed.
    await waitFor(() => expect(screen.getByText("inventory refreshed")).toBeInTheDocument());
  });

  it("says a refused refresh was refused, rather than reporting nothing", async () => {
    answers["/api/v1/jobs/j1"] = { id: "j1", state: "failed", result_error_code: "helper_unavailable" };
    draw("/hosts/h1/system");
    fireEvent.click(await screen.findByTestId("refresh-module"));
    await waitFor(() => expect(screen.getByText("helper_unavailable")).toBeInTheDocument());
  });

  it("reads the whole inventory again from the actions, and leads where a module is not", async () => {
    answers["/api/v1/jobs/j1"] = { id: "j1", state: "succeeded", result_message: "inventory refreshed" };
    draw("/hosts/h1");
    fireEvent.click(await screen.findByTestId("host-actions"));
    expect(screen.getByRole("menuitem", { name: "Open the logs" })).toHaveAttribute("href", "/hosts/h1/logs");
    expect(screen.getByRole("menuitem", { name: "Jobs of this host" })).toHaveAttribute("href", "/hosts/h1/jobs");
    // Deliberately a way to the power module and not a button that
    // reboots from a menu: the order is confirmed where it is placed.
    expect(screen.getByRole("menuitem", { name: "Reboot (power module)" })).toHaveAttribute("href", "/hosts/h1/power");
    fireEvent.click(screen.getByTestId("refresh-inventory"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toEqual({
      path: "/api/v1/hosts/h1/operations",
      body: { action: "inventory.refresh", payload: { inventory: {} } },
    });
  });

  it("offers no refresh of a host that is not connected", async () => {
    answers["/api/v1/hosts/h1"] = { ...host, connection_state: "offline" };
    draw("/hosts/h1/system");
    await waitFor(() => expect(screen.getByTestId("refresh-module")).toBeDisabled());
    fireEvent.click(screen.getByTestId("host-actions"));
    expect(screen.getByTestId("refresh-inventory")).toBeDisabled();
  });

  it("shows the identifier short and says copied only when the clipboard took it", async () => {
    answers["/api/v1/hosts/h1"] = { ...host, id: "0123456789abcdef" };
    // A panel over plain HTTP has no clipboard at all, and a button that
    // says "copied" there tells the reader a value is somewhere it is not.
    const refusing = vi.fn().mockRejectedValue(new Error("not a secure context"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText: refusing }, configurable: true });
    draw("/hosts/h1");
    expect(await screen.findByTestId("host-id")).toHaveTextContent("01234567");
    fireEvent.click(screen.getByTestId("copy-host-id"));
    await waitFor(() => expect(screen.getByTestId("copy-host-id")).toHaveAttribute("title", "Copy by hand"));
    expect(refusing).toHaveBeenCalledWith("0123456789abcdef");
    cleanup();

    const taking = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: taking }, configurable: true });
    draw("/hosts/h1");
    fireEvent.click(await screen.findByTestId("copy-host-id"));
    await waitFor(() => expect(screen.getByTestId("copy-host-id")).toHaveAttribute("title", "Copied"));
    // The whole of it goes, not the eight characters that are read.
    expect(taking).toHaveBeenCalledWith("0123456789abcdef");
  });

  it("says the gateway turned this host away, and why", async () => {
    answers["/api/v1/hosts/h1"] = {
      ...host,
      connection_state: "offline",
      last_connection_refusal: {
        code: "certificate_expired",
        at: new Date(Date.now() - 3600_000).toISOString(),
        detail: "serial 7 expired on 2026-10-15",
      },
    };
    draw("/hosts/h1");
    const badge = await screen.findByText(/connection refused: certificate expired/);
    expect(badge).toHaveAttribute("title", "serial 7 expired on 2026-10-15");
    cleanup();

    // A host that answers is not being refused, whatever the last refusal
    // was: the badge would be a state the reader has already left behind.
    answers["/api/v1/hosts/h1"] = {
      ...host,
      connection_state: "online",
      last_connection_refusal: { code: "certificate_expired", at: new Date().toISOString() },
    };
    draw("/hosts/h1");
    await screen.findByRole("heading", { name: "agent-arch" });
    expect(screen.queryByText(/connection refused/)).toBeNull();
  });

  it("says a maintenance window while it stands, and not after it has passed", async () => {
    answers["/api/v1/hosts/h1"] = {
      ...host,
      maintenance: {
        until: new Date(Date.now() + 3600_000).toISOString(),
        reason: "disk replacement",
        set_by: "ula",
      },
    };
    draw("/hosts/h1");
    const badge = await screen.findByText(/maintenance until/);
    expect(badge).toHaveAttribute("title", "disk replacement · set by ula");
    cleanup();

    answers["/api/v1/hosts/h1"] = {
      ...host,
      maintenance: { until: new Date(Date.now() - 60_000).toISOString(), reason: "disk replacement" },
    };
    draw("/hosts/h1");
    await screen.findByRole("heading", { name: "agent-arch" });
    expect(screen.queryByText(/maintenance until/)).toBeNull();
  });

  it("says where the management address came from, and that none has been seen", async () => {
    draw("/hosts/h1");
    // The address the control plane saw at its own end and one the host
    // reported about itself are two different facts.
    expect(await screen.findByTestId("address-source")).toHaveTextContent("session");
    expect(screen.getByTestId("address-source").closest(".fl-stripitem"))
      .toHaveAttribute("title", "address seen by the control plane on its end of the connection");
    cleanup();

    answers["/api/v1/hosts/h1"] = { ...host, management_address: "", management_address_source: undefined };
    draw("/hosts/h1");
    const head = (await screen.findByRole("heading", { name: "agent-arch" })).closest(".fl-head") as HTMLElement;
    expect(within(head).getByText("address unknown")).toBeInTheDocument();
  });

  it("keeps the way back to the campaign an operator came from", async () => {
    draw("/hosts/h1/overview?campaign=c-42");
    expect(await screen.findByRole("link", { name: "Back to the campaign" }))
      .toHaveAttribute("href", "/campaigns/c-42");
    cleanup();

    draw("/hosts/h1/overview");
    await screen.findByRole("heading", { name: "agent-arch" });
    expect(screen.queryByRole("link", { name: "Back to the campaign" })).toBeNull();
  });
});
