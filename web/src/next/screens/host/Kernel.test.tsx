import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Kernel, moduleBlockOrder, pendingSetting, sysctlOrder } from "./Kernel";
import { orderReady, refusalOf } from "./Power";

/**
 * The kernel module is read for one thing: whether the kernel applies
 * what the panel asked for. Everything else on it - the modules, the
 * command line - is context for that. So the tests are about the
 * difference between asked and applied, about an order going out in the
 * shape the server takes, and about the refusals that stop one.
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
        // The longest match wins: `/api/v1/hosts/h1` is a prefix of
        // `/api/v1/hosts/h1/inventory/kernel`, and answering the second
        // with the first hands the screen the wrong document.
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
} as unknown as Parameters<typeof Kernel>[0]["host"];

const allowed = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "normal", allowed: true,
  })),
});

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "kernel", revision: "abcdef123456", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

/**
 * The module is two sub-tabs since 17.10 and the address names the open
 * one, so a test of a decision asks for the tab a reader would follow a
 * link to.
 */
function draw(tab?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/hosts/h1/kernel?tab=${tab}` : "/hosts/h1/kernel";
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Kernel host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

function base(payload: unknown) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/inventory/kernel": fragment(payload),
    "/api/v1/hosts/h1/actions": allowed("sysctl.ensure", "kernel.module.blacklist", "kernel.module.load"),
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
  });
}

describe("the kernel settings of a host", () => {
  it("says which key the kernel is not applying, and leaves a watched key alone", async () => {
    base({
      release: "6.11.0", managed_path: "/etc/sysctl.d/99-flotestro.conf",
      settings: [
        { key: "net.ipv4.ip_forward", current: "0", desired: "1", managed: true },
        { key: "vm.swappiness", current: "60", managed: false },
      ],
      modules: [], blacklist: [],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kernel-settings")).toBeInTheDocument());
    const table = screen.getByTestId("kernel-settings");
    expect(within(table).getByText("not applied yet")).toBeInTheDocument();
    // A key nobody set a value for is watched, not pending: it must not
    // be counted among the things somebody has to go and fix.
    expect(within(table).getAllByText("not applied yet")).toHaveLength(1);
    expect(screen.getByTestId("kpi-Not applied yet")).toHaveTextContent("1");
  });

  it("counts nothing where the host could not be read, and never a nought", async () => {
    base({ unavailable_reason: "the agent could not read /proc/sys", settings: [], modules: [] });
    draw();
    await waitFor(() => expect(screen.getByText(/could not be read/)).toBeInTheDocument());
    // A kernel nobody could read is not a kernel with no modules.
    expect(screen.getByTestId("kpi-Modules loaded")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Settings as desired")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Modules loaded")).not.toHaveTextContent("0");
  });

  it("blocks a module with the payload the server expects, after a reason and the hostname", async () => {
    base({
      settings: [],
      modules: [{ name: "pcspkr", size_bytes: 12288, used_by: [], blacklisted: false }],
      blacklist: [],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("block-pcspkr")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("block-pcspkr"));

    const order = screen.getByTestId("confirm-order");
    // Nothing goes out until the reason and the machine's own name are
    // both there: that is the whole point of the dialog.
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "noisy in the rack" } });
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(order);

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "kernel.module.blacklist",
      reason: "noisy in the rack",
      target_confirmation: "agent-arch",
      payload: { kernel: { module: "pcspkr", blacklist: true } },
    });
  });

  it("will not block a module the host cannot do without", () => {
    // The registry owns the list, so the row reads its refusal from there
    // rather than keeping a copy that drifts.
    const order = moduleBlockOrder("ext4", false);
    expect(orderReady(order)).toBe(false);
    expect(refusalOf((text) => text, order)).toContain("does not block");
  });

  it("refuses to load a module the panel has blocked on this host", async () => {
    base({
      settings: [],
      modules: [{ name: "br_netfilter", size_bytes: 1024, blacklisted: true }],
      blacklist: ["br_netfilter"],
    });
    draw("change");
    await waitFor(() => expect(screen.getByTestId("module-name")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("module-name"), { target: { value: "br_netfilter" } });
    expect(screen.getByTestId("module-load")).toBeDisabled();
    expect(screen.getByText(/unblock it first/)).toBeInTheDocument();
  });

  it("narrows the module list in the browser, because the host sent all of it", async () => {
    base({
      settings: [],
      modules: [
        { name: "nf_tables", size_bytes: 1, blacklisted: false },
        { name: "pcspkr", size_bytes: 1, blacklisted: false },
      ],
      blacklist: [],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("module-pcspkr")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("module-filter"), { target: { value: "nf_" } });
    expect(screen.queryByTestId("module-pcspkr")).toBeNull();
    expect(screen.getByTestId("module-nf_tables")).toBeInTheDocument();
  });

  it("says a host that has never reported its kernel has not reported it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not reported its kernel/)).toBeInTheDocument());
  });
});

describe("the orders the kernel module composes", () => {
  it("sends the settings as the registry shapes them", () => {
    const order = sysctlOrder({ settings: "net.ipv4.ip_forward = 1" });
    expect(orderReady(order)).toBe(true);
    expect(order.payload).toMatchObject({ kernel: { settings: { "net.ipv4.ip_forward": "1" } } });
  });

  it("refuses a key outside the branches the panel writes in", () => {
    const order = sysctlOrder({ settings: "dev.raid.speed_limit_max = 1" });
    expect(orderReady(order)).toBe(false);
  });

  it("calls a key with no desired value watched, not pending", () => {
    expect(pendingSetting({ key: "vm.swappiness", current: "60", managed: false })).toBe(false);
    expect(pendingSetting({ key: "vm.swappiness", current: "60", desired: "10", managed: true })).toBe(true);
    expect(pendingSetting({ key: "vm.swappiness", current: "10", desired: "10", managed: true })).toBe(false);
  });
});
