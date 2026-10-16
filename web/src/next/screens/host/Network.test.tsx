import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import {
  Network, acceptRAWords, adapterLabel, layerKind, layerMembers, layerSummary, mtuOrder,
  orderReady, privacyWords, relevant, routeProtocolWords,
} from "./Network";

/**
 * The network module is the one whose every change can take the machine
 * away from the panel. So what is held here is not the drawing: it is that
 * a change asks first and carries a reason, that the order is the one the
 * registry composes, that a host with no write mechanism offers nothing,
 * and that a value the kernel never reported stays unknown.
 */

const sent: { path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const found = answers[key];
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => {
        sent.push({ path, body });
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
} as unknown as Host;

/** The server's preview of what this operator may order on this host. */
const may = (actions: string[], refused: Record<string, string> = {}) => ({
  version: 1,
  items: [
    ...actions.map((action) => ({
      action, permission: "host.network.write", mutating: true, risk: "high", allowed: true,
    })),
    ...Object.entries(refused).map(([action, reason]) => ({
      action, permission: "host.network.write", mutating: true, risk: "high",
      allowed: false, reason, reason_code: "permission_denied", missing_permission: "host.network.write",
    })),
  ],
});

const EVERY = [
  "network.mtu.set", "network.route.ensure", "network.profile.apply",
  "network.link.apply", "network.link.remove",
];

const iface = (over: Record<string, unknown>) => ({
  name: "enp0s3", index: 2, kind: "ethernet", mac: "08:00:27:11:22:33", mtu: 1500,
  oper_state: "up", carrier: true, speed_mbps: 1000, driver: "e1000",
  addresses: [{ family: "inet", address: "192.168.56.70/24", scope: "global", permanent: true }],
  management: true,
  ...over,
});

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "network", revision: "abcdef0123456789", source: "agent",
  payload, observed_at: "2026-10-16T09:00:00Z",
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Network host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the network module says", () => {
  it("draws an interface as the kernel reports it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({})],
        routes: [{ destination: "default", gateway: "192.168.56.1", interface: "enp0s3", protocol: "dhcp", metric: 100, family: "inet" }],
        management_interface: "enp0s3", management_address: "192.168.56.70", write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("interface-enp0s3")).toBeInTheDocument());
    const row = screen.getByTestId("interface-enp0s3");
    expect(row).toHaveTextContent("192.168.56.70/24");
    expect(row).toHaveTextContent("1500");
    expect(row).toHaveTextContent("management");
    // The adapter is named in the spelling the operator knows, not the
    // host's own lower-case key.
    expect(screen.getAllByText("NetworkManager").length).toBeGreaterThan(0);
  });

  it("keeps an interface that reported no carrier unknown rather than down", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({ name: "enp0s8", carrier: undefined, speed_mbps: undefined, management: false, addresses: [] })],
        write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("interface-enp0s8")).toBeInTheDocument());
    const row = screen.getByTestId("interface-enp0s8");
    // A missing value is not the same as a missing cable.
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    expect(within(row).queryByText("no carrier")).toBeNull();
    expect(row).toHaveTextContent("—");
  });

  it("hides the virtual interfaces until somebody asks for them", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({}), iface({ name: "veth9f1", kind: "veth", management: false, addresses: [] })],
        write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("interface-enp0s3")).toBeInTheDocument());
    expect(screen.queryByTestId("interface-veth9f1")).toBeNull();
    fireEvent.click(screen.getByLabelText(/Show virtual interfaces/i, { selector: "input" }));
    expect(screen.getByTestId("interface-veth9f1")).toBeInTheDocument();
  });

  it("offers nothing to change where the host has no write mechanism", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({})],
        read_only_reason: "no NetworkManager on this host",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("interface-enp0s3")).toBeInTheDocument());
    expect(screen.queryByTestId("change-enp0s3")).toBeNull();
    expect(screen.getByText(/no NetworkManager on this host/)).toBeInTheDocument();
  });

  it("says once that the module is readable and not changeable", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({ interfaces: [iface({})], write_adapter: "nmstate" }),
      "/api/v1/hosts/h1/actions": may([], Object.fromEntries(EVERY.map((one) => [one, "no"]))),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.network.write/)).toBeInTheDocument());
    // Nothing is offered that would be refused.
    expect(screen.queryByTestId("change-enp0s3")).toBeNull();
  });

  it("asks before it changes the MTU and posts what the registry composes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({})], write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-enp0s3")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("change-enp0s3"));

    // The interface the panel talks over warns before anything is typed.
    expect(screen.getByText(/the interface the panel talks to/)).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("mtu"), { target: { value: "9000" } });
    fireEvent.click(screen.getByTestId("set-mtu"));

    // Nothing has been sent: the change is a question first.
    expect(sent).toHaveLength(0);
    const confirm = screen.getByTestId("confirm");
    expect(confirm).toBeDisabled();

    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "ticket OPS-4211" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(sent[0].body).toEqual({
      action: "network.mtu.set",
      reason: "ticket OPS-4211",
      payload: { network: { interface: "enp0s3", mtu: "9000", rollback_seconds: 120 } },
    });
  });

  it("refuses an MTU the registry would not send, and says why on the button", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({})], write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-enp0s3")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("change-enp0s3"));
    fireEvent.change(screen.getByTestId("mtu"), { target: { value: "3" } });
    const button = screen.getByTestId("set-mtu");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringContaining("68"));
  });

  it("refuses to build a layer out of the interface the panel talks over", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({}), iface({ name: "enp0s8", management: false, addresses: [] })],
        write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("build-layer")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("build-layer"));
    fireEvent.change(screen.getByTestId("layer-name"), { target: { value: "bond0" } });
    fireEvent.change(screen.getByTestId("layer-members"), { target: { value: "enp0s3, enp0s8" } });
    expect(screen.getByText(/the interface the panel talks to this host over/)).toBeInTheDocument();
    expect(screen.getByTestId("build")).toBeDisabled();
  });

  it("says a bond is running on its spare rather than only that it is up", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({
          name: "bond0", kind: "bond", management: false,
          bond: { mode: "active-backup", members: ["enp0s8", "enp0s9"], miimon_ms: 100, primary: "enp0s8", active_member: "enp0s9" },
        })],
        write_adapter: "networkmanager",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("layer-bond0")).toBeInTheDocument());
    expect(within(screen.getByTestId("layer-bond0")).getByText("failed over")).toBeInTheDocument();
  });

  it("says the layering could not be read rather than that there are no layers", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/network": fragment({
        interfaces: [iface({})],
        write_adapter: "networkmanager",
        layering_unavailable_reason: "ip -details link failed",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/ip -details link failed/)).toBeInTheDocument());
  });
});

describe("the words the module puts on what the host reported", () => {
  it("names the origin of a route", () => {
    expect(routeProtocolWords("kernel")).toBe("kernel (from an address)");
    expect(routeProtocolWords("bgp")).toBe("routing daemon (bgp)");
    expect(routeProtocolWords(undefined)).toBe("—");
  });

  it("keeps an unreported kernel switch unknown", () => {
    expect(acceptRAWords(undefined)).toBe("unknown");
    expect(acceptRAWords(0)).toBe("ignored");
    expect(privacyWords(undefined)).toBe("unknown");
    expect(privacyWords(0)).toBe("off");
  });

  it("reads the layering off the interface", () => {
    const bond = iface({ bond: { mode: "802.3ad", members: ["a", "b"], miimon_ms: 100 } }) as never;
    expect(layerKind(bond)).toBe("bond");
    expect(layerMembers(bond)).toEqual(["a", "b"]);
    expect(layerSummary(bond)).toBe("bond (802.3ad) of a, b");
  });

  it("keeps a bridge the host made for docker out of the way", () => {
    expect(relevant(iface({ name: "br-9f1", management: false, kind: "bridge", addresses: [] }) as never)).toBe(false);
    expect(relevant(iface({}) as never)).toBe(true);
  });

  it("shows an unknown adapter name as the host sent it", () => {
    expect(adapterLabel("netplan")).toBe("netplan");
    expect(adapterLabel("something-else")).toBe("something-else");
  });

  it("refuses an order the registry will not take", () => {
    expect(orderReady(mtuOrder("enp0s3", "1500", 120))).toBe(true);
    expect(orderReady(mtuOrder("enp0s3", "", 120))).toBe(false);
    expect(orderReady(mtuOrder("", "1500", 120))).toBe(false);
  });
});
