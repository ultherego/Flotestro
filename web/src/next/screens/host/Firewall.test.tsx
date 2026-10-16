import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import {
  Firewall, adapterLabel, orderReady, restoreInForce, ruleName, ruleRemoveOrder, zonePortOrder,
} from "./Firewall";

/**
 * Only the rules in Flotestro's own table are durable, and every change
 * here can close the panel's own way in. So what is held is that the order
 * carries the fingerprint of the ruleset the operator read, that it asks
 * first with a reason, that a rule without a counter does not pretend
 * nothing passed through it, and that a boot restore nobody reported is
 * unknown rather than agreement.
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

const may = (actions: string[], refused: Record<string, string> = {}) => ({
  version: 1,
  items: [
    ...actions.map((action) => ({
      action, permission: "host.firewall.write", mutating: true, risk: "high", allowed: true,
    })),
    ...Object.entries(refused).map(([action, reason]) => ({
      action, permission: "host.firewall.write", mutating: true, risk: "high",
      allowed: false, reason, reason_code: "permission_denied", missing_permission: "host.firewall.write",
    })),
  ],
});

const EVERY = [
  "firewall.rule.ensure", "firewall.rule.remove", "firewall.zone.port", "firewall.zone.service",
];

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "firewall", revision: "abcdef0123456789", source: "agent",
  payload, observed_at: "2026-10-16T09:00:00Z",
});

const ours = {
  family: "inet", table: "flotestro", chain: "input", handle: 7,
  text: "tcp dport 9100 accept", source: "managed", comment: "flotestro: allow-monitoring - scraping",
  packets: 120, bytes: 4096,
};

const theirs = {
  family: "ip", table: "nat", chain: "DOCKER", handle: 3,
  text: "meta l4proto tcp dnat to 172.17.0.2:80", source: "docker",
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Firewall host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the firewall module says", () => {
  it("names who wrote each rule and what has passed through it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours, theirs],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-7")).toBeInTheDocument());
    expect(screen.getByTestId("rule-7")).toHaveTextContent("Flotestro");
    expect(screen.getByTestId("rule-7")).toHaveTextContent("120 pkt");
    // A rule in somebody else's table is neither ours nor durable.
    expect(within(screen.getByTestId("rule-3")).getByText("docker")).toBeInTheDocument();
  });

  it("says a rule carries no counter rather than counting nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [theirs],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-3")).toBeInTheDocument());
    const row = screen.getByTestId("rule-3");
    expect(within(row).getByText("no counter")).toBeInTheDocument();
    expect(within(row).queryByText("0 pkt / 0 B")).toBeNull();
  });

  it("narrows the list, and tells an empty match from a host that filters nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours, theirs],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-7")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("rule-filter"), { target: { value: "DOCKER" } });
    expect(screen.queryByTestId("rule-7")).toBeNull();
    expect(screen.getByTestId("rule-3")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("rule-filter"), { target: { value: "nothing-matches" } });
    expect(screen.getByText("No rules match.")).toBeInTheDocument();
  });

  it("keeps only the rules the panel owns when asked", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours, theirs],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-3")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Only rules owned by Flotestro", { selector: "input" }));
    expect(screen.queryByTestId("rule-3")).toBeNull();
    expect(screen.getByTestId("rule-7")).toBeInTheDocument();
  });

  it("says a host with no rules filters nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({ adapter: "nftables", writable: true, rules: [] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/nothing filters its traffic/)).toBeInTheDocument());
  });

  it("binds a new rule to the ruleset the operator read, and asks before it goes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-rule")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-rule"));
    fireEvent.change(screen.getByTestId("rule-id"), { target: { value: "block-smtp" } });
    fireEvent.change(screen.getByTestId("rule-action"), { target: { value: "drop" } });
    fireEvent.change(screen.getByTestId("rule-ports"), { target: { value: "25" } });
    fireEvent.click(screen.getByTestId("create-rule"));

    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "stopping outbound spam" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "firewall.rule.ensure",
      reason: "stopping outbound spam",
      payload: {
        firewall: {
          rule_id: "block-smtp", chain: "input", action: "drop", protocol: "tcp",
          ports: ["25"], rollback_seconds: 120, expected_hash: "sha-abc",
        },
      },
    });
  });

  it("refuses a rule that matches nothing in particular, and says so on the button", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-rule")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-rule"));
    fireEvent.change(screen.getByTestId("rule-id"), { target: { value: "block-smtp" } });
    fireEvent.change(screen.getByTestId("rule-protocol"), { target: { value: "" } });
    const button = screen.getByTestId("create-rule");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringContaining("covers all traffic"));
  });

  it("opens a port in a zone permanently, with the rollback the screen carries", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "firewalld", writable: true, hash: "sha-abc", rules: [],
        zones: [{ name: "public", active: true, default: true, target: "default", interfaces: ["enp0s3"], services: ["ssh"], ports: [] }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("zone-public")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("zone-port-public"), { target: { value: "8443/tcp" } });
    fireEvent.click(screen.getByTestId("zone-open-public"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "publishing the console" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "firewall.zone.port",
      reason: "publishing the console",
      payload: {
        firewall: { zone: "public", ports: ["8443"], protocol: "tcp", enable: true, rollback_seconds: 120 },
      },
    });
  });

  it("will not remove a service the zone does not allow", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "firewalld", writable: true, rules: [],
        zones: [{ name: "public", active: true, default: true, services: ["ssh"] }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("zone-public")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("zone-service-public"), { target: { value: "https" } });
    expect(screen.getByTestId("zone-service-remove-public")).toBeDisabled();
    expect(screen.getByTestId("zone-service-add-public")).not.toBeDisabled();
  });

  it("keeps a boot restore nobody reported unknown rather than agreed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, rules: [ours],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getAllByText("not reported by this agent").length).toBe(2));
  });

  it("says once that the module is readable and not changeable", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/firewall": fragment({
        adapter: "nftables", writable: true, hash: "sha-abc", rules: [ours],
      }),
      "/api/v1/hosts/h1/actions": may([], Object.fromEntries(EVERY.map((one) => [one, "no"]))),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.firewall.write/)).toBeInTheDocument());
    expect(screen.queryByTestId("new-rule")).toBeNull();
    expect(screen.queryByTestId("remove-rule-7")).toBeNull();
  });
});

describe("what the module reads out of the snapshot", () => {
  it("reads the panel's own name for a rule out of its comment", () => {
    expect(ruleName(ours as never)).toBe("allow-monitoring");
    expect(ruleName(theirs as never)).toBe("");
  });

  it("will not take away a rule it cannot name", () => {
    expect(orderReady(ruleRemoveOrder("allow-monitoring"))).toBe(true);
    expect(orderReady(ruleRemoveOrder(""))).toBe(false);
  });

  it("calls the restore in force only where it ran, or where it is not needed", () => {
    expect(restoreInForce({ ran: true })).toBe(true);
    expect(restoreInForce({ ran: false })).toBe(false);
    expect(restoreInForce({ reason: "nft_boot_restore_not_needed" })).toBe(true);
    expect(restoreInForce({ reason: "nft_boot_restore_unit_missing" })).toBe(false);
  });

  it("refuses a zone entry of more than one port", () => {
    expect(orderReady(zonePortOrder("public", "8443", "tcp", true))).toBe(true);
    expect(orderReady(zonePortOrder("public", "", "tcp", true))).toBe(false);
  });

  it("shows an unknown adapter name as the host sent it", () => {
    expect(adapterLabel("ufw")).toBe("UFW");
    expect(adapterLabel("something-else")).toBe("something-else");
  });
});
