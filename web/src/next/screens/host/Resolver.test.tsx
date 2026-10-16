import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import { Resolver, modeMeaning, orderReady, ownerMeaning, resolverOrder } from "./Resolver";

/**
 * A host that cannot resolve names loses the directory, Kerberos and with
 * them logging in. So what is held here is that the change asks first and
 * carries a reason, that the test query runs on the host rather than in
 * the panel's own network, and that a resolver nobody could read is
 * unknown rather than a resolver with no servers.
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
      action, permission: "host.dns.write", mutating: true, risk: "high", allowed: true,
    })),
    ...Object.entries(refused).map(([action, reason]) => ({
      action, permission: "host.dns.write", mutating: true, risk: "high",
      allowed: false, reason, reason_code: "permission_denied", missing_permission: "host.dns.write",
    })),
  ],
});

const EVERY = ["dns.host.apply", "dns.resolve.test"];

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "dns", revision: "abcdef0123456789", source: "agent",
  payload, observed_at: "2026-10-16T09:00:00Z",
});

const resolved = {
  owner: "systemd-resolved", mode: "stub",
  resolv_conf: "/etc/resolv.conf", resolv_conf_target: "/run/systemd/resolve/stub-resolv.conf",
  servers: ["192.168.56.50"], search_domains: ["flotestro.test"],
  links: [{ name: "enp0s3", servers: ["192.168.56.50"], domains: ["flotestro.test"], default_route: true, dnssec: "no", dns_over_tls: "no" }],
  dnssec: "no", dns_over_tls: "no",
  writable: true, write_adapter: "systemd-resolved",
  observed_at: "2026-10-16T09:00:00Z",
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Resolver host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the resolver module says", () => {
  it("draws what the host resolves with and who owns the file", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment(resolved),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("link-enp0s3")).toBeInTheDocument());
    expect(screen.getAllByText("systemd-resolved").length).toBeGreaterThan(0);
    expect(screen.getByText("/run/systemd/resolve/stub-resolv.conf", { exact: false })).toBeInTheDocument();
    // The owner is the answer to "why can I not change this", so it is a
    // sentence rather than a word on hover alone.
    expect(screen.getByText(/systemd-resolved writes resolv.conf/)).toBeInTheDocument();
  });

  it("counts nothing where the resolver could not be read", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({ unavailable_reason: "resolvectl is not on this host" }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/resolvectl is not on this host/)).toBeInTheDocument());
    // A resolver nobody could read is unknown, never a resolver with no
    // servers: the tile draws a dash and says so.
    const tile = screen.getByTestId("kpi-Name servers");
    expect(tile).toHaveTextContent("—");
    expect(tile).toHaveAttribute("data-state", "unknown");
  });

  it("keeps the change shut on a host that rewrites the file itself", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({
        ...resolved, owner: "dhcp-client", writable: false, write_adapter: undefined,
        read_only_reason: "a DHCP client rewrites resolv.conf on every lease",
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-resolver")).toBeInTheDocument());
    const button = screen.getByTestId("change-resolver");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", "a DHCP client rewrites resolv.conf on every lease");
  });

  it("runs the test query on the host, with the names that were typed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment(resolved),
      "/api/v1/hosts/h1/actions": may(EVERY),
      "/api/v1/jobs/job-1234abcd/attempts": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("resolve")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("resolve-names"), { target: { value: "ipa.flotestro.test, db.flotestro.test" } });
    fireEvent.click(screen.getByTestId("resolve"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "dns.resolve.test",
      payload: { dns: { names: ["ipa.flotestro.test", "db.flotestro.test"] } },
    });
  });

  it("shows what the host answered, and says so when it answered nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment(resolved),
      "/api/v1/hosts/h1/actions": may(EVERY),
      "/api/v1/jobs/job-1234abcd/attempts": {
        items: [{
          status: "succeeded",
          detail: { queries: { queries: [
            { name: "ipa.flotestro.test", addresses: ["192.168.56.50"], server: "192.168.56.50", took_millis: 3 },
            { name: "nowhere.flotestro.test", error: "NXDOMAIN", took_millis: 9 },
          ] } },
        }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("resolve")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("resolve"));
    await waitFor(() => expect(screen.getByTestId("answer-ipa.flotestro.test")).toBeInTheDocument());
    expect(screen.getByTestId("answer-ipa.flotestro.test")).toHaveTextContent("192.168.56.50");
    // A name that did not resolve carries the host's own refusal, not a
    // blank cell.
    expect(screen.getByTestId("answer-nowhere.flotestro.test")).toHaveTextContent("NXDOMAIN");
  });

  it("asks before it rewrites the resolver and posts what the registry composes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment(resolved),
      "/api/v1/hosts/h1/actions": may(EVERY),
      "/api/v1/jobs/job-1234abcd/attempts": { items: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-resolver")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("change-resolver"));
    await waitFor(() => expect(screen.getByTestId("apply-resolver")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("apply-resolver"));

    // Nothing has gone yet: the change is a question first.
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "moving to the new resolver" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(sent[0].body).toEqual({
      action: "dns.host.apply",
      reason: "moving to the new resolver",
      payload: {
        dns: {
          interface: "enp0s3",
          servers: ["192.168.56.50"],
          search_domains: ["flotestro.test"],
          ignore_auto_dns: true,
          rollback_seconds: 120,
        },
      },
    });
  });

  it("keeps a link that never said whether it answers other names unknown", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({
        ...resolved,
        links: [{ name: "enp0s8", servers: [], domains: [] }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("link-enp0s8")).toBeInTheDocument());
    const row = screen.getByTestId("link-enp0s8");
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    expect(within(row).queryByText("no")).toBeNull();
  });

  /**
   * The two facts the old panel put on a link's row, and the word behind
   * the abbreviation. A link that validates and a link that encrypts are
   * different machines to an operator, and neither is readable from the
   * global card above the table.
   */
  it("keeps DNSSEC and DoT on the link's own row, and says what DoT stands for", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({
        ...resolved,
        links: [{
          name: "enp0s3", servers: ["192.168.56.50"], domains: ["flotestro.test"],
          default_route: true, dnssec: "allow-downgrade", dns_over_tls: "opportunistic",
        }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("link-enp0s3")).toBeInTheDocument());
    const row = screen.getByTestId("link-enp0s3");
    expect(within(row).getByText("allow-downgrade")).toBeInTheDocument();
    expect(within(row).getByText("opportunistic")).toBeInTheDocument();
    // "DoT" is three letters; the heading carries what they mean, as the
    // heading of the panel being replaced did.
    expect(screen.getByText("DoT")).toHaveAttribute("title", "DNS over TLS");
  });

  /** A link that reported neither draws the dash, never a "no". */
  it("leaves DNSSEC and DoT blank on a link that reported neither", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({
        ...resolved,
        links: [{ name: "enp0s8", servers: [], domains: [], default_route: false }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("link-enp0s8")).toBeInTheDocument());
    const row = screen.getByTestId("link-enp0s8");
    expect(within(row).getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("says the host has one global list rather than drawing an empty table", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment({ ...resolved, links: [] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/one global list/)).toBeInTheDocument());
  });

  it("says once that the module is readable and not changeable", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/dns": fragment(resolved),
      "/api/v1/hosts/h1/actions": may([], { "dns.host.apply": "no" }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.dns.write/)).toBeInTheDocument());
    expect(screen.queryByTestId("change-resolver")).toBeNull();
  });
});

describe("the words the module puts on what the host reported", () => {
  it("says what owning resolv.conf means for a change written here", () => {
    expect(ownerMeaning("dhcp-client")).toContain("overwritten at the next renewal");
    expect(ownerMeaning("whatever")).toBe("");
    expect(modeMeaning("stub")).toContain("local stub");
    expect(modeMeaning("whatever")).toBe("");
  });

  it("refuses a resolver with no server, and one whose server is not an address", () => {
    expect(orderReady(resolverOrder({ interface: "enp0s3", servers: "192.0.2.53", rollback_seconds: 120 }))).toBe(true);
    expect(orderReady(resolverOrder({ interface: "enp0s3", servers: "", rollback_seconds: 120 }))).toBe(false);
    expect(orderReady(resolverOrder({ interface: "enp0s3", servers: "not-an-address", rollback_seconds: 120 }))).toBe(false);
  });
});
