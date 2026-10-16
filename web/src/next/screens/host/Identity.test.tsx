import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Identity } from "./Identity";
import type { Host } from "../../../lib/types";

/**
 * This module answers two questions that look alike and are not: what the
 * host believes about its domain, and what the directory and the local
 * sudoers actually grant on it. What is tested is that it keeps the three
 * answers apart - yes, no, and *does not apply* - and that a join carries a
 * reason and the host's own name, and never a password.
 */

const answers: Record<string, unknown> = {};
const posted: { path: string; body: unknown }[] = [];

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/hosts/h1` is a prefix of
        // `/api/v1/hosts/h1/access`, and answering the second with the
        // first hands the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-01234567", requires_approval: true });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Record<string, unknown> = {}): Host => ({
  id: "h1", hostname: "agent-arch.lab.test", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as unknown as Host);

const emptyAccess = {
  hostname: "agent-arch.lab.test", known: true, fqdn: "agent-arch.lab.test", enrolled: false,
  host_groups: [], hbac_rules: [], sudo_rules: [],
  directory: { configured: true, reachable: true },
  local_sudoers: { read: true, passwordless_globally: false, files: [], problems: [] },
  local_sudo_rules: [],
  root_equivalent_warnings: [],
};

/** Every change of this module allowed, as the host's preview answers it. */
const allowed = {
  version: 1,
  items: ["identity.host.enroll", "identity.host.preflight", "identity.keytab.renew", "identity.host.leave"]
    .map((action) => ({ action, permission: "identity.write", mutating: true, risk: "critical", allowed: true })),
};

const everyPermission = {
  subject: "tester",
  permissions: ["identity.host.enroll", "identity.read", "identity.keytab.rotate", "identity.host.leave"],
};

function draw(one: Host = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Identity host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("a host's identity", () => {
  it("says a host outside a domain has no principal, rather than an unknown one", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    await waitFor(() => expect(screen.getAllByText("not in a domain").length).toBeGreaterThan(0));
    // "Not in a domain" and "unknown" are different answers, and the one
    // that is wrong here would send somebody looking for a keytab.
    expect(screen.queryByText("Keytab KVNO")?.parentElement).toHaveTextContent("not in a domain");
  });

  it("says a fact the enrolled host did not report is unknown", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z",
        payload: { sssd_running: true },
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw(host({ identity: { enrolled: true, domain: "lab.test", realm: "LAB.TEST", sssd_online: null } }));
    await waitFor(() => expect(screen.getByText("Keytab KVNO")).toBeInTheDocument());
    const kvno = screen.getByText("Keytab KVNO").parentElement as HTMLElement;
    expect(within(kvno).getByText("unknown")).toBeInTheDocument();
  });

  it("joins with the realm in capitals, a reason and the host's own name typed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    fireEvent.change(await screen.findByTestId("domain"), { target: { value: "lab.test" } });
    fireEvent.change(screen.getByTestId("realm"), { target: { value: "lab.test" } });
    fireEvent.click(screen.getByTestId("join"));
    const confirm = screen.getByTestId("confirm-join");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-join-reason"), { target: { value: "joining the lab" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-join-typed"), { target: { value: "agent-arch.lab.test" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "identity.host.enroll",
      reason: "joining the lab",
      target_confirmation: "agent-arch.lab.test",
      payload: { domain_enroll: { domain: "lab.test", realm: "LAB.TEST", hostname: "agent-arch.lab.test" } },
    });
    // The one-time password is fetched when the task goes out: no field on
    // this screen takes one, and no order carries one.
    expect(JSON.stringify(posted[0].body)).not.toMatch(/password/i);
    expect(document.querySelectorAll("input[type=password]")).toHaveLength(0);
  });

  it("checks the host before it joins, and changes nothing by doing so", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    fireEvent.change(await screen.findByTestId("domain"), { target: { value: "lab.test" } });
    fireEvent.change(screen.getByTestId("realm"), { target: { value: "LAB.TEST" } });
    fireEvent.click(screen.getByTestId("preflight"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({ action: "identity.host.preflight" });
  });

  it("refuses a principal that is the host's own", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw(host({ identity: { enrolled: true, domain: "lab.test", realm: "LAB.TEST", sssd_online: true } }));
    const principal = await screen.findByTestId("principal");
    fireEvent.change(principal, { target: { value: "host/agent-arch.lab.test" } });
    expect(await screen.findByText(/not a service principal/)).toBeInTheDocument();
    expect(screen.getByTestId("renew")).toBeDisabled();
  });

  it("keeps the join off the screen for a session that may not order one", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": { subject: "reader", permissions: ["host.read"] },
    });
    draw();
    await waitFor(() => expect(screen.getByText("Directory client")).toBeInTheDocument());
    expect(screen.queryByTestId("join")).toBeNull();
    expect(screen.queryByTestId("preflight")).toBeNull();
  });

  it("puts a local grant of root before everything else on the screen", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": {
        ...emptyAccess,
        root_equivalent_warnings: ["%devs may run ALL as root without a password"],
        local_sudoers: { read: true, passwordless_globally: true, files: [], problems: [] },
      },
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    expect(await screen.findByText(/may run ALL as root without a password/)).toBeInTheDocument();
    expect(screen.getByText(/A global Defaults line turns authentication off/)).toBeInTheDocument();
  });

  it("says a sudoers policy that was not read is unknown, not an empty policy", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": {
        ...emptyAccess,
        local_sudoers: { read: false, reason: "the helper could not read /etc/sudoers", passwordless_globally: false },
      },
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    expect(await screen.findByText(/could not read \/etc\/sudoers/)).toBeInTheDocument();
    expect(screen.queryByText("The local sudoers files grant nothing.")).toBeNull();
  });

  it("says nobody from the directory can sign in when no rule reaches the host", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    expect(await screen.findByText(/nobody from the directory can sign in/)).toBeInTheDocument();
  });

  it("says the directory is refused rather than drawing it as empty", async () => {
    const { ApiError } = await import("../../../lib/api");
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": new ApiError(403, "forbidden", "not for you"),
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw();
    expect(await screen.findByText(/You do not have permission to read the directory/)).toBeInTheDocument();
  });

  it("leaves the domain only with a reason and the hostname typed out", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/identity": {
        source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z", payload: {},
      },
      "/api/v1/hosts/h1/access": emptyAccess,
      "/api/v1/hosts/h1/actions": allowed,
      "/api/v1/whoami": everyPermission,
    });
    draw(host({ identity: { enrolled: true, domain: "lab.test", realm: "LAB.TEST", sssd_online: true } }));
    fireEvent.click(await screen.findByTestId("leave"));
    fireEvent.change(screen.getByTestId("confirm-leave-reason"), { target: { value: "decommissioning" } });
    fireEvent.change(screen.getByTestId("confirm-leave-typed"), { target: { value: "agent-arch.lab.test" } });
    fireEvent.click(screen.getByTestId("confirm-leave"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "identity.host.leave",
      reason: "decommissioning",
      payload: { domain_leave: { domain: "lab.test", realm: "LAB.TEST" } },
    });
  });
});
