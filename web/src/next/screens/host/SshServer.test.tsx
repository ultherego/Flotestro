import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import {
  SshServer, describe as describeSetting, effectiveConfigurationMissing, orderReady,
  sshConfigOrder, sshConfigSettings,
} from "./SshServer";

/**
 * sshd is how a person still reaches a machine when the panel cannot. So
 * what is held here is that rotating a key asks first and carries a
 * reason, that an order which changes nothing is not placed at all, and
 * that a configuration the host could not print is unknown rather than a
 * server with no ports and no methods.
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
      action, permission: "host.ssh.write", mutating: true, risk: "high", allowed: true,
    })),
    ...Object.entries(refused).map(([action, reason]) => ({
      action, permission: "host.ssh.write", mutating: true, risk: "high",
      allowed: false, reason, reason_code: "permission_denied", missing_permission: "host.ssh.write",
    })),
  ],
});

const EVERY = ["ssh.config.apply", "ssh.hostkey.rotate"];

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "ssh", revision: "abcdef0123456789", source: "agent",
  payload, observed_at: "2026-10-16T09:00:00Z",
});

const sshd = {
  ports: ["22"], listen_addresses: ["0.0.0.0"],
  permit_root_login: "prohibit-password", password_authentication: "no",
  pubkey_authentication: "yes", kbd_interactive_authentication: "no",
  max_auth_tries: 4, allow_users: ["ops"], allow_groups: [], deny_users: [], deny_groups: [],
  host_keys: [{ type: "ed25519", bits: 256, fingerprint: "SHA256:abcdefg", path: "/etc/ssh/ssh_host_ed25519_key" }],
  managed_path: "/etc/ssh/sshd_config.d/50-flotestro.conf",
  managed_present: true, managed_config: "PermitRootLogin prohibit-password\n",
  unit: "sshd.service", observed_at: "2026-10-16T09:00:00Z",
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<SshServer host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the sshd module says", () => {
  it("draws the configuration sshd itself printed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment(sshd),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-key-ed25519")).toBeInTheDocument());
    expect(screen.getByTestId("host-key-ed25519")).toHaveTextContent("SHA256:abcdefg");
    expect(screen.getAllByText("prohibit-password").length).toBeGreaterThan(0);
    expect(screen.getByTestId("method-Public key")).toHaveTextContent("yes");
    expect(screen.getByText("sshd.service")).toBeInTheDocument();
  });

  it("keeps a method the server never reported unknown", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment({ ...sshd, gssapi_authentication: undefined }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("method-GSSAPI")).toBeInTheDocument());
    const row = screen.getByTestId("method-GSSAPI");
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    expect(within(row).queryByText("no")).toBeNull();
  });

  it("keeps an attempt limit the read left empty unknown rather than nought", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment({ ...sshd, max_auth_tries: 0 }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-key-ed25519")).toBeInTheDocument());
    // MaxAuthTries is never zero in a configuration sshd printed: a zero
    // is the value of a field the read left empty.
    const labels = screen.getAllByText("Max auth tries");
    const posture = labels[0].closest(".fl-fact") as HTMLElement;
    expect(within(posture).getByText("unknown")).toBeInTheDocument();
    expect(within(posture).queryByText("0")).toBeNull();
    const effective = labels[1].closest(".fl-fact") as HTMLElement;
    expect(effective).toHaveTextContent("—");
    expect(within(effective).queryByText("0")).toBeNull();
  });

  it("says the host printed no effective configuration, and still counts the keys", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment({
        ports: [], host_keys: sshd.host_keys, managed_present: false,
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/the read of sshd -T gave nothing/)).toBeInTheDocument());
    // The ports are unknown; the keys came from the disk and are counted.
    expect(screen.getByTestId("kpi-Ports")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Host keys")).toHaveTextContent("1");
  });

  it("asks before it rotates a host key, and posts the key type", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment(sshd),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rotate-ed25519")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rotate-ed25519"));
    // Every client with the old fingerprint will warn; the dialog says so.
    expect(screen.getByText(/known_hosts will warn/)).toBeInTheDocument();
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "key rotation window" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "ssh.hostkey.rotate",
      reason: "key rotation window",
      payload: { ssh: { key_type: "ed25519" } },
    });
  });

  it("does not place an order that would change nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment(sshd),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-configuration")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("change-configuration"));
    // Empty means "leave it alone", so an untouched form has nothing to say.
    expect(screen.getByTestId("apply-configuration")).toBeDisabled();

    fireEvent.change(screen.getByTestId("field-port"), { target: { value: "2222" } });
    expect(screen.getByTestId("apply-configuration")).not.toBeDisabled();
    fireEvent.click(screen.getByTestId("apply-configuration"));

    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "moving sshd off 22" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "ssh.config.apply",
      reason: "moving sshd off 22",
      payload: { ssh: { port: "2222" } },
    });
  });

  it("refuses a port outside the range, and says why on the button", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment(sshd),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("change-configuration")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("change-configuration"));
    fireEvent.change(screen.getByTestId("field-port"), { target: { value: "99999" } });
    const button = screen.getByTestId("apply-configuration");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringContaining("65535"));
  });

  it("says the panel has written nothing to this host yet", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment({ ...sshd, managed_present: false, managed_config: undefined }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not written anything to this host yet/)).toBeInTheDocument());
  });

  it("says once that the module is readable and not changeable", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/ssh": fragment(sshd),
      "/api/v1/hosts/h1/actions": may([], Object.fromEntries(EVERY.map((one) => [one, "no"]))),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.ssh.write/)).toBeInTheDocument());
    expect(screen.queryByTestId("change-configuration")).toBeNull();
    expect(screen.queryByTestId("rotate-ed25519")).toBeNull();
  });
});

describe("what the module reads out of the snapshot", () => {
  it("tells a configuration sshd never printed from one it printed", () => {
    expect(effectiveConfigurationMissing({ ports: [] })).toBe(true);
    expect(effectiveConfigurationMissing({ ports: ["22"] })).toBe(false);
    expect(effectiveConfigurationMissing({ ports: [], permit_root_login: "no" })).toBe(false);
  });

  it("names only the settings the order would change", () => {
    expect(sshConfigSettings(sshConfigOrder({}))).toEqual([]);
    expect(sshConfigSettings(sshConfigOrder({ port: "2222" }))).toEqual(["port"]);
    // The lockout consent is not a setting; it is permission to make one.
    expect(sshConfigSettings(sshConfigOrder({ port: "2222", allow_lockout: true }))).toEqual(["port"]);
  });

  it("refuses a port the server would not take", () => {
    expect(orderReady(sshConfigOrder({ port: "2222" }))).toBe(true);
    expect(orderReady(sshConfigOrder({ port: "99999" }))).toBe(false);
    expect(orderReady(sshConfigOrder({ max_auth_tries: "400" }))).toBe(false);
  });

  it("reads a list setting out as the sentence says it", () => {
    expect(describeSetting(["ops", "admins"])).toBe("ops admins");
    expect(describeSetting("no")).toBe("no");
  });
});
