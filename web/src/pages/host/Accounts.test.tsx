import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import type { HostActions } from "../../lib/actions";
import type { LocalAccount } from "../../lib/types";
import { AccountGroups, KeysPanel, type Request } from "./Accounts";

/**
 * The SSH key editor of an account.
 */

const preview: HostActions = {
  version: 1,
  items: [
    { action: "localuser.sshkeys.add", permission: "localuser.sshkeys.add", mutating: true, risk: "high", allowed: true },
    { action: "localuser.sshkeys.remove", permission: "localuser.sshkeys.remove", mutating: true, risk: "high", allowed: true },
    {
      action: "localuser.sshkeys.replace_all", permission: "localuser.sshkeys.replace",
      mutating: true, risk: "critical", allowed: true,
    },
  ],
};

vi.mock("../../lib/api", () => ({
  api: {
    get: (path: string) => {
      if (path === "/api/v1/hosts/h1/actions") return Promise.resolve(preview);
      return Promise.reject(new Error(`no answer for ${path}`));
    },
    post: () => Promise.reject(new Error("the test places no order of its own")),
  },
  ApiError: class extends Error {},
}));

const userKey = "SHA256:kVpBs5Sdlm2SO0vhFQb4Qz3f0sBv1ke2rK6mFqOZQ0I";
const managedKey = "SHA256:8oLrJk7GkqQ0Yb5t1nWlYy3xmD0QpH1dV2sC9uNfE4A";

function accountWith(overrides: Partial<LocalAccount> = {}): LocalAccount {
  return {
    name: "jane",
    uid: 1001,
    gid: 1001,
    home: "/home/jane",
    source: "local",
    groups: ["users"],
    locked: false,
    password_set: false,
    ssh_keys: [
      { fingerprint: userKey, type: "ED25519", comment: "jane@laptop", source: "authorized_keys" },
      { fingerprint: managedKey, type: "RSA", comment: "deploy", source: "managed" },
    ],
    observed_at: "2026-09-18T08:00:00Z",
    ...overrides,
  };
}

let request: Request & { mutate: ReturnType<typeof vi.fn> };

beforeEach(() => {
  request = { mutate: vi.fn(), message: "", busy: false };
});

afterEach(cleanup);

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function editor(account: LocalAccount) {
  return draw(<KeysPanel hostID="h1" account={account} request={request} onClose={() => {}} />);
}

/** The order the editor placed last. */
function lastOrder(): Record<string, unknown> {
  expect(request.mutate).toHaveBeenCalled();
  const calls = request.mutate.mock.calls;
  return calls[calls.length - 1][0] as Record<string, unknown>;
}

describe("the SSH key editor", () => {
  it("opens on the keys the inventory knows, with the file each one lives in", async () => {
    editor(accountWith());
    const rows = await screen.findAllByTestId("account-key");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("ED25519");
    expect(rows[0]).toHaveTextContent("jane@laptop");
    expect(rows[0]).toHaveTextContent("the user's authorized_keys");
    expect(rows[1]).toHaveTextContent("deploy");
    expect(rows[1]).toHaveTextContent("the panel's managed file");
  });

  it("says so when the account has no key, rather than showing an empty list as the whole truth", () => {
    editor(accountWith({ ssh_keys: [] }));
    expect(screen.getByText(/The host reports no key for jane/)).toBeInTheDocument();
    expect(screen.queryAllByTestId("account-key")).toHaveLength(0);
  });

  it("removes one key by its fingerprint and names the file it lives in", async () => {
    editor(accountWith());
    const remove = await screen.findAllByRole("button", { name: "Remove" });
    fireEvent.click(remove[0]);
    expect(lastOrder()).toMatchObject({
      action: "localuser.sshkeys.remove",
      name: "jane",
      fingerprints: [userKey],
    });
    expect(lastOrder().managed_file).toBeUndefined();
    expect(lastOrder().ssh_keys).toBeUndefined();

    fireEvent.click(remove[1]);
    expect(lastOrder()).toMatchObject({
      action: "localuser.sshkeys.remove",
      fingerprints: [managedKey],
      managed_file: true,
    });
  });

  it("asks for an explicit consent before taking the last key of an account with no password", async () => {
    editor(accountWith({
      ssh_keys: [{ fingerprint: userKey, type: "ED25519", source: "authorized_keys" }],
      password_set: false,
    }));
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    // Nothing is ordered on the first click: the removal waits for the
    // operator to say that cutting the account off is what they mean.
    expect(request.mutate).not.toHaveBeenCalled();
    expect(screen.getByText(/nobody can log in as it/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove and cut the account off" }));
    expect(lastOrder()).toMatchObject({
      action: "localuser.sshkeys.remove",
      fingerprints: [userKey],
      allow_lockout: true,
    });
  });

  it("adds a key without carrying the ones already there", async () => {
    editor(accountWith());
    const pasted = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8Kx3vQOZKq0M0hDPuJHf5Zx1kJHgqRqYqGZ6XxLm1";
    fireEvent.change(screen.getByPlaceholderText("ssh-ed25519 AAAA… jane@laptop"), { target: { value: pasted } });
    fireEvent.change(screen.getByPlaceholderText("jane@laptop"), { target: { value: "bob@desktop" } });
    fireEvent.click(await screen.findByRole("button", { name: "Add key" }));

    const order = lastOrder();
    expect(order).toMatchObject({
      action: "localuser.sshkeys.add",
      name: "jane",
      keys: [{ public_key: pasted, comment: "bob@desktop" }],
    });
    // An add names the new key and nothing else: neither the full list nor
    // the fingerprints of the keys that stay.
    expect(order.ssh_keys).toBeUndefined();
    expect(order.expected_fingerprints).toBeUndefined();
    expect(order.fingerprints).toBeUndefined();
  });

  it("binds a replace to the fingerprints of the file the operator saw", async () => {
    editor(accountWith());
    fireEvent.click(await screen.findByRole("button", { name: "Replace all…" }));

    // The confirmation names the key that goes away before anything is sent.
    expect(screen.getByTestId("keys-going-away")).toHaveTextContent("jane@laptop");

    const replacement = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeq4cJ7bMk0d6pQ0y0m0K0yS7T4a0m9v1c2X3y4Z5b6";
    fireEvent.change(screen.getByLabelText(/^The complete list/), { target: { value: replacement } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "rotating the key of a leaver" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace all keys" }));

    const order = lastOrder();
    expect(order).toMatchObject({
      action: "localuser.sshkeys.replace_all",
      name: "jane",
      ssh_keys: [replacement],
      // The list the operator saw in this very editor, for the file the
      // order writes: the key of the managed file is not part of it.
      expected_fingerprints: [userKey],
    });
    expect(order.managed_file).toBeUndefined();
    expect(String(order.reason).length).toBeGreaterThanOrEqual(8);
  });

  it("names the privileged membership of the account and what changing it takes", () => {
    editor(accountWith({ groups: ["users", "sudo"] }));
    expect(screen.getByText(/accounts\.privileged_groups/)).toBeInTheDocument();
  });
});

describe("the groups of an account", () => {
  it("badges a group that is root by another name", () => {
    render(<AccountGroups groups={["users", "sudo", "docker"]} />);
    const badges = screen.getAllByTestId("privileged-group");
    expect(badges.map((badge) => badge.textContent)).toEqual(["sudo", "docker"]);
    expect(badges[0]).toHaveClass("badge", "warn");
    expect(screen.getByText("users")).not.toHaveClass("badge");
  });
});
