import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import type { HostActions } from "../../lib/actions";
import type { LocalAccount } from "../../lib/types";
import { AccountGroups, KeysPanel, accountOrder, type Request } from "./Accounts";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

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
    fireEvent.change(screen.getByLabelText(/^Reason for adding the key/), { target: { value: "bob joins the on-call rota" } });
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
    fireEvent.change(screen.getByLabelText(/^Reason for replacing the list/), { target: { value: "rotating the key of a leaver" } });
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

/* Every order this page places goes through the operation registry, so the
   host page and the Bulk workspace send one payload and refuse one set of
   values. The page still keeps the refusals that read the account rather
   than the form - the last key of an account with no password. */

function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7 jane@laptop";
const FINGERPRINT = "SHA256:" + "a".repeat(43);

describe("accountOrder", () => {
  it("sends what the Bulk workspace sends, action by action", () => {
    expect(accountOrder({ action: "localuser.lock", name: "jane" }).payload)
      .toEqual(bulk("localuser.lock", { name: "jane" }));

    expect(accountOrder({
      action: "localuser.create", name: "jane", gecos: "Jane Smith",
      groups: ["developers", "adm"], ssh_keys: [KEY], create_home: true,
    }).payload).toEqual(bulk("localuser.create", {
      name: "jane", gecos: "Jane Smith", groups: "developers\nadm", ssh_keys: KEY, create_home: true,
    }));

    expect(accountOrder({ action: "localuser.groups.set", name: "jane", groups: ["developers"] }).payload)
      .toEqual(bulk("localuser.groups.set", { name: "jane", groups: "developers" }));

    expect(accountOrder({ action: "localuser.expiry.set", name: "jane", expires_at: "2026-12-31" }).payload)
      .toEqual(bulk("localuser.expiry.set", { name: "jane", expires_at: "2026-12-31" }));

    expect(accountOrder({
      action: "localuser.sshkeys.remove", name: "jane", fingerprints: [FINGERPRINT], managed_file: true,
    }).payload).toEqual(bulk("localuser.sshkeys.remove", {
      name: "jane", fingerprints: FINGERPRINT, managed_file: true,
    }));

    expect(accountOrder({
      action: "localuser.sshkeys.replace_all", name: "jane", ssh_keys: [KEY], expected_fingerprints: [FINGERPRINT],
    }).payload).toEqual(bulk("localuser.sshkeys.replace_all", {
      name: "jane", ssh_keys: KEY, expected_fingerprints: FINGERPRINT,
    }));

    expect(accountOrder({ action: "localuser.delete", name: "jane", remove_home: true }).payload)
      .toEqual(bulk("localuser.delete", { name: "jane", remove_home: true }));
  });

  it("adds a key exactly as the Bulk workspace does, and keeps a comment on top of it", () => {
    expect(accountOrder({ action: "localuser.sshkeys.add", name: "jane", keys: [{ public_key: KEY }] }).payload)
      .toEqual(bulk("localuser.sshkeys.add", { name: "jane", public_keys: KEY }));
    // The comment is the one thing the registry's key list does not carry,
    // so it is put back rather than lost.
    expect(accountOrder({
      action: "localuser.sshkeys.add", name: "jane", keys: [{ public_key: KEY, comment: "jane@laptop" }],
    }).payload).toEqual({ local_user: { name: "jane", keys: [{ public_key: KEY, comment: "jane@laptop" }] } });
  });

  // The refusals the page did not make before it went through the registry.
  it("refuses on the host page what the Bulk workspace refuses", () => {
    const refuses = (order: Parameters<typeof accountOrder>[0], sentence: string) => {
      const problems = accountOrder(order).problems;
      expect(problems, JSON.stringify(order)).not.toEqual([]);
      expect(problems[0].message).toContain(sentence);
    };

    refuses({ action: "localuser.create", name: "Jane Smith", ssh_keys: [KEY] }, "An account name starts with");
    refuses({ action: "localuser.create", name: "jane", gecos: "Jane: Smith", ssh_keys: [KEY] }, "no colon");
    refuses({ action: "localuser.groups.set", name: "jane", groups: ["Developers"] }, "not a group name");
    refuses({ action: "localuser.delete", name: "root" }, "is not deleted through the panel");
    refuses({ action: "localuser.expiry.set", name: "jane", expires_at: "31/12/2026" }, "YYYY-MM-DD");
    refuses(
      { action: "localuser.sshkeys.add", name: "jane", keys: [{ public_key: "-----BEGIN OPENSSH PRIVATE KEY-----" }] },
      "That is a private key",
    );
    refuses({ action: "localuser.sshkeys.add", name: "jane", keys: [{ public_key: "not a key" }] }, "A key is one line");
    refuses({ action: "localuser.sshkeys.remove", name: "jane", fingerprints: ["ab:cd"] }, "not a fingerprint");
    refuses(
      { action: "localuser.sshkeys.replace_all", name: "jane", ssh_keys: [], expected_fingerprints: [FINGERPRINT] },
      "takes every way in away",
    );
  });

  it("gives the same refusals the Bulk workspace computes for the same form", () => {
    const entry = operationForm("localuser.create");
    const form: FormValue = { name: "Jane Smith", gecos: "", groups: "", ssh_keys: KEY, create_home: true };
    expect(accountOrder({
      action: "localuser.create", name: "Jane Smith", ssh_keys: [KEY], create_home: true,
    }).problems).toEqual(entry?.validate({ ...emptyForm(entry), ...form }));
  });
});
