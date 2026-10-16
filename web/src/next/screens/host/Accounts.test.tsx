import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Accounts } from "./Accounts";
import type { Host, LocalAccount } from "../../../lib/types";

/**
 * Every row of this module is a way into the machine, so what is tested is
 * what it *does*: the order it posts, the gate that keeps a control off the
 * screen, the consent before an account is cut off - and the one thing a
 * key field must never do, which is let a private key out of the browser.
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
        // `/api/v1/hosts/h1/local-accounts`, and answering the second with
        // the first hands the screen the wrong document.
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

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
} as unknown as Host;

const account = (over: Partial<LocalAccount>): LocalAccount => ({
  name: "jane", uid: 1000, gid: 1000, home: "/home/jane", shell: "/bin/bash",
  source: "local", groups: [], locked: false, password_set: false, ssh_keys: [],
  observed_at: "2026-10-16T08:00:00Z",
  ...over,
});

/** Every change of this module allowed, as the host's preview answers it. */
const allowed = {
  version: 1,
  items: [
    "localuser.create", "localuser.delete", "localuser.lock", "localuser.unlock",
    "localuser.groups.set", "localuser.expiry.set",
    "localuser.sshkeys.add", "localuser.sshkeys.remove", "localuser.sshkeys.replace_all",
  ].map((action) => ({ action, permission: "host.write", mutating: true, risk: "high", allowed: true })),
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Accounts host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("a host's accounts", () => {
  it("draws an account with the way in it actually has", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [
        account({ name: "jane", groups: ["sudo"], ssh_keys: [{ fingerprint: "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg", type: "ssh-ed25519", comment: "jane@laptop" }] }),
      ] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const row = await screen.findByTestId("account-jane");
    expect(within(row).getByText("SSH key")).toBeInTheDocument();
    expect(within(row).getByText("1000")).toBeInTheDocument();
    // A group that is root by another name is marked as such on the row.
    expect(within(row).getByText("sudo")).toBeInTheDocument();
    expect(row).toHaveTextContent("AbCdEfGhIjKl");
  });

  /**
   * The UID stays on the row, and nought is a value here.
   *
   * 0 is root - the one number on this screen an operator must be able
   * to see without opening anything - so the column draws it rather than
   * treating it as "nobody said".
   */
  it("draws the UID on the row, and a UID of nought as root's own number", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [
        account({ name: "root", uid: 0, gid: 0, home: "/root" }),
        account({ name: "jane", uid: 1000 }),
      ] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const root = await screen.findByTestId("account-root");
    // The cell holds the number itself, not a dash standing in for one.
    const uid = within(root).getByText("0");
    expect(uid).toBeInTheDocument();
    expect(uid).not.toHaveTextContent("—");
    expect(screen.getByText("UID")).toBeInTheDocument();
    expect(within(screen.getByTestId("account-jane")).getByText("1000")).toBeInTheDocument();
  });

  it("says an account the host could not read is unknown, never 'no access'", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [
        account({ name: "quiet", locked: null, password_set: null, unavailable_reason: "shadow unreadable" }),
      ] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const row = await screen.findByTestId("account-quiet");
    expect(within(row).getAllByText("unknown").length).toBeGreaterThan(0);
    expect(within(row).queryByText("no access")).toBeNull();
    // The expiry of an account whose record was not read is unknown too, and
    // not the word "never", which would read as "this account never expires".
    expect(within(row).queryByText("never")).toBeNull();
  });

  it("posts the lock the server expects, with the registry's payload", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("lock-jane"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({ action: "localuser.lock", payload: { local_user: { name: "jane" } } });
    expect(await screen.findByText(/waiting for approval/)).toBeInTheDocument();
  });

  it("will not delete until the name is typed and a reason given", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("delete-jane"));
    const confirm = screen.getByTestId("confirm-delete");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("delete-reason"), { target: { value: "leaver ticket 42" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("delete-confirm"), { target: { value: "jane" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "localuser.delete",
      reason: "leaver ticket 42",
      target_confirmation: "jane",
      payload: { local_user: { name: "jane" } },
    });
  });

  it("asks for consent before the last key of an account goes away", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [
        account({ name: "jane", password_set: false, ssh_keys: [{ fingerprint: "SHA256:ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFfE", type: "ssh-ed25519" }] }),
      ] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("manage-jane"));
    fireEvent.click(await screen.findByTestId("remove-key-SHA256:ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFfE"));
    const confirm = screen.getByTestId("confirm-remove-key");
    fireEvent.change(screen.getByTestId("remove-key-reason"), { target: { value: "offboarding jane" } });
    // The reason alone is not enough: cutting the account off is a second,
    // explicit decision.
    expect(confirm).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /That is the intent/ }));
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "localuser.sshkeys.remove",
      reason: "offboarding jane",
      payload: { local_user: { name: "jane", allow_lockout: true, fingerprints: ["SHA256:ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFfE"] } },
    });
  });

  it("refuses a private key and sends nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("manage-jane"));
    const secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----";
    fireEvent.change(screen.getByTestId("new-key"), { target: { value: secret } });
    fireEvent.change(screen.getByTestId("key-reason"), { target: { value: "a good reason here" } });
    expect(await screen.findByText(/That is a private key/)).toBeInTheDocument();
    expect(screen.getByTestId("add-key")).toBeDisabled();
    fireEvent.click(screen.getByTestId("add-key"));
    expect(posted).toHaveLength(0);
  });

  it("never puts a key in an address", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("manage-jane"));
    const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsecretmaterial jane@laptop";
    fireEvent.change(screen.getByTestId("new-key"), { target: { value: key } });
    // Nothing the operator types goes into a link, so no address on the page
    // can carry the material of a key.
    for (const anchor of document.querySelectorAll("a")) {
      expect(anchor.getAttribute("href") ?? "").not.toContain("secretmaterial");
    }
  });

  it("takes the control away where the host refuses the action", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": {
        version: 1,
        items: [
          { action: "localuser.lock", permission: "host.write", mutating: true, risk: "high", allowed: false, reason_code: "permission_denied", missing_permission: "host.write", reason: "you lack host.write" },
          { action: "localuser.delete", permission: "host.write", mutating: true, risk: "destructive", allowed: false, reason_code: "permission_denied", missing_permission: "host.write", reason: "you lack host.write" },
        ],
      },
    });
    draw();
    await screen.findByTestId("account-jane");
    expect(screen.queryByTestId("lock-jane")).toBeNull();
    expect(screen.queryByTestId("delete-jane")).toBeNull();
    // Every change refused, so the module says so once rather than losing
    // its buttons without a word.
    expect(await screen.findByText(/You can read this module/)).toBeInTheDocument();
  });

  it("says so, rather than drawing an empty host, when the read is refused", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": new (await import("../../../lib/api")).ApiError(403, "forbidden", "not for you"),
    });
    draw();
    expect(await screen.findByText(/You do not have permission to read this host's accounts/)).toBeInTheDocument();
  });

  it("reads the system accounts from the server when they are asked for", async () => {
    const asked: string[] = [];
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [account({ name: "jane" })] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    const api = (await import("../../../lib/api")).api;
    const read = api.get;
    (api as unknown as { get: (path: string) => unknown }).get = (path: string) => {
      asked.push(path);
      return read(path);
    };
    draw();
    await screen.findByTestId("account-jane");
    fireEvent.click(screen.getByRole("checkbox", { name: /Show system accounts/ }));
    await waitFor(() => expect(asked.some((one) => one.includes("local-accounts?source=system"))).toBe(true));
    (api as unknown as { get: unknown }).get = read;
  });
});

describe("where one account opens", () => {
  it("puts the keys, the groups and the expiry under the account's own row", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/local-accounts": { accounts: [
        account({ name: "jane", groups: ["sudo"] }),
        account({ name: "bob", uid: 1001 }),
      ] },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const row = await screen.findByTestId("account-jane");
    fireEvent.click(screen.getByTestId("manage-jane"));
    // The three tabs open in the row immediately under jane's, across the
    // whole width - which is where the old module put them.
    const detail = screen.getByTestId("account-jane").nextElementSibling;
    expect(detail).toHaveClass("fl-row-detail");
    expect(detail?.querySelector("td")?.getAttribute("colspan"))
      .toBe(String(row.querySelectorAll("td").length));
    expect(within(detail as HTMLElement).getByRole("tab", { name: /Groups/ })).toBeInTheDocument();
    expect(within(detail as HTMLElement).getByRole("tab", { name: /Expiry/ })).toBeInTheDocument();
    // One account opens at a time: there is one detail row in the table.
    expect(document.querySelectorAll(".fl-row-detail")).toHaveLength(1);
  });
});
