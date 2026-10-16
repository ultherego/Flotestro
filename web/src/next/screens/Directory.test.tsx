import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import { Directory, actionName, changeTone, lines, names, verdictLabel, verdictTone } from "./Directory";

/**
 * The directory screen, tested by what it asks of the directory.
 *
 * Nothing on this screen is the panel's own record, so what matters is
 * the order it is written in: a change is planned, the plan's impact is
 * read, and a second person approves. Every test here either sends a
 * change and checks what was sent, or checks that the screen refused to
 * send one that was not ready.
 */

const asked: string[] = [];
const sent: { path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
let planned: unknown = { id: "c0ffee1234", action_type: "identity.user.disable", state: "awaiting_approval" };

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: "/api/v1/
  // identity/users" left to answer ".../users?preserved=true" would hand
  // the preserved card the list of live accounts.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    const value = answers[key];
    if (value instanceof actual.ApiError) return Promise.reject(value);
    return Promise.resolve(value);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => { sent.push({ path, body }); return Promise.resolve(planned); },
    },
  };
});

const user = (over: Record<string, unknown> = {}) => ({
  uid: "alice", first_name: "Alice", last_name: "Nowak", uid_number: "1001", gid_number: "1001",
  shell: "/bin/bash", home_directory: "/home/alice", groups: ["ops"], disabled: false,
  ssh_key_fingerprints: ["SHA256:aaa"], ...over,
});

const status = {
  configured: true, reachable: true, principal: "flotestro/panel@EXAMPLE.TEST",
  summary: "IPA example.test",
  connector: {
    principal: "flotestro/panel@EXAMPLE.TEST", keytab_readable: true,
    keytab_entries: [{ principal: "flotestro/panel@EXAMPLE.TEST", kvno: 3, timestamp: "2026-10-01T00:00:00Z" }],
    last_success_at: "2026-10-16T09:00:00Z", cache_entries: 12, cache_ttl_seconds: 60,
  },
  hosts: {
    offline_count: 2,
    by_verdict: { no_cached_logins: 1, cached_logins_until: 1 },
    offline_from_directory: [
      {
        id: "h1", hostname: "web1", site: "lab", environment: "test", checked_at: "2026-10-16T08:00:00Z",
        offline_verdict: { verdict: "no_cached_logins", reason: "SSSD caches nothing" },
      },
    ],
  },
};

/** The answers every tab leans on; a test adds or overrides what it needs. */
function baseAnswers() {
  return {
    "/api/v1/identity/status": status,
    "/api/v1/identity/users": { items: [user({})], count: 1 },
    "/api/v1/identity/users?preserved=true": { items: [], count: 0 },
    "/api/v1/identity/changes?limit=20": { items: [], count: 0 },
    "/api/v1/identity/groups": { items: [], count: 0 },
    "/api/v1/identity/hbac-rules": { items: [], count: 0 },
    "/api/v1/identity/sudo-rules": { items: [], count: 0 },
    "/api/v1/identity/hosts": { items: [], count: 0 },
    "/api/v1/identity/host-groups": { items: [], count: 0 },
    "/api/v1/identity/services": { items: [], count: 0 },
    "/api/v1/identity/dns/zones": { items: [], count: 0 },
    "/api/v1/identity/dns/records": { items: [], count: 0 },
    "/api/v1/hosts": { items: [], count: 0 },
    "/api/v1/whoami": { permissions: [] },
  };
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Directory />, { wrapper });
}

/** Opens one of the screen's own tabs by the name an operator reads. */
const open = (name: string) => fireEvent.click(screen.getByRole("tab", { name }));

const type = (testId: string, value: string) =>
  fireEvent.change(screen.getByTestId(testId), { target: { value } });

beforeEach(() => {
  for (const key of Object.keys(answers)) delete answers[key];
  Object.assign(answers, baseAnswers());
  planned = { id: "c0ffee1234", action_type: "identity.user.disable", state: "awaiting_approval" };
});

afterEach(() => { cleanup(); asked.length = 0; sent.length = 0; });

describe("the accounts of the directory", () => {
  it("reads the live accounts and the preserved ones from two different addresses", async () => {
    answers["/api/v1/identity/users?preserved=true"] = { items: [user({ uid: "bob", disabled: true })], count: 1 };
    draw();
    await waitFor(() => expect(screen.getByTestId("account-alice")).toBeInTheDocument());
    // The preserved entry is not counted as a user, and the live list does
    // not borrow the preserved answer.
    expect(screen.getByTestId("kpi-accounts")).toHaveTextContent("1");
    expect(screen.getByTestId("kpi-preserved")).toHaveTextContent("1");
    expect(screen.getByTestId("preserved-bob")).toBeInTheDocument();
    expect(screen.queryByTestId("account-bob")).toBeNull();
  });

  it("says a directory that listed no fingerprints is unknown, and never nought", async () => {
    answers["/api/v1/identity/users"] = { items: [user({ uid: "silent", ssh_key_fingerprints: undefined })], count: 1 };
    draw();
    await waitFor(() => expect(screen.getByTestId("account-silent")).toBeInTheDocument());
    const row = screen.getByTestId("account-silent");
    expect(row).toHaveTextContent("—");
    expect(within(row).queryByText("0")).toBeNull();
  });

  it("opens the one account that was picked, and nothing until one is", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-alice")).toBeInTheDocument());
    expect(screen.queryByTestId("act-lock")).toBeNull();
    fireEvent.click(screen.getByTestId("pick-alice"));
    expect(screen.getByTestId("act-lock")).toHaveTextContent("Lock…");
    expect(screen.getByText("/home/alice")).toBeInTheDocument();
  });

  it("refuses to order a lock until the reason is long enough, then sends it as a change", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-alice")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-alice"));
    fireEvent.click(screen.getByTestId("act-lock"));
    expect(screen.getByTestId("plan-lock")).toBeDisabled();
    type("lock-reason", "short");
    expect(screen.getByTestId("plan-lock")).toBeDisabled();
    type("lock-reason", "leaving the company");
    fireEvent.click(screen.getByTestId("plan-lock"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/identity/changes");
    expect(sent[0].body).toEqual({
      action: "identity.user.disable",
      reason: "leaving the company",
      payload: { reference: { uid: "alice", reason: "leaving the company" } },
    });
  });

  it("draws the plan's impact and its conflicts, which is why a change is planned at all", async () => {
    planned = {
      id: "abcdef1234", action_type: "identity.user.disable", state: "blocked",
      plan: {
        summary: "Lock alice",
        steps: ["end the panel sessions", "disable in the directory"],
        reachable_hosts: ["web1.example.test", "web2.example.test"],
        affected_users: ["alice"],
        conflicts: ["alice holds the only sudo rule for web1"],
      },
    };
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-alice")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-alice"));
    fireEvent.click(screen.getByTestId("act-lock"));
    type("lock-reason", "leaving the company");
    fireEvent.click(screen.getByTestId("plan-lock"));
    await waitFor(() => expect(screen.getByText("Lock alice")).toBeInTheDocument());
    expect(screen.getByText("alice holds the only sudo rule for web1")).toBeInTheDocument();
    expect(screen.getByText("Hosts reached (2)")).toBeInTheDocument();
    expect(screen.getByText("web2.example.test")).toBeInTheDocument();
  });

  it("will not preserve an account until its name is typed back", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-alice")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-alice"));
    fireEvent.click(screen.getByTestId("act-preserve"));
    type("confirm-reason", "the person has left");
    expect(screen.getByTestId("confirm")).toBeDisabled();
    type("confirm-target", "alicia");
    expect(screen.getByTestId("confirm")).toBeDisabled();
    type("confirm-target", "alice");
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect((sent[0].body as { action: string }).action).toBe("identity.user.preserve");
  });

  it("offers the one-time password only where one is waiting, and asks why it is read", async () => {
    answers["/api/v1/identity/changes?limit=20"] = {
      count: 2,
      items: [
        { id: "reset1234", action_type: "identity.user.password.reset", state: "succeeded", secret_available: true, created_at: "2026-10-16T09:00:00Z" },
        { id: "other1234", action_type: "identity.user.disable", state: "succeeded", created_at: "2026-10-16T08:00:00Z" },
      ],
    };
    planned = { uid: "alice", one_time_password: "correct-horse", expires_on_first_login: true };
    draw();
    await waitFor(() => expect(screen.getByTestId("change-reset1234")).toBeInTheDocument());
    expect(within(screen.getByTestId("change-other1234")).queryByRole("button")).toBeNull();
    fireEvent.click(screen.getByTestId("reveal-reset1234"));
    expect(screen.getByTestId("reveal-confirm")).toBeDisabled();
    type("reveal-reason", "handing it to the owner");
    fireEvent.click(screen.getByTestId("reveal-confirm"));
    await waitFor(() => expect(screen.getByTestId("one-time-password")).toHaveTextContent("correct-horse"));
    expect(sent[0].path).toBe("/api/v1/identity/changes/reset1234/reveal");
  });

  it("says the read was refused rather than drawing a directory with no accounts", async () => {
    answers["/api/v1/identity/users"] = new ApiError(403, "forbidden", "not for you");
    draw();
    await waitFor(() => expect(screen.getByText(/do not have permission/)).toBeInTheDocument());
    expect(screen.queryByTestId("accounts")).toBeNull();
  });
});

describe("the rules", () => {
  it("marks a rule that is narrowed by nothing, and counts those apart", async () => {
    answers["/api/v1/identity/hbac-rules"] = {
      count: 2,
      items: [
        { name: "everywhere", enabled: true, allows_everything: true, all_users: true, all_hosts: true, all_services: true },
        { name: "ops-ssh", enabled: true, allows_everything: false, all_users: false, all_hosts: false, all_services: false, users: ["alice"], hosts: ["web1"], services: ["sshd"] },
      ],
    };
    draw();
    open("HBAC rules");
    await waitFor(() => expect(screen.getByTestId("hbac-everywhere")).toBeInTheDocument());
    expect(screen.getByTestId("hbac-everywhere")).toHaveTextContent("covers the whole fleet");
    expect(screen.getByTestId("hbac-ops-ssh")).toHaveTextContent("narrowed");
    expect(screen.getByTestId("kpi-hbac-wide")).toHaveTextContent("1");
  });

  it("declares an HBAC rule as a whole, with the lists split on the commas", async () => {
    draw();
    open("HBAC rules");
    await waitFor(() => expect(screen.getByTestId("new-hbac")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-hbac"));
    type("hbac-name", "ops-ssh");
    expect(screen.getByTestId("plan-hbac")).toBeDisabled();
    type("hbac-reason", "the operations team needs shell access");
    fireEvent.click(screen.getByTestId("plan-hbac"));
    await waitFor(() => expect(sent).toHaveLength(1));
    const body = sent[0].body as { action: string; payload: { hbac_rule: { name: string; services: string[] } } };
    expect(body.action).toBe("identity.hbac.rule.ensure");
    expect(body.payload.hbac_rule.name).toBe("ops-ssh");
    expect(body.payload.hbac_rule.services).toEqual(["sshd"]);
  });

  it("plans the removal of a sudo rule it was opened on, by that rule's name", async () => {
    answers["/api/v1/identity/sudo-rules"] = {
      count: 1,
      items: [{
        name: "ops-restart", enabled: true, critical: true, critical_reasons: ["runs as root"],
        all_users: false, all_hosts: false, all_commands: false, run_as_any_user: false,
        users: ["alice"], commands: ["/usr/bin/systemctl"], run_as: ["root"],
      }],
    };
    draw();
    open("sudo rules");
    await waitFor(() => expect(screen.getByTestId("sudo-ops-restart")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-sudo-critical")).toHaveTextContent("1");
    fireEvent.click(screen.getByTestId("edit-sudo-ops-restart"));
    type("sudo-reason", "the rule is no longer needed");
    fireEvent.click(screen.getByTestId("plan-sudo-removal"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "identity.sudo.rule.remove",
      reason: "the rule is no longer needed",
      payload: { sudo_rule: { name: "ops-restart" } },
    });
  });

  it("asks the directory itself whether access is allowed, and shows its verdict", async () => {
    planned = { user: "alice", host: "web1", service: "sshd", allowed: false, matched: [], not_matched: ["ops-ssh"] };
    draw();
    open("HBAC rules");
    await waitFor(() => expect(screen.getByTestId("simulate")).toBeInTheDocument());
    expect(screen.getByTestId("simulate")).toBeDisabled();
    type("simulate-user", "alice");
    type("simulate-host", "web1");
    fireEvent.click(screen.getByTestId("simulate"));
    await waitFor(() => expect(screen.getByText("denied")).toBeInTheDocument());
    expect(sent[0].path).toBe("/api/v1/identity/access/simulate");
    expect(sent[0].body).toEqual({ user: "alice", host: "web1", service: "sshd" });
  });
});

describe("the host entries and the groups", () => {
  it("links a directory entry to the fleet host of the same name, inside the new panel", async () => {
    answers["/api/v1/identity/hosts"] = {
      count: 2,
      items: [
        { fqdn: "web1.example.test", enrolled: true, enrolled_at: "20261001000000Z", member_of: ["web"] },
        { fqdn: "orphan.example.test", enrolled: false },
      ],
    };
    answers["/api/v1/hosts"] = {
      count: 1,
      items: [{ id: "h1", hostname: "web1", identity: { domain: "example.test" } }],
    };
    draw();
    open("Hosts");
    await waitFor(() => expect(screen.getByTestId("entry-web1.example.test")).toBeInTheDocument());
    const linked = screen.getByTestId("entry-web1.example.test");
    expect(within(linked).getByRole("link", { name: "web1" })).toHaveAttribute("href", "/hosts/h1");
    expect(within(linked).getByRole("link", { name: "Join" })).toHaveAttribute("href", "/hosts/h1/identity");
    // A name the fleet does not carry is said plainly, and offers no join.
    const orphan = screen.getByTestId("entry-orphan.example.test");
    expect(orphan).toHaveTextContent("not in the fleet");
    expect(within(orphan).queryByRole("link")).toBeNull();
  });

  it("narrows the host entries in the browser, over what the directory answered", async () => {
    answers["/api/v1/identity/hosts"] = {
      count: 2,
      items: [{ fqdn: "web1.example.test", enrolled: true }, { fqdn: "db1.example.test", enrolled: true }],
    };
    draw();
    open("Hosts");
    await waitFor(() => expect(screen.getByTestId("entry-db1.example.test")).toBeInTheDocument());
    type("host-filter", "web");
    expect(screen.queryByTestId("entry-db1.example.test")).toBeNull();
    expect(screen.getByTestId("entry-web1.example.test")).toBeInTheDocument();
  });

  it("sends a host group membership change as an add and a remove, not as a whole list", async () => {
    answers["/api/v1/identity/host-groups"] = {
      count: 1,
      items: [{ name: "web", hosts: ["web1.example.test"] }],
    };
    draw();
    open("Host groups");
    await waitFor(() => expect(screen.getByTestId("hostgroup-web")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-hostgroup-web"));
    type("hostgroup-add", "web2.example.test, web3.example.test");
    type("hostgroup-reason", "two new machines for the web tier");
    fireEvent.click(screen.getByTestId("plan-host-members"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "identity.hostgroup.members",
      reason: "two new machines for the web tier",
      payload: { host_group: { group: "web", add: ["web2.example.test", "web3.example.test"], remove: [] } },
    });
  });
});

describe("the keys, the services and the zones", () => {
  it("warns that an empty list takes every key away, and still lets it be planned", async () => {
    draw();
    open("SSH keys");
    await waitFor(() => expect(screen.getByTestId("withkeys-alice")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("setkeys-alice"));
    expect(screen.getByText(/removes every key of the account/)).toBeInTheDocument();
    expect(screen.getByTestId("plan-keys")).toHaveTextContent("Plan removal of every key");
    type("keys-reason", "the laptop was lost");
    fireEvent.click(screen.getByTestId("plan-keys"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "identity.sshkeys.set",
      reason: "the laptop was lost",
      payload: { ssh_keys: { uid: "alice", keys: [] } },
    });
  });

  it("offers a keytab rotation only to somebody who may rotate one", async () => {
    answers["/api/v1/identity/services"] = {
      count: 2,
      items: [
        { principal: "HTTP/web1.example.test@EXAMPLE.TEST", service: "HTTP", host: "web1.example.test", has_keytab: true },
        { principal: "host/web1.example.test@EXAMPLE.TEST", service: "host", host: "web1.example.test", has_keytab: null },
      ],
    };
    draw();
    open("Services");
    await waitFor(() => expect(screen.getByTestId("service-HTTP/web1.example.test@EXAMPLE.TEST")).toBeInTheDocument());
    // No permission: the column is not drawn at all, because a button the
    // server would refuse is a promise the page cannot keep.
    expect(screen.queryByTestId("rotate-HTTP/web1.example.test@EXAMPLE.TEST")).toBeNull();
    // A keytab the directory said nothing about is unknown, not "none".
    expect(screen.getByTestId("service-host/web1.example.test@EXAMPLE.TEST")).toHaveTextContent("unknown");
    cleanup();

    answers["/api/v1/whoami"] = { permissions: ["identity.keytab.rotate"] };
    draw();
    open("Services");
    await waitFor(() => expect(screen.getByTestId("rotate-HTTP/web1.example.test@EXAMPLE.TEST")).toBeInTheDocument());
    // The host's own keytab is replaced by a re-join, never rotated here.
    expect(screen.queryByTestId("rotate-host/web1.example.test@EXAMPLE.TEST")).toBeNull();
  });

  it("reads the records of the zone that was chosen, not of the first one", async () => {
    answers["/api/v1/identity/dns/zones"] = {
      count: 2,
      items: [{ name: "example.test", reverse: false }, { name: "56.168.192.in-addr.arpa", reverse: true }],
    };
    answers["/api/v1/identity/dns/records"] = { count: 0, items: [] };
    draw();
    open("DNS");
    await waitFor(() => expect(screen.getByTestId("zone")).toBeInTheDocument());
    await waitFor(() => expect(asked.some((one) => one.includes("zone=example.test"))).toBe(true));
    fireEvent.change(screen.getByTestId("zone"), { target: { value: "56.168.192.in-addr.arpa" } });
    await waitFor(() => expect(asked.some((one) => one.includes("zone=56.168.192.in-addr.arpa"))).toBe(true));
  });

  it("plans a record and its reverse together, because forgetting it is the usual mistake", async () => {
    answers["/api/v1/identity/dns/zones"] = { count: 1, items: [{ name: "example.test", reverse: false }] };
    planned = { id: "dns1234", action_type: "dns.record.ensure", state: "awaiting_approval" };
    draw();
    open("DNS");
    await waitFor(() => expect(screen.getByTestId("record-name")).toBeInTheDocument());
    expect(screen.getByTestId("plan-record")).toBeDisabled();
    type("record-name", "web3");
    type("record-value", "192.168.56.80");
    fireEvent.click(screen.getByTestId("plan-record"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "dns.record.ensure",
      payload: { dns: { zone: "example.test", name: "web3", type: "A", value: "192.168.56.80", ttl: 0, reverse: true } },
    });
  });
});

describe("the health of the integration", () => {
  it("keeps the connector and the hosts apart, and judges each on its own", async () => {
    draw();
    open("Integration health");
    await waitFor(() => expect(screen.getByTestId("offline-web1")).toBeInTheDocument());
    // The connector names its principal, and so does the keytab the panel
    // reads for itself: two halves, two statements of the same name.
    expect(screen.getAllByText("flotestro/panel@EXAMPLE.TEST", { selector: "code" })).toHaveLength(2);
    expect(screen.getByTestId("keytab")).toHaveTextContent("3");
    const row = screen.getByTestId("offline-web1");
    expect(row).toHaveTextContent("no cached logins");
    expect(row).toHaveTextContent("SSSD caches nothing");
    expect(within(row).getByRole("link", { name: "web1" })).toHaveAttribute("href", "/hosts/h1/identity");
  });

  it("says plainly when no connector is configured rather than reading it as unreachable", async () => {
    answers["/api/v1/identity/status"] = { configured: false };
    draw();
    await waitFor(() => expect(screen.getAllByText(/No directory connector is configured/).length).toBeGreaterThan(0));
  });
});

describe("the words the screen puts on what it read", () => {
  it("names a change by what it does, and an unknown action by its own identifier", () => {
    expect(actionName("identity.user.preserve")).toBe("Preserve an account");
    expect(actionName("identity.user.teleport")).toBe("identity.user.teleport");
  });

  it("reads a change nobody has approved as waiting, not as wrong", () => {
    expect(changeTone("awaiting_approval")).toBe("info");
    expect(changeTone("succeeded")).toBe("ok");
    expect(changeTone("failed")).toBe("error");
    expect(changeTone("partially_applied")).toBe("warn");
  });

  it("splits a typed list on the commas and the newlines, and drops the blanks", () => {
    expect(names("alice, bob ,, carol")).toEqual(["alice", "bob", "carol"]);
    expect(lines("one\n\n  two  \n")).toEqual(["one", "two"]);
  });

  it("reads a host nobody judged as unknown and one that cannot log in at all as a fault", () => {
    const t = (text: string) => text;
    expect(verdictTone("unknown")).toBe("unknown");
    expect(verdictTone("no_cached_logins")).toBe("error");
    expect(verdictTone("cached_logins_until")).toBe("warn");
    expect(verdictLabel("cached_logins_indefinitely", t)).toBe("cached logins indefinitely");
    expect(verdictLabel("something_new", t)).toBe("something_new");
  });
});
