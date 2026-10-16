import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Security } from "./Security";
import type { Host } from "../../../lib/types";

/**
 * The module judges facts the host reported. What is tested is the line it
 * must never cross: a check nobody could judge is unknown and is never
 * counted as a pass, a fix is ordered only with a reason and the host's
 * name typed out, and a control the host refuses is not on the screen.
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
        // The longest match wins: `/api/v1/hosts/h1/security` is a prefix of
        // `/api/v1/hosts/h1/security/remediation`, and answering the second
        // with the first hands the screen a report where its plans go.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        if (path.endsWith("/security/remediation")) {
          return Promise.resolve({ plan: { id: "plan-0123456789", state: "running" }, skipped: {} });
        }
        return Promise.resolve({ id: "job-01234567", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Record<string, unknown> = {}): Host => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [
    { name: "security.mac", available: true, read_only: false },
    { name: "security.audit", available: true, read_only: false },
  ],
  identity: { enrolled: false, sssd_online: null },
  ...over,
} as unknown as Host);

const finding = (over: Record<string, unknown> = {}) => ({
  check_id: "selinux.enforcing", check_version: 2, title: "SELinux enforces its policy",
  severity: "high", rationale: "a permissive host only logs what it would have stopped",
  applicable: true, passed: false, unknown: false,
  expected: "enforcing", observed: "permissive", module: "security", revision: "abcdef1234567890",
  observed_at: "2026-10-16T08:00:00Z",
  remediation: { action: "selinux.mode.set" },
  ...over,
});

const snapshot = (over: Record<string, unknown> = {}) => ({
  source: "agent", revision: "abcdef123456", observed_at: "2026-10-16T08:00:00Z",
  payload: {
    mac: { system: "selinux", mode: "permissive", configured_mode: "enforcing" },
    audit: { present: true, active: true, rules_loaded: 42, rules_configured: 50 },
    secure_boot: null, fips_enabled: false, lockdown: "none",
    listening_known: true, owners_known: false,
    listening: [
      { protocol: "tcp", address: "0.0.0.0", port: 22, reach: "all-interfaces" },
      { protocol: "tcp", address: "127.0.0.1", port: 5432, reach: "loopback", process: "postgres" },
    ],
    ...over,
  },
});

/** Every change of this module allowed, as the host's preview answers it. */
const allowed = {
  version: 1,
  items: ["security.scan", "security.remediate", "selinux.mode.set", "security.audit.reload"]
    .map((action) => ({ action, permission: "security.write", mutating: true, risk: "critical", allowed: true })),
};

function draw(one: Host = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Security host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("a host's security", () => {
  it("counts a check nobody could judge as unknown, and never as a pass", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [finding({ check_id: "audit.rules", unknown: true, reason_code: "fact_missing", observed: "—", remediation: {} })],
        plan_hash: "0123456789abcdef", plan_hash_version: 1, generated_at: "2026-10-16T08:00:00Z",
        counts: { failed: 0, passed: 3, unknown: 1, not_applicable: 2 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const row = await screen.findByTestId("finding-audit.rules");
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    // The code says which side has to move, in words rather than in a code.
    expect(row).toHaveTextContent("the host did not report this fact");
    // A finding without an operation behind it cannot be ticked for a fix.
    expect(within(row).getByRole("checkbox")).toBeDisabled();
  });

  it("shows dashes, not noughts, while the report has not been computed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": new Error("still computing"),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const counts = await screen.findByTestId("check-counts");
    await waitFor(() => expect(counts).toHaveTextContent("—"));
    expect(counts).toHaveTextContent("need action: not counted");
  });

  it("orders a fix only with a reason and the hostname typed out", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [finding({})],
        plan_hash: "0123456789abcdef", plan_hash_version: 1, generated_at: "2026-10-16T08:00:00Z",
        counts: { failed: 1, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const row = await screen.findByTestId("finding-selinux.enforcing");
    fireEvent.click(within(row).getByRole("checkbox"));
    fireEvent.click(screen.getByTestId("fix-selected"));
    const confirm = screen.getByTestId("confirm-remediate");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-remediate-reason"), { target: { value: "hardening sweep" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-remediate-typed"), { target: { value: "agent-arch" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/security/remediation");
    // The request is bound to the set of findings on screen: the fingerprint
    // goes with it, and a host that changed meanwhile is refused.
    expect(posted[0].body).toMatchObject({
      plan_hash: "0123456789abcdef", check_ids: ["selinux.enforcing"], reason: "hardening sweep",
    });
  });

  it("moves SELinux between its two modes and says what that means", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [], plan_hash: "0123456789abcdef", plan_hash_version: 1,
        generated_at: "2026-10-16T08:00:00Z", counts: { failed: 0, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("selinux-mode"));
    expect(screen.getByText(/starts enforcing its policy now and after reboot/)).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("confirm-operation-reason"), { target: { value: "back to enforcing" } });
    fireEvent.change(screen.getByTestId("confirm-operation-typed"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-operation"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "selinux.mode.set", reason: "back to enforcing", payload: { security: { mode: "enforcing" } },
    });
  });

  it("says a host that did not report its sockets reported none of them", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot({ listening_known: false, listening: [] }),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [], plan_hash: "0123456789abcdef", plan_hash_version: 1,
        generated_at: "2026-10-16T08:00:00Z", counts: { failed: 0, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    await waitFor(() => expect(screen.getAllByText("This host did not report its listening sockets.").length).toBeGreaterThan(0));
    expect(screen.queryByTestId("sockets")).toBeNull();
  });

  it("names the reach of every socket, the ones beyond the loopback first", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [], plan_hash: "0123456789abcdef", plan_hash_version: 1,
        generated_at: "2026-10-16T08:00:00Z", counts: { failed: 0, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const table = await screen.findByTestId("sockets");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("22");
    expect(rows[0]).toHaveTextContent("every interface");
    // Without root the list is complete but nameless, and the screen says so
    // rather than leaving the cell blank.
    expect(rows[0]).toHaveTextContent("not readable");
  });

  it("keeps the scan and the fix off the screen where the host refuses them", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [finding({})], plan_hash: "0123456789abcdef", plan_hash_version: 1,
        generated_at: "2026-10-16T08:00:00Z", counts: { failed: 1, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": {
        version: 1,
        items: ["security.scan", "security.remediate", "selinux.mode.set", "security.audit.reload"].map((action) => ({
          action, permission: "security.write", mutating: true, risk: "critical",
          allowed: false, reason_code: "permission_denied", missing_permission: "security.write",
          reason: "you lack security.write",
        })),
      },
    });
    draw();
    await screen.findByTestId("finding-selinux.enforcing");
    expect(screen.queryByTestId("fix-selected")).toBeNull();
    expect(screen.queryByTestId("selinux-mode")).toBeNull();
    // The scan asks to be explained rather than vanishing: it is the one
    // action a reader would otherwise go looking for.
    expect(screen.getAllByText("you lack security.write").length).toBeGreaterThan(0);
    expect(await screen.findByText(/You can read this module/)).toBeInTheDocument();
  });

  it("warns that sudo loads nothing when the host's own checker refuses the files", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [] },
      "/api/v1/hosts/h1/security": {
        findings: [finding({
          check_id: "sudo.syntax_valid", title: "sudoers parses", observed: "visudo refuses /etc/sudoers.d/ops",
          remediation: {},
        })],
        plan_hash: "0123456789abcdef", plan_hash_version: 1, generated_at: "2026-10-16T08:00:00Z",
        counts: { failed: 1, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    expect(await screen.findByText(/sudo loads none of them/)).toBeInTheDocument();
  });

  it("stops a running plan, and offers the stop only while one runs", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/security": snapshot(),
      "/api/v1/hosts/h1/security/remediation": { items: [{
        id: "plan-0123456789", plan_hash: "0123456789abcdef", reason: "hardening", created_by: "tester",
        stop_on_failure: true, state: "running", created_at: "2026-10-16T08:00:00Z",
        steps: [{ position: 1, check_id: "selinux.enforcing", action_type: "selinux.mode.set", requires_reboot: false, state: "running" }],
      }] },
      "/api/v1/hosts/h1/security": {
        findings: [], plan_hash: "0123456789abcdef", plan_hash_version: 1,
        generated_at: "2026-10-16T08:00:00Z", counts: { failed: 0, passed: 0, unknown: 0, not_applicable: 0 },
      },
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("stop-plan-0123456789"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/security/remediation/plan-0123456789/stop");
  });
});
