import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Backups, backupTone, definitionRequest, size } from "./Backups";
import type { Host } from "../../../lib/types";

/**
 * A backup module answers two questions and nothing else matters as much:
 * is the last copy recent, and has anybody ever read one back. The second
 * is the one this product refuses to round off - a copy nobody verified is
 * not a copy that failed verification, and a repository nobody measured is
 * not a repository of nought bytes.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const deleted: string[] = [];
const answers: Record<string, unknown> = {};
let postResult: unknown = { id: "0123456789abcdef", requires_approval: false };

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest match wins: `/api/v1/hosts/h1/backups` is a prefix of
  // `/api/v1/hosts/h1/backups/runs`, and answering the second with the
  // first hands the screen the wrong document.
  const reply = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const answer = answers[key];
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => { asked.push(path); return reply(path); },
      post: (path: string, body?: unknown) => { posted.push({ path, body }); return Promise.resolve(postResult); },
      put: () => Promise.resolve({}),
      del: (path: string) => { deleted.push(path); return Promise.resolve(undefined); },
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  enrolled_at: "2026-10-01T00:00:00Z",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, capabilities: [], identity: {},
} as unknown as Host;

const actions = (over: Record<string, { allowed: boolean; reason?: string; missing?: string }> = {}) => ({
  version: 1,
  items: ["backup.run", "backup.verify", "backup.restore", "backup.plan"].map((action) => ({
    action,
    permission: action,
    mutating: true,
    risk: "normal",
    allowed: over[action]?.allowed ?? true,
    reason: over[action]?.reason,
    reason_code: over[action] && !over[action].allowed ? "permission_denied" : undefined,
    missing_permission: over[action]?.missing,
  })),
});

const definition = (over: Record<string, unknown> = {}) => ({
  id: "d1",
  name: "nightly",
  tool: "restic",
  repository: "/srv/backup",
  paths: ["/etc", "/srv"],
  keep_last: 7,
  password_secret: "backup.password",
  updated_by: "ulther",
  updated_at: "2026-10-01T00:00:00Z",
  status: "ok",
  age_hours: 9,
  last_success_at: "2026-10-16T00:00:00Z",
  unverified: true,
  ...over,
});

const report = (over: Record<string, unknown> = {}) => ({
  host_id: "h1",
  definitions: [definition()],
  status: "ok",
  tools: { tools: [{ name: "restic", available: true, version: "restic 0.17.0" }], runbooks: [], runbooks_known: true },
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Backups host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  deleted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  postResult = { id: "0123456789abcdef", requires_approval: false };
});

describe("what the module reads", () => {
  it("gives a size nobody reported back as unknown, never as nought bytes", () => {
    expect(size(undefined)).toBeUndefined();
    expect(size(0)).toBe("0 B");
    expect(size(1536)).toBe("1.5 KiB");
  });

  it("calls a state nobody could judge unknown, and anything else wrong", () => {
    expect(backupTone("ok")).toBe("ok");
    expect(backupTone("warning")).toBe("warn");
    expect(backupTone("unknown")).toBe("unknown");
    expect(backupTone("never")).toBe("error");
  });

  it("writes the whole definition back, so a field the form never showed survives", () => {
    const body = definitionRequest(
      definition({ env_secrets: { AWS_SECRET_ACCESS_KEY: "s3.key" }, prune: true }) as never,
      "hash-1",
      { read_data: true },
    );
    expect(body).toMatchObject({
      id: "nightly",
      plan_hash: "hash-1",
      tool: "restic",
      repository: "/srv/backup",
      paths: ["/etc", "/srv"],
      keep_last: 7,
      prune: true,
      password_secret: { name: "backup.password" },
      env_secrets: { AWS_SECRET_ACCESS_KEY: { name: "s3.key" } },
      read_data: true,
    });
    // A retention the definition never carried is nought, which is what the
    // server reads as "this rule does not apply".
    expect(body.keep_monthly).toBe(0);
  });
});

describe("the backups of a host", () => {
  it("draws a definition with the age of its last copy and where it goes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("definition-nightly");
    expect(row).toHaveTextContent("9 h old");
    expect(row).toHaveTextContent("/srv/backup");
    expect(row).toHaveTextContent("password from backup.password");
  });

  it("says a copy nobody has read back is not verified, and not a failed check", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("definition-nightly");
    expect(within(row).getByText("not verified")).toBeInTheDocument();
    expect(within(row).queryByText("failed")).toBeNull();
  });

  it("says a repository nobody measured is a dash, never nought bytes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report({
        definitions: [definition({ repository_size: undefined, snapshots: undefined })],
      }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("definition-nightly");
    expect(row).toHaveTextContent("—");
    expect(within(row).queryByText("0 B")).toBeNull();
  });

  it("says the host has nothing backed up yet, and offers the way to define one", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report({ definitions: [] }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText(/The panel does not back up anything on this host yet/)).toBeInTheDocument());
  });

  it("names the tools the host has, and the ones it has not", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report({
        tools: { tools: [{ name: "restic", available: true, version: "restic 0.17.0" }, { name: "borg", available: false }] },
      }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/restic · restic 0.17.0/)).toBeInTheDocument());
    expect(screen.getByText(/borg · not installed/)).toBeInTheDocument();
  });
});

describe("what the module does", () => {
  it("asks the host for the plan of a copy, not only for the state of the repository", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("plan-nightly"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "backup.plan",
      payload: { backup: { id: "nightly", plan: "run", plan_hash: "" } },
    });
  });

  it("runs a backup only after a reason and the machine's own name", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("run-nightly"));
    const confirm = screen.getByTestId("confirm-order");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "before the upgrade" } });
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "backup.run",
      reason: "before the upgrade",
      payload: { backup: { id: "nightly" } },
    });
  });

  it("verifies by reading the data back, which is the only check that proves anything", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("verify-nightly"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "quarterly check" } });
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "backup.verify",
      payload: { backup: { read_data: true } },
    });
  });

  it("saves a definition the operator typed, with the retention as numbers", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report({ definitions: [] }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("definition-open"));
    fireEvent.change(await screen.findByTestId("definition-name"), { target: { value: "weekly" } });
    fireEvent.change(screen.getByTestId("definition-repository"), { target: { value: "/srv/weekly" } });
    fireEvent.change(screen.getByTestId("definition-paths"), { target: { value: "/etc /var/lib/app" } });
    fireEvent.click(screen.getByTestId("definition-save"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/backups");
    expect(posted[0].body).toMatchObject({
      name: "weekly",
      tool: "restic",
      repository: "/srv/weekly",
      paths: ["/etc", "/var/lib/app"],
      keep_last: 7,
      initialize: true,
    });
  });

  it("asks before it forgets a definition, and says the repository is untouched", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("forget-nightly"));
    expect(screen.getByText(/Nothing is deleted from the repository/)).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "the host is leaving" } });
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(deleted).toHaveLength(1));
    expect(deleted[0]).toContain("name=nightly");
    expect(deleted[0]).toContain("reason=the%20host%20is%20leaving");
  });

  it("reads the run history of the definition the operator opened, and of no other", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/backups/runs": { items: [
        { definition: "nightly", kind: "run", outcome: "succeeded", snapshot_id: "9f2c", bytes_added: 2048, started_by: "ulther", recorded_at: "2026-10-16T00:00:00Z" },
      ] },
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("definition-nightly");
    fireEvent.click(within(row).getByRole("button", { name: "nightly" }));
    const runs = await screen.findByTestId("runs");
    expect(runs).toHaveTextContent("succeeded");
    expect(runs).toHaveTextContent("2.0 KiB");
    expect(asked.some((one) => one.startsWith("/api/v1/hosts/h1/backups/runs?definition=nightly"))).toBe(true);
  });
});

describe("the repository and the restore", () => {
  /** A planning job that answered with the repository and its copies. */
  const planned = {
    items: [{
      status: "succeeded",
      detail: {
        kind: "backup_plan",
        plan: { plan_hash: "hash-7" },
        state: {
          tool: "restic",
          tool_version: "restic 0.17.0",
          snapshots: [{ id: "9f2c", time: "2026-10-15T00:00:00Z", paths: ["/etc"] }],
        },
      },
    }],
  };

  it("restores into a directory the operator names, against the plan it read", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
      "/api/v1/jobs/0123456789abcdef/attempts": planned,
    });
    draw();
    // The copies come from the plan the host answered with, and the plan
    // belongs to the definition it was read for.
    const row = await screen.findByTestId("definition-nightly");
    fireEvent.click(within(row).getByRole("button", { name: "nightly" }));
    fireEvent.click(screen.getByTestId("plan-nightly"));
    const copies = await screen.findByTestId("snapshot-9f2c");
    expect(copies).toHaveTextContent("9f2c");

    fireEvent.click(screen.getByTestId("restore-9f2c"));
    const target = screen.getByTestId("restore-target");
    expect(target).toHaveValue("/srv/flotestro-restore");
    fireEvent.change(target, { target: { value: "/srv/check" } });
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "proving the copy" } });
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));

    await waitFor(() => expect(posted).toHaveLength(2));
    expect(posted[1].body).toMatchObject({
      action: "backup.restore",
      reason: "proving the copy",
      payload: {
        backup: {
          id: "nightly",
          plan_hash: "hash-7",
          snapshot_id: "9f2c",
          overwrite: "empty-target",
          target: "/srv/check",
        },
      },
    });
  });

  it("says why the repository could not be read rather than showing no copies", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions(),
      "/api/v1/jobs/0123456789abcdef/attempts": {
        items: [{ status: "succeeded", detail: { state: { unavailable_reason: "wrong password" } } }],
      },
    });
    draw();
    fireEvent.click(await screen.findByTestId("plan-nightly"));
    await waitFor(() =>
      expect(screen.getByText(/The repository could not be read: wrong password/)).toBeInTheDocument());
  });
});

describe("what the server refuses", () => {
  it("does not draw an order the server would not take", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions({ "backup.run": { allowed: false, missing: "backup.run" } }),
    });
    draw();
    await screen.findByTestId("definition-nightly");
    await waitFor(() => expect(screen.queryByTestId("run-nightly")).toBeNull());
    // The others are untouched: one refusal is not a read-only module.
    expect(screen.getByTestId("verify-nightly")).toBeInTheDocument();
  });

  it("says once that the module can be read but not changed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/backups": report(),
      "/api/v1/hosts/h1/actions": actions({
        "backup.run": { allowed: false, missing: "backup.run" },
        "backup.verify": { allowed: false, missing: "backup.verify" },
        "backup.restore": { allowed: false, missing: "backup.restore" },
      }),
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText(/You can read this module; changing it needs the permission/)).toBeInTheDocument());
  });
});
