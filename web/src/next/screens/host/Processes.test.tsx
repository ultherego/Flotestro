import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Processes, agentProcess, processTone, treeRows, type Process } from "./Processes";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";

/**
 * A snapshot of the host's processes, and what may be done to one.
 *
 * The signal is the whole point of the screen's care: a PID on its own is
 * not an identity, so the order carries the start time the process was
 * seen with, and the question is asked before anything is sent.
 */

const answers: Record<string, unknown> = {};
const sent: { path: string; body: unknown }[] = [];

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it; a short key
  // answering a longer path hands the screen the wrong document.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
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
        return Promise.resolve({ id: "job-01234567", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Partial<Host> = {}): Host => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as Host);

const allow = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.operate", mutating: true, risk: "normal", allowed: true,
  })),
});

const fragment = (payload: Record<string, unknown>) => ({
  host_id: "h1", module: "processes", revision: "abcdef1234567890", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

const process = (over: Partial<Process> = {}): Process => ({
  pid: 100, ppid: 1, user: "root", command: "/usr/bin/nginx", name: "nginx", state: "S",
  rss_bytes: 1024 * 1024, threads: 2, start_time_ticks: 4242, cpu_ticks: 10,
  ...over,
});

function draw(one: Host = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Processes host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the processes of one host", () => {
  it("reads a bounded slice, in the order the operator chose", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/actions": allow("process.list", "process.signal") });
    draw();
    await waitFor(() => expect(screen.getByTestId("read-processes")).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "by CPU time" }));
    fireEvent.click(screen.getByTestId("read-processes"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "process.list",
      payload: { process_list: { sort_by: "cpu", limit: 200 } },
    });
  });

  it("asks before it signals, and ties the order to the process it was shown", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("process.list", "process.signal"),
      "/api/v1/hosts/h1/inventory/processes": fragment({ processes: [process()], total: 1 }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("term-100")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("term-100"));
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("signal-reason"), { target: { value: "stuck worker, ticket 4412" } });
    expect(screen.getByTestId("signal-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("signal-hostname"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("signal-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "process.signal",
      reason: "stuck worker, ticket 4412",
      payload: {
        process_signal: {
          pid: 100,
          // The PID alone may meanwhile belong to a different process.
          expected_start_ticks: 4242,
          signal: "TERM",
          command: "/usr/bin/nginx",
        },
      },
    });
  });

  it("offers no signal where one would be ignored or refused", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("process.list", "process.signal"),
      "/api/v1/hosts/h1/inventory/processes": fragment({
        processes: [
          process({ pid: 1, ppid: 0, command: "/sbin/init", name: "systemd" }),
          process({ pid: 7, ppid: 2, command: "", name: "kworker/0:1" }),
          process(),
        ],
        total: 3,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("process-1")).toBeInTheDocument());
    expect(within(screen.getByTestId("process-1")).getByText("no signal")).toBeInTheDocument();
    // A kernel thread cannot be ended, and has no address space to report.
    expect(within(screen.getByTestId("process-7")).getByText("no signal")).toBeInTheDocument();
    expect(within(screen.getByTestId("process-7")).getByTitle("A kernel thread has no address space of its own.")).toBeInTheDocument();
    expect(within(screen.getByTestId("process-100")).getByTestId("term-100")).toBeInTheDocument();
  });

  it("warns that the agent's own process carries the order it is being sent", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("process.list", "process.signal"),
      "/api/v1/hosts/h1/inventory/processes": fragment({
        processes: [process({ pid: 300, unit: "flotestro-agent.service", command: "/usr/bin/flotestro-agent" })],
        total: 1,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("term-300")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("term-300"));
    expect(screen.getByText(/This is the agent itself/)).toBeInTheDocument();
  });

  it("counts nothing until the host has been read, and says a user it never got is unknown", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/actions": allow("process.list", "process.signal") });
    const { unmount } = draw();
    await waitFor(() => expect(screen.getByTestId("process-states")).toBeInTheDocument());
    // No snapshot: every state says it was not counted rather than nought.
    expect(screen.getByTestId("process-states")).toHaveTextContent("running: not counted");
    expect(screen.getByText("This host has not been read yet. Use “Read from host”.")).toBeInTheDocument();
    unmount();

    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/processes": fragment({
        processes: [process({ user: undefined })], total: 1,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("process-100")).toBeInTheDocument());
    expect(within(screen.getByTestId("process-100")).getByText("unknown")).toBeInTheDocument();
  });

  it("marks a cut-off slice with how much of the host it is", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("process.list"),
      "/api/v1/hosts/h1/inventory/processes": fragment({ processes: [process()], truncated: true, total: 412 }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/Showing 1 of 412 processes/)).toBeInTheDocument());
  });

  it("narrows on the command, the user, the unit and the bare PID", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("process.list"),
      "/api/v1/hosts/h1/inventory/processes": fragment({
        processes: [process(), process({ pid: 200, command: "/usr/sbin/sshd", name: "sshd", user: "sshd" })],
        total: 2,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("process-200")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("process-filter"), { target: { value: "sshd" } });
    await waitFor(() => expect(screen.queryByTestId("process-100")).toBeNull());
    fireEvent.change(screen.getByTestId("process-filter"), { target: { value: "100" } });
    await waitFor(() => expect(screen.getByTestId("process-100")).toBeInTheDocument());
    expect(screen.queryByTestId("process-200")).toBeNull();
  });
});

describe("nesting a flat slice", () => {
  const slice: Process[] = [
    process({ pid: 1, ppid: 0, name: "systemd" }),
    process({ pid: 10, ppid: 1, name: "nginx" }),
    process({ pid: 11, ppid: 10, name: "nginx worker" }),
    process({ pid: 50, ppid: 999, name: "orphan" }),
  ];

  it("puts every process under its parent and counts what hangs off it", () => {
    const rows = treeRows(slice, () => true, new Set());
    expect(rows.map((row) => [row.process.pid, row.depth])).toEqual([[1, 0], [10, 1], [11, 2], [50, 0]]);
    expect(rows[1].children).toBe(1);
  });

  it("makes a child of a parent outside the slice a root of its own", () => {
    const rows = treeRows(slice, () => true, new Set());
    expect(rows.find((row) => row.process.pid === 50)?.depth).toBe(0);
  });

  it("keeps a parent whose child matches, and folds away a collapsed branch", () => {
    const matching = treeRows(slice, (one) => one.name === "nginx worker", new Set());
    expect(matching.map((row) => row.process.pid)).toEqual([1, 10, 11]);
    const folded = treeRows(slice, () => true, new Set([10]));
    expect(folded.map((row) => row.process.pid)).toEqual([1, 10, 50]);
  });
});

describe("reading a process", () => {
  it("tells a zombie from something merely asleep", () => {
    expect(processTone("R")).toBe("ok");
    expect(processTone("Z")).toBe("error");
    expect(processTone("D")).toBe("warn");
    expect(processTone("S")).toBe("neutral");
  });

  it("knows the agent by the unit that carries it", () => {
    expect(agentProcess(process({ unit: "flotestro-agent.service" }))).toBe(true);
    expect(agentProcess(process({ unit: "nginx.service" }))).toBe(false);
  });
});
