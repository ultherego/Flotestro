import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Schedules, commandOf, hostClock } from "./Schedules";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import type { Schedule } from "../../../lib/host/schedules";

/**
 * The recurring work of one host, and the line the screen will not cross:
 * an entry the host administrator wrote is read and left alone. Running
 * it, switching it off or taking it away is offered only for the entries
 * the panel owns.
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
  capabilities: [{ name: "schedules", version: 1, available: true, read_only: false, features: { cron: true } }],
  identity: { enrolled: false, sssd_online: null },
  ...over,
} as Host);

const allow = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.operate", mutating: true, risk: "normal", allowed: true,
  })),
});

const EVERY = [
  "schedule.ensure", "schedule.run_now", "schedule.disable", "schedule.remove", "schedule.preview",
];

const fragment = (payload: Record<string, unknown>) => ({
  host_id: "h1", module: "schedules", revision: "abcdef1234567890", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

const entry = (over: Partial<Schedule> = {}): Schedule => ({
  id: "nightly-backup", kind: "cron", source: "managed", enabled: true, expression: "0 3 * * *",
  command: ["/usr/bin/backup", "--all"], user: "root", path: "/etc/cron.d/flotestro-nightly-backup",
  ...over,
});

/**
 * The screen is three sub-tabs since 17.10 - the readings, the list of
 * entries and the form - and the address names which one is open, so a
 * test that works on the list asks for `?tab=schedules` the way a reader
 * following a link would.
 */
function draw(one: Host = host(), tab?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/hosts/${one.id}/schedules?tab=${tab}` : `/hosts/${one.id}/schedules`;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Schedules host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the recurring work of one host", () => {
  it("asks before it runs an entry out of turn, and sends the reason", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({ schedules: [entry()], timezone: "Europe/Warsaw" }),
    });
    draw(host(), "schedules");
    await waitFor(() => expect(screen.getByTestId("run-nightly-backup")).toBeEnabled());
    fireEvent.click(screen.getByTestId("run-nightly-backup"));
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("entry-reason"), { target: { value: "catching up a missed window" } });
    expect(screen.getByTestId("entry-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("entry-hostname"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("entry-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "schedule.run_now",
      reason: "catching up a missed window",
      payload: { schedule: { id: "nightly-backup" } },
    });
  });

  it("switches an entry off without a question, because nothing is erased", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({ schedules: [entry()] }),
    });
    draw(host(), "schedules");
    await waitFor(() => expect(screen.getByTestId("schedule-nightly-backup")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("schedule-nightly-backup")).getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "schedule.disable",
      // The registry leaves out what is off: `enabled` absent is the same
      // order it composes for the Bulk workspace.
      payload: { schedule: { id: "nightly-backup" } },
    });
  });

  it("leaves the host administrator's own entries alone", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({
        schedules: [entry({ id: "logrotate:3", source: "host", path: "/etc/crontab", line: 3 })],
      }),
    });
    draw(host(), "schedules");
    await waitFor(() => expect(screen.getByTestId("schedule-logrotate:3")).toBeInTheDocument());
    const row = screen.getByTestId("schedule-logrotate:3");
    expect(row).toHaveTextContent("host admin");
    expect(within(row).getByRole("button", { name: "Run now" })).toBeDisabled();
    expect(within(row).getByRole("button", { name: "Remove" })).toBeDisabled();
    expect(within(row).getByTitle("Only entries owned by Flotestro can be run from the panel.")).toBeInTheDocument();
  });

  it("counts nothing when the host could not read its schedules", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({ schedules: [], unavailable_reason: "crontab is not installed" }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/crontab is not installed/)).toBeInTheDocument());
    // An unread list is not an empty one: nought would say the host runs
    // nothing on a schedule, which nobody has established.
    const shape = screen.getByTestId("schedule-shape");
    expect(shape).toHaveTextContent("enabled: not counted");
    expect(within(shape).queryByText("0")).toBeNull();
  });

  it("refuses a new entry the registry would not take, and says why", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({ schedules: [] }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-schedule")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-schedule"));
    await waitFor(() => expect(screen.getByTestId("schedule-id")).toBeInTheDocument());
    // Nothing named and nothing to run: the panel refuses before the
    // request leaves, and says the first thing that is wrong.
    expect(screen.getByTestId("schedule-create")).toBeDisabled();
    expect(screen.getByText("Name the entry this acts on.")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("schedule-id"), { target: { value: "nightly" } });
    fireEvent.change(screen.getByTestId("schedule-command"), { target: { value: "backup --all" } });
    // A command that is not an absolute path is not a command cron runs.
    expect(screen.getByText("The program is named by its absolute path.")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("schedule-command"), { target: { value: "/usr/bin/backup --all" } });
    await waitFor(() => expect(screen.getByTestId("schedule-create")).toBeEnabled());
    fireEvent.click(screen.getByTestId("schedule-create"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "schedule.ensure",
      payload: {
        schedule: {
          id: "nightly", expression: "0 3 * * *", command: ["/usr/bin/backup", "--all"],
          user: "root", kind: "cron",
        },
      },
    });
  });

  it("names what the host administrator already runs under that name, and takes it over only on purpose", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/schedules": fragment({
        schedules: [entry({
          id: "nightly:7", source: "host", kind: "cron", path: "/etc/cron.d/nightly", line: 7,
          command: undefined, command_line: "/usr/bin/other",
        })],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-schedule")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-schedule"));
    fireEvent.change(screen.getByTestId("schedule-id"), { target: { value: "nightly" } });
    fireEvent.change(screen.getByTestId("schedule-command"), { target: { value: "/usr/bin/backup" } });
    await waitFor(() => expect(screen.getByText(/already runs under this name/)).toBeInTheDocument());
    // Without the consent the order is not offered at all.
    expect(screen.getByTestId("schedule-create")).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /Take it over/ }));
    await waitFor(() => expect(screen.getByTestId("schedule-create")).toBeEnabled());
    fireEvent.click(screen.getByTestId("schedule-create"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect((sent[0].body as { payload: { schedule: { adopt: boolean } } }).payload.schedule.adopt).toBe(true);
  });

  it("draws no button for an order this operator may not place", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow("schedule.disable"),
      "/api/v1/hosts/h1/inventory/schedules": fragment({ schedules: [entry()] }),
    });
    draw(host(), "schedules");
    await waitFor(() => expect(screen.getByTestId("schedule-nightly-backup")).toBeInTheDocument());
    const row = screen.getByTestId("schedule-nightly-backup");
    expect(within(row).queryByRole("button", { name: "Run now" })).toBeNull();
    expect(within(row).queryByRole("button", { name: "Remove" })).toBeNull();
    expect(within(row).getByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(screen.queryByTestId("new-schedule")).toBeNull();
  });
});

describe("reading an entry", () => {
  it("shows the wall clock the host wrote, not the browser's idea of it", () => {
    expect(hostClock("2026-10-17T03:00:00+02:00")).toBe("2026-10-17 03:00");
    expect(hostClock("tomorrow")).toBe("tomorrow");
  });

  it("shows what the host will really run, whichever way the entry carries it", () => {
    expect(commandOf(entry())).toBe("/usr/bin/backup --all");
    expect(commandOf(entry({ command: undefined, command_line: "/bin/sh -c x" }))).toBe("/bin/sh -c x");
  });
});
