import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Backups, ageTone, lastDays } from "./Backups";
import { ToastProvider } from "../../components/Toast";

/**
 * A backup screen is read for three things: what has not been copied, what
 * nobody has read back, and what the panel cannot say either way. The last
 * of the three is the one that gets lost, because a host nobody asked and
 * a host with fresh copies both look quiet.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest registered key wins. A short key would otherwise
        // answer a longer path and hand the screen the wrong document
        // while the test went green.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const definition = (over: Record<string, unknown> = {}) => ({
  host_id: "h1", hostname: "db", definition: "pgdata", tool: "restic",
  repository: "s3:https://minio.lab/flotestro", status: "ok",
  last_success_at: "2026-10-16T02:00:00Z", age_hours: 6,
  unverified: false, last_restore_at: "2026-10-01T09:00:00Z",
  ...over,
});

const page = (over: Record<string, unknown> = {}) => ({
  items: [definition()],
  count: 1, total: 1,
  counts: { never: 0, critical: 0, warning: 0, ok: 1, unknown: 0 },
  unverified: 0, never_restored: 0,
  total_hosts: 7, evaluated_hosts: 4, unknown_hosts: 3,
  hosts_total: 7,
  thresholds: { warning_hours: 36, critical_hours: 72, verification_days: 30 },
  repositories: [],
  ...over,
});

/** The arrangement the board reads before it draws anything. */
const layout = { widgets: [], present: false, revision: 0 };

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Backups />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the fleet's backups", () => {
  it("draws a definition as its age, its host, what copies it, where to, and whether anybody read it back", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/backups": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("backup-db-pgdata")).toBeInTheDocument());
    const row = screen.getByTestId("backup-db-pgdata");
    expect(within(row).getByText("6 h")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "db" })).toHaveAttribute("href", "/hosts/h1/backups");
    expect(row).toHaveTextContent("pgdata");
    expect(row).toHaveTextContent("restic");
    expect(row).toHaveTextContent("s3:https://minio.lab/flotestro");
    expect(within(row).getByText("verified")).toBeInTheDocument();
  });

  it("keeps the worst first, as the server sorted them, and colours each by its age", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/backups": page({
        items: [
          definition({ definition: "never", status: "never", age_hours: undefined, last_success_at: undefined }),
          definition({ definition: "stale", status: "critical", age_hours: 400 }),
          definition({ definition: "unjudged", status: "unknown", age_hours: undefined, last_success_at: undefined }),
          definition({ definition: "ageing", status: "warning", age_hours: 50 }),
          definition({ definition: "fresh", status: "ok", age_hours: 6 }),
        ],
        count: 5, total: 5,
        counts: { never: 1, critical: 1, warning: 1, ok: 1, unknown: 1 },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("backup-db-fresh")).toBeInTheDocument());
    const names = [...screen.getByTestId("backups").querySelectorAll("tbody tr")]
      .map((row) => row.getAttribute("data-testid"));
    expect(names).toEqual([
      "backup-db-never", "backup-db-stale", "backup-db-unjudged", "backup-db-ageing", "backup-db-fresh",
    ]);
    const tone = (name: string) =>
      screen.getByTestId(`backup-db-${name}`).querySelector(".fl-pill")?.className;
    expect(tone("never")).toContain("fl-error");
    expect(tone("stale")).toContain("fl-error");
    expect(tone("ageing")).toContain("fl-warn");
    expect(tone("fresh")).toContain("fl-ok");
    // The one that matters: nobody could judge this definition, and that
    // is not the colour of a fresh copy.
    expect(tone("unjudged")).toContain("fl-unknown");
    // 400 hours is read as days; the pill is for a glance, not a reading.
    expect(screen.getByTestId("backup-db-stale")).toHaveTextContent("17 d");
  });

  it("says when there is no copy at all rather than leaving the cell blank", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/backups": page({
        items: [definition({
          definition: "nothing", status: "never", age_hours: undefined,
          last_success_at: undefined, last_restore_at: undefined, unverified: true,
        })],
        counts: { never: 1, critical: 0, warning: 0, ok: 0, unknown: 0 },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("backup-db-nothing")).toBeInTheDocument());
    const row = screen.getByTestId("backup-db-nothing");
    expect(row).toHaveTextContent("never ran");
    expect(row).toHaveTextContent("no copy recorded");
    expect(row).toHaveTextContent("not verified");
    expect(row).toHaveTextContent("never restored");
  });

  it("counts the hosts nobody has defined anything for apart from the ones with copies", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/backups": page({ counts: { never: 2, critical: 5, warning: 1, ok: 30, unknown: 0 }, unverified: 9, never_restored: 21 }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Never ran")).toHaveTextContent("2"));
    expect(screen.getByTestId("kpi-Stale")).toHaveTextContent("5");
    expect(screen.getByTestId("kpi-Unverified")).toHaveTextContent("9");
    expect(screen.getByTestId("kpi-Never restored")).toHaveTextContent("21");
    // Three hosts have nothing defined: the panel does not know whether
    // anything copies them, which is not the same as knowing they are fine.
    const hosts = screen.getByText("Nothing defined").closest(".fl-bars") as HTMLElement;
    expect(hosts).toHaveTextContent("With a definition");
    expect(screen.getByTestId("backup-states")).toBeInTheDocument();
  });

  it("gives a backend with no reading a dash, never an age of nought", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/backups": page({
        repositories: [
          { repository: "s3:https://minio.lab/flotestro", hosts: 4, unverified: 1, oldest_age_hours: 73, budget_key: "backend:minio.lab", capacity: 2, used: 1, claimants: 3 },
          { repository: "/srv/backup", hosts: 2, unverified: 0, budget_key: "backend:local" },
        ],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("repository-/srv/backup")).toBeInTheDocument());
    const silent = screen.getByTestId("repository-/srv/backup");
    expect(silent.querySelector(".fl-unknown")).toHaveTextContent("—");
    expect(within(silent).getByText("no limit set")).toBeInTheDocument();
    const busy = screen.getByTestId("repository-s3:https://minio.lab/flotestro");
    expect(busy).toHaveTextContent("73 h");
    expect(busy).toHaveTextContent("1 / 2");
    expect(busy).toHaveTextContent("1 unverified");
    expect(busy).toHaveTextContent("3 campaigns want it");
  });

  it("shows a dash while the fleet has not answered, never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      // The answer never arrives: a panel that drew noughts here would
      // report a fleet with nothing wrong.
      "/api/v1/backups": new Promise(() => {}),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Never ran")).toBeInTheDocument());
    const tile = screen.getByTestId("kpi-Never ran");
    expect(tile).toHaveAttribute("data-state", "unknown");
    expect(tile).toHaveTextContent("—");
    expect(tile).not.toHaveTextContent("0");
    expect(screen.getByTestId("kpi-Unverified")).toHaveAttribute("data-state", "unknown");
  });

  it("says the answer did not come instead of drawing an empty fleet", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.queryByTestId("backups")).not.toBeInTheDocument();
  });

  it("asks the server again when the page size changes", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/backups": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("backups")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: "200" }));
    await waitFor(() => expect(asked.some((one) => one.includes("/api/v1/backups?limit=200"))).toBe(true));
  });
});

describe("the colour of a copy's age", () => {
  it("keeps a definition nobody could judge apart from a fresh one", () => {
    expect(ageTone("ok")).toBe("ok");
    expect(ageTone("warning")).toBe("warn");
    expect(ageTone("critical")).toBe("error");
    // Never having run is a fact about the definition, and a bad one.
    expect(ageTone("never")).toBe("error");
    // Not having been judged is not a fact about the copies.
    expect(ageTone("unknown")).toBe("unknown");
  });
});

describe("the calendar of the last days", () => {
  it("puts today last and leaves out what fell outside the window", () => {
    const day = (back: number) => new Date(Date.now() - back * 86400000).toISOString();
    const rows = [
      { last_success_at: day(0) }, { last_success_at: day(0) },
      { last_success_at: day(3) },
      // Older than the window, and older than anything it could be drawn
      // beside: the age column is where this one is read.
      { last_success_at: day(40) },
      // Never copied: it belongs to no day at all rather than to today.
      { last_success_at: undefined },
    ];
    const { labels, values } = lastDays(rows as never, 14);
    expect(labels).toHaveLength(14);
    expect(values).toHaveLength(14);
    expect(values[13]).toBe(2);
    expect(values[10]).toBe(1);
    expect(values.reduce((sum, one) => sum + one, 0)).toBe(3);
  });
});
