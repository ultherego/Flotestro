import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Status, STATUS_SCREEN, blockSummary, blockTone, numberFact, shortIdentifier, statusCatalogue,
} from "./Status";

/**
 * The screen that says whether this installation is well.
 *
 * What is tested is what the screen decides, not that it draws: how many
 * parts it counts as fine, what it does with a part nobody could judge,
 * and whether a figure the server never sent comes out as a dash. The
 * last one is the rule the whole product rests on, and this is the screen
 * where it is easiest to lose, because almost every value here is a
 * number.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. A short key
  // left to answer a longer path hands the screen another document's
  // body, and the screen then tests nothing it claims to.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    return Promise.resolve(answers[key]);
  };
  return { ...actual, api: { ...actual.api, get: answer } };
});

const view = (over: Record<string, unknown> = {}) => ({
  generated_at: "2026-10-16T10:00:00Z",
  ok: true,
  unknown: 1,
  links: { openapi: "/api/v1/openapi.json", metrics: "/metrics" },
  blocks: {
    database: { ok: true, facts: { latency_ms: 1.25, pool_used: 3, pool_max: 10, pool_idle: 2 } },
    outbox: {
      ok: true,
      facts: {
        pending: 4,
        consumers: [{ name: "siem", behind: 12, failures: 0, updated_at: "2026-10-16T09:59:00Z" }],
      },
    },
    // leased and dispatched are not in the answer at all: the band has to
    // say so rather than drawing two segments of nought.
    scheduler: { ok: true, facts: { awaiting_approval: 0, queued: 2, running: 1 } },
    relays: { ok: null, facts: { active: 1, silent: 0 } },
    housekeeping: {
      ok: true,
      attention: "the last sweep left work behind",
      facts: {
        last_sweep_at: "2026-10-16T08:00:00Z",
        retention: { jobs: "72h", audit_events: "8760h" },
        removed: { jobs: 5 },
      },
    },
  },
  ...over,
});

/** The screen is three tabs; the parts of the panel are the second. */
function draw(tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[tab ? `/status?tab=${tab}` : "/status"]}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Status />, { wrapper });
}

beforeEach(() => {
  for (const key of Object.keys(answers)) delete answers[key];
});

afterEach(() => { cleanup(); asked.length = 0; });

describe("the condition of the installation", () => {
  it("counts a part nobody could judge apart from the parts that are fine", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-fine")).toBeInTheDocument());
    // Five parts: three plainly fine, one with a note, one the server
    // could not judge at all.
    expect(screen.getByTestId("kpi-fine")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-unknown")).toHaveTextContent("1");
    expect(screen.getByTestId("kpi-wanting")).toHaveTextContent("1");
    // Judged is the whole minus the unjudged, never the whole.
    expect(screen.getByTestId("kpi-judged")).toHaveTextContent("4");
  });

  it("names every part that is not plainly fine, with the server's own reason", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw();
    await waitFor(() => expect(screen.getAllByText("the last sweep left work behind").length).toBeGreaterThan(0));
    // The part nobody could judge is on the list too: unknown is not fine.
    expect(screen.getAllByText("Relays").length).toBeGreaterThan(0);
    expect(screen.getAllByText("judged as unknown").length).toBeGreaterThan(0);
  });

  it("says a kind the sweep did not report, rather than removing nought from it", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw("components");
    await waitFor(() => expect(screen.getByTestId("kind-audit_events")).toBeInTheDocument());
    const swept = screen.getByTestId("kind-jobs");
    expect(swept).toHaveTextContent("5");
    const silent = screen.getByTestId("kind-audit_events");
    expect(silent).toHaveTextContent("—");
    expect(within(silent).queryByText("0")).toBeNull();
  });

  it("puts a count the server never sent under the band as not counted", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw("components");
    await waitFor(() => expect(screen.getByTestId("scheduler-band")).toBeInTheDocument());
    const band = screen.getByTestId("scheduler-band");
    // Two were counted and drawn, one is a real nought, and two never
    // arrived - and those three are words under the line, not slivers.
    expect(band).toHaveTextContent("leased: not counted");
    expect(band).toHaveTextContent("dispatched: not counted");
    expect(band).toHaveTextContent("for approval");
    expect(band.querySelectorAll(".fl-band-seg")).toHaveLength(2);
  });

  it("draws the pool as the share it is, and no arc at all where none was reported", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    const { container, unmount } = draw();
    await waitFor(() => expect(container.querySelector(".fl-ring-value")).not.toBeNull());
    expect(container.querySelector(".fl-ring-value")).toHaveTextContent("30%");
    unmount();
    cleanup();

    const quiet = view();
    quiet.blocks.database.facts = { latency_ms: 1.25 } as typeof quiet.blocks.database.facts;
    Object.assign(answers, { "/api/v1/status": quiet });
    const second = draw();
    await waitFor(() => expect(second.container.querySelector(".fl-ring-value")).not.toBeNull());
    expect(second.container.querySelector(".fl-ring-value")).toHaveTextContent("—");
    expect(second.container.querySelector(".fl-ring-arc")).toBeNull();
  });

  it("leads to the relays and the jobs of the new panel, not of the old one", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw("components");
    await waitFor(() => expect(screen.getByTestId("relays-band")).toBeInTheDocument());
    const relays = within(screen.getByTestId("relays-band")).getByRole("listitem");
    expect(relays).toHaveAttribute("href", "/relays");
    const queued = within(screen.getByTestId("scheduler-band")).getAllByRole("listitem");
    expect(queued.some((one) => one.getAttribute("href") === "/jobs?state=queued")).toBe(true);
  });

  it("waits for a second reading before it draws a line over time", async () => {
    Object.assign(answers, { "/api/v1/status": view() });
    draw();
    await waitFor(() => expect(screen.getByText(/One reading so far/)).toBeInTheDocument());
    expect(screen.queryByTestId("latency-chart")).toBeNull();
  });

  it("copies the whole answer, and says copied only when the clipboard took it", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    Object.assign(answers, { "/api/v1/status": view() });
    draw();
    await waitFor(() => expect(screen.getByTestId("copy-diagnostics")).toBeEnabled());
    fireEvent.click(screen.getByTestId("copy-diagnostics"));
    await waitFor(() => expect(screen.getByTestId("copy-diagnostics")).toHaveTextContent("Copied"));
    expect(JSON.parse(writeText.mock.calls[0][0] as string).blocks.database.facts.latency_ms).toBe(1.25);
  });

  it("does not claim a copy the browser refused", async () => {
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockRejectedValue(new Error("not a secure context")) },
      configurable: true,
    });
    Object.assign(answers, { "/api/v1/status": view() });
    draw();
    await waitFor(() => expect(screen.getByTestId("copy-diagnostics")).toBeEnabled());
    fireEvent.click(screen.getByTestId("copy-diagnostics"));
    await waitFor(() => expect(screen.getByTestId("copy-diagnostics")).toHaveTextContent("Copy diagnostics"));
  });

  it("says a part is not fine before anything else on the screen", async () => {
    Object.assign(answers, { "/api/v1/status": view({ ok: false, unknown: 0 }) });
    draw();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("A part of this panel is not fine"));
  });

  it("says what went wrong instead of an empty panel when the read fails", async () => {
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.getByRole("alert")).toHaveTextContent("no such thing");
    expect(asked).toContain("/api/v1/status");
  });
});

describe("the judgements the screen makes on its own", () => {
  it("reads a part that could not be judged as unknown, a failing one as an error", () => {
    expect(blockTone({ ok: null })).toBe("unknown");
    expect(blockTone({ ok: false })).toBe("error");
    expect(blockTone({ ok: true })).toBe("ok");
    // Fine with a note is not the same as fine.
    expect(blockTone({ ok: true, attention: "slow" })).toBe("warn");
  });

  it("gives no summary for a measurement the server did not send", () => {
    const t = (text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, name: string) => String(params?.[name] ?? ""));
    expect(blockSummary("database", {}, t)).toBe("");
    expect(blockSummary("database", { latency_ms: 2 }, t)).toBe("2.0 ms round trip");
  });

  it("reads a number only where the server sent one", () => {
    expect(numberFact({ a: 3 }, "a")).toBe(3);
    expect(numberFact({ a: "3" }, "a")).toBeUndefined();
    expect(numberFact(undefined, "a")).toBeUndefined();
  });

  it("keeps the ends of an identifier and drops the middle nobody reads", () => {
    expect(shortIdentifier("short")).toBe("short");
    expect(shortIdentifier("0123456789abcdef0123456789abcdef")).toBe("01234567…89abcdef");
  });
});

/**
 * The parts of the panel stand on a board, as they did in the screen
 * this replaces: which part an installation watches first is its own
 * decision. The rewrite drew them on a plain screen, so the control was
 * gone and the arrangement stored for it was unreachable.
 */
describe("arranging the parts", () => {
  it("offers the arrange bar and draws its containers on the board", async () => {
    Object.assign(answers, {
      "/api/v1/status": view(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 1 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("board")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    expect(screen.getByTestId("arrange")).toHaveTextContent("Arrange this screen");
    expect(STATUS_SCREEN).toMatch(/^[a-z0-9_]+$/);
    expect(asked).toContain(`/api/v1/settings/layout/${STATUS_SCREEN}`);
  });

  it("gives every part the server reported a container of its own", () => {
    const catalogue = statusCatalogue(["database", "outbox"], true);
    expect(catalogue.map((one) => one.key)).toEqual(expect.arrayContaining(["database", "outbox", "build"]));
    // Nothing named twice: a key drawn twice is a container drawn twice.
    expect(new Set(catalogue.map((one) => one.key)).size).toBe(catalogue.length);
  });
});
