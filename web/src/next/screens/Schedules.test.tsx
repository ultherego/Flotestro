import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Schedules, calendarRows, describeRecurrence, entriesByDay, nextRunWords, parseRecurrence,
  recurrenceProblem, recurrenceText, scheduleBody, scheduleTone, emptyForm,
  type CalendarEntry,
} from "./Schedules";
import { ToastProvider } from "../../components/Toast";

/**
 * A schedule is an order the panel keeps until its moment, so the screen
 * is read for one thing above all: what each of them is waiting for. The
 * tests below hold that, and the three writes that change what the fleet
 * does while nobody is watching - running one early, turning one off and
 * deleting one - each of which must ask first and carry a reason.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What a write answers with; an Error here is rejected rather than returned. */
const writes: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. A short
  // "/api/v1/campaign-schedules" left to answer the run-now address would
  // hand the mutation the list, and every assertion after that measures
  // the harness rather than the screen.
  const longest = (table: Record<string, unknown>, path: string) =>
    Object.keys(table).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];

  const read = (path: string) => {
    asked.push(path);
    const key = longest(answers, path);
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    const value = answers[key];
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value);
  };
  const write = (method: string) => (path: string, body?: unknown) => {
    sent.push({ method, path, body });
    const key = longest(writes, path);
    const value = key ? writes[key] : undefined;
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value ?? {});
  };
  return {
    ...actual,
    api: { ...actual.api, get: read, post: write("POST"), put: write("PUT"), del: write("DELETE") },
  };
});

const ORDER = { name: "nightly", action: "unit.restart", payload: {}, selector: { host_ids: [] } };

const schedule = (over: Record<string, unknown> = {}) => ({
  id: "s1",
  name: "nightly-restart",
  order: ORDER,
  start_at: null,
  recurrence: "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=0",
  timezone: "Europe/Warsaw",
  next_run_at: "2999-01-01T22:00:00Z",
  last_run_at: "2026-10-09T22:00:00Z",
  last_campaign_id: "c1",
  last_error: "",
  created_by: "tszymanski",
  enabled: true,
  reason: "the monthly window",
  created_at: "2026-09-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
  ...over,
});

const base = (items: unknown[] = [schedule()], entries: CalendarEntry[] = []) => ({
  "/api/v1/campaign-schedules": { items, count: items.length },
  "/api/v1/maintenance/calendar": { items: entries, count: entries.length },
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Schedules />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(writes)) delete writes[key];
});

const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (whole, key: string) => String(params?.[key] ?? whole));

describe("what a schedule amounts to before it is drawn", () => {
  it("writes a rule the API reads and reads its own writing back", () => {
    const weekly = { freq: "WEEKLY" as const, monthDay: 1, weekdays: ["TH", "MO"], hour: 22, minute: 5 };
    expect(recurrenceText(weekly)).toBe("FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=5");
    expect(parseRecurrence(recurrenceText(weekly))).toEqual({ ...weekly, weekdays: ["MO", "TH"] });
    const monthly = { freq: "MONTHLY" as const, monthDay: 15, weekdays: ["MO"], hour: 2, minute: 30 };
    expect(recurrenceText(monthly)).toBe("FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=30");
    expect(parseRecurrence(recurrenceText(monthly))).toEqual(monthly);
    // A rule of another shape is not half a rule: it is none the form holds.
    expect(parseRecurrence("FREQ=YEARLY")).toBeNull();
    expect(parseRecurrence("")).toBeNull();
    expect(parseRecurrence("FREQ=MONTHLY;BYMONTHDAY=99;BYHOUR=2;BYMINUTE=0")).toBeNull();
  });

  it("says the rule in words, and calls a single moment once", () => {
    expect(describeRecurrence(t, undefined)).toBe("once");
    expect(describeRecurrence(t, "FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=30"))
      .toBe("monthly on day 15 at 02:30");
    expect(describeRecurrence(t, "FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=22;BYMINUTE=0"))
      .toBe("weekly on MO, TH at 22:00");
  });

  it("names what each is waiting for, and a switch that is off is not a moment", () => {
    const now = new Date("2026-10-16T10:00:00Z");
    expect(nextRunWords(t, { enabled: false, next_run_at: "2026-10-16T11:00:00Z" }, now)).toBe("disabled");
    expect(nextRunWords(t, { enabled: true, next_run_at: null }, now)).toBe("nothing more to place");
    expect(nextRunWords(t, { enabled: true, next_run_at: "2026-10-16T10:30:00Z" }, now)).toMatch(/^in 30 min/);
    expect(nextRunWords(t, { enabled: true, next_run_at: "2026-10-16T14:00:00Z" }, now)).toMatch(/^in 4 h/);
    expect(nextRunWords(t, { enabled: true, next_run_at: "2026-10-20T10:00:00Z" }, now)).toMatch(/^in 4 days/);
    expect(nextRunWords(t, { enabled: true, next_run_at: "2026-10-16T09:00:00Z" }, now)).toMatch(/^due now/);
  });

  it("reads a refusal as a fault whatever the clock says", () => {
    expect(scheduleTone({ enabled: true, next_run_at: "2999-01-01T00:00:00Z", last_error: "" })).toBe("ok");
    expect(scheduleTone({ enabled: true, next_run_at: null, last_error: "" })).toBe("warn");
    expect(scheduleTone({ enabled: false, next_run_at: null, last_error: "" })).toBe("unknown");
    expect(scheduleTone({ enabled: true, next_run_at: "2999-01-01T00:00:00Z", last_error: "no rights" }))
      .toBe("error");
  });

  it("refuses a body the server would refuse, and says which part", () => {
    const form = { ...emptyForm(), name: "nightly", reason: "the monthly window" };
    expect(scheduleBody({ ...form, orderText: "{" }).problem).toBe("order_json");
    expect(scheduleBody({ ...form, orderText: "[]" }).problem).toBe("order_json");
    expect(scheduleBody({ ...form, name: "  " }).problem).toBe("name");
    expect(scheduleBody({ ...form, reason: "short" }).problem).toBe("reason");
    // Neither a moment nor a rule is a schedule that never fires.
    expect(scheduleBody(form).problem).toBe("moment");
    expect(scheduleBody({ ...form, startAt: "2000-01-01T02:00" }).problem).toBe("start_past");
    const rule = { ...form, recurrence: { ...form.recurrence, freq: "WEEKLY" as const, weekdays: [] } };
    expect(scheduleBody(rule).problem).toBe("recurrence");
    expect(recurrenceProblem(rule.recurrence)).toBe("no_weekday");

    const good = scheduleBody({
      ...form,
      recurrence: { freq: "MONTHLY", monthDay: 15, weekdays: [], hour: 2, minute: 0 },
    });
    expect(good.problem).toBeUndefined();
    expect(good.body).toMatchObject({
      name: "nightly",
      recurrence: "FREQ=MONTHLY;BYMONTHDAY=15;BYHOUR=2;BYMINUTE=0",
      reason: "the monthly window",
      enabled: true,
    });
  });

  it("puts a window on every day it covers, not only the one it opened on", () => {
    const entry: CalendarEntry = {
      kind: "host_window", id: "h1", name: "agent-arch",
      start: "2026-10-05T08:00:00Z", end: "2026-10-07T08:00:00Z",
    };
    const byDay = entriesByDay([entry], new Date(2026, 9, 1), new Date(2026, 10, 1));
    expect([...byDay.keys()].sort()).toEqual(["2026-10-05", "2026-10-06", "2026-10-07"]);
    // And the rows the table draws are the same three, in order.
    const rows = calendarRows([entry], 2026, 9);
    expect(rows.map((one) => one.day)).toEqual(["2026-10-05", "2026-10-06", "2026-10-07"]);
    // A day nobody planned anything on is not an empty row.
    expect(rows.every((one) => one.entry.id === "h1")).toBe(true);
    expect(calendarRows([], 2026, 9)).toEqual([]);
  });
});

describe("the schedules the fleet runs on a clock", () => {
  it("draws a schedule as its rule, its operation and what it is waiting for", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("schedule-nightly-restart")).toBeInTheDocument());
    const row = screen.getByTestId("schedule-nightly-restart");
    expect(row).toHaveTextContent("unit.restart");
    expect(row).toHaveTextContent("weekly on MO, TH at 22:00");
    expect(row).toHaveTextContent("Europe/Warsaw");
    // The campaign the last moment placed is reachable from the row, in
    // the new panel rather than the one this replaces.
    expect(within(row).getByRole("link", { name: "campaign" }))
      .toHaveAttribute("href", "/next/campaigns/c1");
  });

  it("counts nothing before the list has arrived, and never a nought", () => {
    Object.assign(answers, base());
    draw();
    // The request is still in flight: a tile that said 0 would answer a
    // question nobody has asked yet.
    expect(screen.getByTestId("kpi-schedules")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-refused")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-schedules").querySelector(".fl-kpi-value"))
      .not.toHaveTextContent("0");
  });

  it("counts what is waiting, what is due within a day and what was refused", async () => {
    Object.assign(answers, base([
      schedule(),
      schedule({ id: "s2", name: "off", enabled: false, next_run_at: null }),
      schedule({ id: "s3", name: "broken", last_error: "no rights", next_run_at: null }),
      schedule({ id: "s4", name: "soon", next_run_at: new Date(Date.now() + 3600_000).toISOString() }),
    ]));
    draw();
    await waitFor(() => expect(screen.getByTestId("schedule-soon")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-schedules")).toHaveTextContent("4");
    // Waiting is enabled with a moment ahead: the disabled one and the
    // one with nothing more to place are not waiting for anything.
    expect(screen.getByTestId("kpi-waiting")).toHaveTextContent("2");
    expect(screen.getByTestId("kpi-due")).toHaveTextContent("1");
    expect(screen.getByTestId("kpi-refused")).toHaveTextContent("1");
  });

  it("offers the Bulk workspace when nothing runs on a clock yet", async () => {
    Object.assign(answers, base([]));
    draw();
    await waitFor(() => expect(screen.getByText("No campaign runs on a clock here yet.")).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Schedule one from the Bulk workspace" }))
      .toHaveAttribute("href", "/next/bulk");
  });

  it("will not create a schedule the server would refuse, and says why", async () => {
    Object.assign(answers, base([]));
    draw();
    await waitFor(() => expect(screen.getByTestId("schedule-new")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("schedule-new"));

    // A fresh form has neither a name nor a reason nor a moment.
    expect(screen.getByTestId("schedule-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("schedule-name"), { target: { value: "nightly" } });
    fireEvent.change(screen.getByTestId("schedule-reason"), { target: { value: "short" } });
    expect(screen.getByText("the reason needs at least 8 characters")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("schedule-reason"), { target: { value: "the monthly window" } });
    expect(screen.getByText("give the schedule a first run or a recurrence")).toBeInTheDocument();
    expect(screen.getByTestId("schedule-save")).toBeDisabled();

    fireEvent.change(screen.getByTestId("schedule-freq"), { target: { value: "WEEKLY" } });
    // Weekly with no weekday names no moment at all.
    fireEvent.click(screen.getByLabelText("MO"));
    expect(screen.getByText("the recurrence is incomplete: a day, an hour and a minute")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("TH"));
    fireEvent.change(screen.getByTestId("schedule-order"), { target: { value: "{" } });
    expect(screen.getByText("the order is not a JSON object")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("schedule-order"), {
      target: { value: JSON.stringify(ORDER) },
    });
    expect(screen.getByTestId("schedule-save")).toBeEnabled();
    fireEvent.click(screen.getByTestId("schedule-save"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/campaign-schedules");
    expect(sent[0].body).toMatchObject({
      name: "nightly",
      recurrence: "FREQ=WEEKLY;BYDAY=TH;BYHOUR=2;BYMINUTE=0",
      reason: "the monthly window",
      timezone: expect.any(String),
    });
  });

  it("edits an existing schedule in place and writes it back to its own address", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-nightly-restart")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-nightly-restart"));
    // The form opens on the record, not on a blank.
    expect(screen.getByTestId("schedule-name")).toHaveValue("nightly-restart");
    expect(screen.getByTestId("schedule-timezone")).toHaveValue("Europe/Warsaw");
    expect(screen.getByTestId("schedule-freq")).toHaveValue("WEEKLY");
    expect(screen.getByLabelText("MO")).toBeChecked();
    expect(screen.getByLabelText("TU")).not.toBeChecked();

    fireEvent.change(screen.getByTestId("schedule-name"), { target: { value: "nightly-restart-2" } });
    fireEvent.click(screen.getByTestId("schedule-save"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "PUT", path: "/api/v1/campaign-schedules/s1" });
    expect(sent[0].body).toMatchObject({ name: "nightly-restart-2" });
  });

  it("asks before deleting one, and will not go without a reason the trail takes", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("delete-nightly-restart")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("delete-nightly-restart"));

    expect(screen.getByRole("dialog")).toHaveTextContent("Delete the schedule nightly-restart?");
    expect(screen.getByTestId("ask-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("ask-confirm")).toBeDisabled();
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "decommissioned" } });
    fireEvent.click(screen.getByTestId("ask-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "DELETE",
      path: "/api/v1/campaign-schedules/s1",
      body: { reason: "decommissioned" },
    });
  });

  it("turns one off by rewriting the record with the flag turned over", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("toggle-nightly-restart")).toBeInTheDocument());
    expect(screen.getByTestId("toggle-nightly-restart")).toHaveTextContent("Disable");
    fireEvent.click(screen.getByTestId("toggle-nightly-restart"));
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "the window moved" } });
    fireEvent.click(screen.getByTestId("ask-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "PUT", path: "/api/v1/campaign-schedules/s1" });
    expect(sent[0].body).toMatchObject({
      name: "nightly-restart",
      enabled: false,
      reason: "the window moved",
      timezone: "Europe/Warsaw",
    });
  });

  it("places the order early on request and leads to the campaign it made", async () => {
    Object.assign(answers, base());
    Object.assign(writes, {
      "/api/v1/campaign-schedules/s1/run-now": { id: "c9", name: "nightly-restart", state: "awaiting_approval" },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("run-nightly-restart")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("run-nightly-restart"));
    expect(screen.getByTestId("ask-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "the incident of today" } });
    fireEvent.click(screen.getByTestId("ask-confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/campaign-schedules/s1/run-now",
      body: { reason: "the incident of today" },
    });
    await waitFor(() =>
      expect(screen.getByRole("link", { name: "nightly-restart" }))
        .toHaveAttribute("href", "/next/campaigns/c9"));
  });
});

describe("the maintenance calendar", () => {
  /**
   * A month is read across, not down.
   *
   * The first draft of this screen flattened the calendar into a row per
   * day-and-entry, because the kit draws one table and has no calendar
   * piece. A list of days answers "what is on the 5th" and loses the
   * question the owner actually opens this card for - what the month
   * looks like - so the month is built out of that one table instead:
   * seven weekday columns, a week to a row, a day in every cell.
   */
  it("draws the month as a month: seven weekdays across and a week to a row", async () => {
    Object.assign(answers, base([], [
      {
        kind: "host_window", id: "h1", name: "agent-arch",
        start: "2026-10-05T08:00:00Z", end: "2026-10-05T12:00:00Z",
        reason: "kernel", set_by: "tszymanski",
      },
    ]));
    vi.setSystemTime(new Date("2026-10-16T09:00:00Z"));
    draw();
    await waitFor(() => expect(screen.getByTestId("calendar")).toBeInTheDocument());
    const calendar = screen.getByTestId("calendar");
    expect(within(calendar).getAllByRole("columnheader").map((one) => one.textContent))
      .toEqual(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]);

    // October 2026 opens on a Thursday and runs five weeks, so the 1st
    // stands in the fourth column and the Monday before it is a square
    // of the month before: drawn to fill the week out, carrying nothing.
    const weeks = within(calendar).getAllByRole("row").slice(1);
    expect(weeks).toHaveLength(5);
    const first = within(weeks[0]).getAllByRole("cell");
    expect(first[3]).toHaveTextContent("1");
    expect(first[0]).toBeEmptyDOMElement();
    expect(within(weeks[1]).getAllByRole("cell")[0])
      .toContainElement(screen.getByTestId("day-2026-10-05"));
    // The day the clock is on says so, and only that one.
    expect(within(screen.getByTestId("day-2026-10-16")).getByText("today")).toBeInTheDocument();
    expect(screen.getAllByText("today")).toHaveLength(1);

    // And the entry stands in its own square with everything the
    // flattened list gave it: the kind, the hour, the name and the link.
    const fifth = screen.getByTestId("day-2026-10-05");
    expect(within(fifth).getByText("maintenance")).toBeInTheDocument();
    expect(within(fifth).getByRole("link", { name: "agent-arch" }))
      .toHaveAttribute("href", "/next/hosts/h1");
    expect(fifth).toHaveTextContent("kernel · tszymanski");
    vi.useRealTimers();
  });

  it("names what stands on each day and leads to it inside the new panel", async () => {
    Object.assign(answers, base([], [
      {
        kind: "host_window", id: "h1", name: "agent-arch",
        start: "2026-10-05T08:00:00Z", end: "2026-10-06T08:00:00Z",
        reason: "kernel", set_by: "tszymanski",
      },
      {
        kind: "campaign_window", id: "c1", name: "october patching",
        start: "2026-10-05T20:00:00Z", end: "2026-10-05T23:00:00Z", state: "running",
      },
    ]));
    // The month the screen opens on is the one the clock is in, so the
    // entries are placed in it rather than in a month of 2026.
    vi.setSystemTime(new Date("2026-10-16T09:00:00Z"));
    draw();
    await waitFor(() => expect(screen.getAllByTestId("day-2026-10-05").length).toBeGreaterThan(0));
    const rows = screen.getAllByTestId("day-2026-10-05");
    expect(rows.some((row) => within(row).queryByText("maintenance"))).toBe(true);
    expect(rows.some((row) => within(row).queryByText("window"))).toBe(true);
    // The window covers two days, so it is a row on each of them.
    expect(screen.getAllByRole("link", { name: "agent-arch" })).toHaveLength(2);
    expect(screen.getAllByRole("link", { name: "agent-arch" })[0])
      .toHaveAttribute("href", "/next/hosts/h1");
    expect(screen.getAllByRole("link", { name: "october patching" })[0])
      .toHaveAttribute("href", "/next/campaigns/c1");
    // The window runs into the next day, and says so there rather than
    // repeating an hour that belongs to the day it opened on.
    const second = screen.getAllByTestId("day-2026-10-06");
    expect(second.some((row) => row.textContent?.includes("runs through"))).toBe(true);
    expect(second.every((row) => !row.textContent?.includes("10:00"))).toBe(true);
    vi.useRealTimers();
  });

  it("asks the server for the month on screen when the month is changed", async () => {
    Object.assign(answers, base([], []));
    vi.setSystemTime(new Date("2026-10-16T09:00:00Z"));
    draw();
    await waitFor(() => expect(screen.getByTestId("calendar-month")).toHaveTextContent("2026-10"));
    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: "Next month" }));
    expect(screen.getByTestId("calendar-month")).toHaveTextContent("2026-11");
    await waitFor(() =>
      expect(asked.some((one) => one.startsWith("/api/v1/maintenance/calendar") && one.includes("2026-11")))
        .toBe(true));
    vi.useRealTimers();
  });

  it("says a month with nothing in it is empty rather than drawing nothing", async () => {
    Object.assign(answers, base([], []));
    draw();
    await waitFor(() => expect(screen.getByText("Nothing is planned in this month.")).toBeInTheDocument());
  });
});
