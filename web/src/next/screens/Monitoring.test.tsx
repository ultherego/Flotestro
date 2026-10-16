import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Monitoring, alertStateName, alertStateTone, describeCondition, describeSelector,
  metricValue, policyLabel, severityTone,
} from "./Monitoring";
import { ToastProvider } from "../../components/Toast";

/**
 * What this screen must not say.
 *
 * A reading that stopped is not a reading of nought, so a no-data episode
 * carries no value and does not wear the colour of something that passed.
 * A fleet the server has not answered for yet is unknown, not quiet. And
 * the alert list narrows on the server, so a filter is a question put to
 * the API rather than a sieve over a page that is already loaded.
 */

const asked: string[] = [];
const sent: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

/** A path that is held open: the query never settles, so the screen is loading. */
const PENDING = Symbol("pending");

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest matching key wins: "/api/v1/monitoring" is the head of
        // every other monitoring path, and a short key answering a longer
        // one would hand the screen somebody else's document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        if (answers[key] === PENDING) return new Promise(() => {});
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body: unknown) => {
        sent.push({ path, body });
        return Promise.resolve({ id: "a1", hostname: "db-01", rule_name: "root nearly full", note: "looking at it", until: "2026-10-16T12:00:00Z" });
      },
      put: (path: string, body: unknown) => {
        sent.push({ path, body });
        return Promise.resolve({ id: "r1", name: "root nearly full", enabled: false });
      },
      del: (path: string) => {
        sent.push({ path, body: undefined });
        return Promise.resolve(undefined);
      },
    },
  };
});

const alert = (over: Record<string, unknown>) => ({
  id: "a1", rule_id: "r1", rule_name: "root nearly full", metric: "filesystem_used_percent",
  severity: "critical", state: "firing", value: 94.2, detail: "/ at 94%",
  started_at: "2026-10-16T08:00:00Z", fired_at: "2026-10-16T08:05:00Z", resolved_at: null,
  silenced: false, host_id: "h1", hostname: "db-01",
  ...over,
});

const rule = (over: Record<string, unknown>) => ({
  id: "r1", name: "root nearly full", metric: "filesystem_used_percent", operator: "gt",
  threshold: 90, for_minutes: 5, severity: "critical", selector: {}, enabled: true,
  expected_cadence_seconds: 60, max_gap_seconds: 120, no_data_policy: "unknown",
  created_by: "tszymanski", created_at: "2026-10-16T07:00:00Z", updated_at: "2026-10-16T07:00:00Z",
  ...over,
});

const fleet = (over: Record<string, unknown>) => ({
  firing: [alert({})],
  counts: { critical: 1, warning: 0, info: 0, silenced: 0, acknowledged: 0, no_data: 0, pending: 0 },
  firing_total: 1, partial: false, hosts_reporting: 7, hosts_silent: 0, rules: 3,
  agent_footprint: {
    hosts_measured: 7, rss_bytes_max: 40000000, rss_bytes_median: 30000000,
    cpu_percent_max: 1.2, cpu_percent_median: 0.4,
    rss_budget_bytes: 64000000, cpu_budget_percent: 2, over_budget: [],
  },
  generated_at: "2026-10-16T09:00:00Z",
  ...over,
});

/** Every path the screen reads, so no short key answers a longer one. */
function serve(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/whoami": { permissions: ["monitoring.rules.write", "monitoring.silence.write"] },
    "/api/v1/monitoring": fleet({}),
    "/api/v1/monitoring/rules": { items: [rule({})], count: 1, metrics: ["filesystem_used_percent"], operators: ["gt"], severities: ["critical", "warning", "info"] },
    "/api/v1/monitoring/alerts": { items: [], count: 0, total: 0 },
    "/api/v1/monitoring/silences": { items: [], count: 0, can_silence_fleet: true, can_silence_global: false },
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    ...over,
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Monitoring />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("a firing alert", () => {
  it("says which host, which rule, what it read and since when", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a1")).toBeInTheDocument());
    const row = screen.getByTestId("firing-a1");
    expect(within(row).getByRole("link", { name: "db-01" })).toHaveAttribute("href", "/next/hosts/h1/monitoring");
    expect(row).toHaveTextContent("root nearly full");
    expect(row).toHaveTextContent("filesystem_used_percent");
    // The reading carries its unit: a bare 94.2 is not a percentage.
    expect(row).toHaveTextContent("94.2%");
    expect(within(row).getByText("firing")).toBeInTheDocument();
    expect(within(row).getByText("nobody")).toBeInTheDocument();
  });

  it("marks an alert somebody took, so it is not counted as waiting", async () => {
    serve({
      "/api/v1/monitoring": fleet({
        firing: [alert({ acknowledged_at: "2026-10-16T08:30:00Z", acknowledged_by: "tszymanski" })],
        counts: { critical: 0, warning: 0, info: 0, silenced: 0, acknowledged: 1, no_data: 0, pending: 0 },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a1")).toBeInTheDocument());
    const row = screen.getByTestId("firing-a1");
    expect(within(row).getByText("acknowledged")).toBeInTheDocument();
    expect(within(row).getByText(/tszymanski/)).toBeInTheDocument();
    // Nothing is waiting for a person, and the headline says that rather
    // than repeating the number of alerts there are.
    expect(screen.getByTestId("kpi-Waiting for somebody")).toHaveAttribute("data-state", "ok");
  });
});

describe("a severity", () => {
  it("keeps its colour: critical is a fault, info is a note", () => {
    expect(severityTone("critical")).toBe("error");
    expect(severityTone("warning")).toBe("warn");
    expect(severityTone("info")).toBe("info");
  });

  it("wears that colour on the pill of the row, not on a frame round the card", async () => {
    serve({
      "/api/v1/monitoring": fleet({
        firing: [alert({}), alert({ id: "a2", severity: "warning", rule_name: "swap in use" })],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a2")).toBeInTheDocument());
    const critical = within(screen.getByTestId("firing-a1")).getByText("critical");
    const warning = within(screen.getByTestId("firing-a2")).getByText("warning");
    expect(critical).toHaveClass("fl-pill", "fl-error");
    expect(warning).toHaveClass("fl-pill", "fl-warn");
    // The card around them carries no state of its own.
    expect(critical.closest(".fl-card")).not.toHaveClass("fl-error");
  });
});

describe("what nobody could evaluate", () => {
  it("reads as unknown rather than as a reading of nought", async () => {
    serve({
      "/api/v1/monitoring": fleet({
        firing: [alert({ state: "no_data", value: 0, detail: "no sample for 14 minutes" })],
        counts: { critical: 0, warning: 0, info: 0, silenced: 0, acknowledged: 0, no_data: 1, pending: 0 },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a1")).toBeInTheDocument());
    const row = screen.getByTestId("firing-a1");
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    // The value nobody has is not 0% and not 0.
    expect(row).not.toHaveTextContent("0%");
    // And the state is not the colour of something that came out well.
    const state = within(row).getByText("no data");
    expect(state).toHaveClass("fl-warn");
    expect(state).not.toHaveClass("fl-ok");
  });

  it("colours a no-data episode as a warning and never as resolved", () => {
    expect(alertStateTone("no_data")).toBe("warn");
    expect(alertStateName("no_data")).toBe("no data");
    expect(alertStateTone("resolved")).toBe("ok");
    // A silenced alert is still firing; only nobody is being told.
    expect(alertStateName("firing", true)).toBe("firing, silenced");
    expect(alertStateTone("firing", true)).toBe("neutral");
    expect(alertStateTone("firing", false)).toBe("error");
    // A window still filling has judged nothing yet.
    expect(alertStateTone("pending")).toBe("unknown");
  });

  it("leaves the headline figures unknown while the server has not answered", async () => {
    serve({ "/api/v1/monitoring": PENDING });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Waiting for somebody")).toBeInTheDocument());
    for (const label of ["Waiting for somebody", "Hosts reporting", "Gone quiet", "Rules enabled"]) {
      const tile = screen.getByTestId(`kpi-${label}`);
      expect(tile).toHaveAttribute("data-state", "unknown");
      expect(tile).toHaveTextContent("—");
      // A fleet nobody has asked is not a fleet with nothing wrong.
      expect(tile).not.toHaveTextContent(/\b0\b/);
    }
  });

  it("says a footprint no agent reported is unknown, not nothing", async () => {
    serve({
      "/api/v1/monitoring": fleet({
        agent_footprint: {
          hosts_measured: 0, rss_budget_bytes: 64000000, cpu_budget_percent: 2, over_budget: [],
        },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByText("No agent has sent its footprint yet; an older agent does not.")).toBeInTheDocument());
    const median = screen.getByText("Median RSS").closest(".fl-fig") as HTMLElement;
    expect(median).toHaveClass("fl-unknown");
    expect(median).toHaveTextContent("—");
  });
});

describe("the rules", () => {
  it("reads a rule as its condition, how long it must hold and what a gap means", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-root nearly full")).toBeInTheDocument());
    const row = screen.getByTestId("rule-root nearly full");
    expect(row).toHaveTextContent("filesystem_used_percent > 90%");
    expect(row).toHaveTextContent("5 min");
    expect(row).toHaveTextContent("mark unknown");
    expect(row).toHaveTextContent("gap ≤ 2 min");
    expect(within(row).getByText("whole fleet")).toBeInTheDocument();
  });

  it("says a fleet with no rule is unwatched rather than well", async () => {
    serve({ "/api/v1/monitoring/rules": { items: [], count: 0, metrics: [], operators: [], severities: [] } });
    draw();
    await waitFor(() => expect(
      screen.getByText("No rules yet: the agents sample, but nothing turns the samples into alerts."),
    ).toBeInTheDocument());
  });

  it("turns a rule off on the server", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-root nearly full")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("rule-root nearly full")).getByRole("checkbox"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/monitoring/rules/r1")).toBe(true));
    expect((sent[0].body as { enabled: boolean }).enabled).toBe(false);
  });

  it("asks before deleting a rule, and names what the deletion does", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-root nearly full")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("rule-root nearly full")).getByRole("button", { name: "Delete" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("Its alerts resolve on the next evaluation.");
    fireEvent.click(screen.getByTestId("confirm-delete"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/monitoring/rules/r1")).toBe(true));
  });
});

describe("narrowing the alert list", () => {
  it("puts the filter to the server rather than sifting the page", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("alert-state")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("alert-state"), { target: { value: "no_data" } });
    await waitFor(() => expect(asked.some((one) => one.includes("state=no_data"))).toBe(true));
    fireEvent.change(screen.getByTestId("alert-taken"), { target: { value: "waiting" } });
    await waitFor(() => expect(asked.some((one) => one.includes("acknowledged=false"))).toBe(true));
  });

  it("says how much of a longer list is on screen", async () => {
    serve({
      "/api/v1/monitoring/alerts": { items: [alert({ id: "h-1", state: "resolved", resolved_at: "2026-10-16T08:40:00Z" })], count: 1, total: 312 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("history-shown")).toHaveTextContent("1 of 312 shown"));
  });
});

describe("taking an alert", () => {
  it("will not acknowledge without a sentence for the trail", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a1")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("firing-a1")).getByRole("button", { name: "Acknowledge" }));
    expect(screen.getByTestId("confirm-reason")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "short" } });
    expect(screen.getByTestId("confirm-reason")).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "draining the log partition" } });
    fireEvent.click(screen.getByTestId("confirm-reason"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/monitoring/alerts/a1/acknowledge")).toBe(true));
    expect(sent[0].body).toEqual({ note: "draining the log partition" });
  });

  it("silences one alert on its own host, with a reason and an end", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("firing-a1")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("firing-a1")).getByRole("button", { name: "Silence" }));
    fireEvent.change(screen.getByTestId("silence-reason"), { target: { value: "migrating the volume" } });
    fireEvent.click(screen.getByTestId("confirm-silence"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/hosts/h1/monitoring/silences")).toBe(true));
    expect(sent[0].body).toMatchObject({ reason: "migrating the volume", minutes: 60, rule_id: "r1" });
  });
});

describe("the board the server bounded", () => {
  it("says the rows are a part of the alerts, and the counts are not", async () => {
    serve({
      "/api/v1/monitoring": fleet({
        partial: true, partial_reason: "cap_reached", firing_total: 900,
        counts: { critical: 900, warning: 0, info: 0, silenced: 0, acknowledged: 0, no_data: 0, pending: 0 },
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("board-capped")).toBeInTheDocument());
    expect(screen.getByTestId("board-capped")).toHaveTextContent("1 of 900 shown");
    expect(screen.getByTestId("board-capped")).toHaveTextContent("a cap on rows ended the answer before its last row");
    // The headline counts the whole of it, which is the point of saying so.
    expect(screen.getByTestId("kpi-Waiting for somebody")).toHaveTextContent("900");
  });
});

describe("the words a rule is read in", () => {
  it("writes a condition, a scope and a policy the way an operator says them", () => {
    expect(describeCondition({ metric: "cpu_percent", operator: "gte", threshold: 80 })).toBe("cpu_percent ≥ 80%");
    expect(describeCondition({ metric: "agent_rss_bytes", operator: "gt", threshold: 67108864 })).toBe("agent_rss_bytes > 64 MiB");
    expect(describeSelector(undefined)).toBe("whole fleet");
    expect(describeSelector({ site: "waw", tags: ["role=db"], owner: "dba" })).toBe("site=waw, tag=role=db, owner=dba");
    expect(policyLabel(undefined)).toBe("ignore gaps");
    expect(policyLabel("alert")).toBe("alert on a gap");
    // Minutes without a sample is a count of minutes, not a bare number.
    expect(metricValue("host_offline", 14)).toBe("14 min");
  });
});
