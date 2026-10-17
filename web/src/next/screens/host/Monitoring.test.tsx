import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host, MetricPoint } from "../../../lib/types";
import { bytes } from "../../../lib/format";
import { Monitoring, axisLabel, busiestInterface, readings, usageTone } from "./Monitoring";

/**
 * This is where the product reads its own measurements, so the one rule it
 * may not break is the one about holes: a stretch the host never reported
 * is not a stretch at nought. A point with a reading missing is dropped
 * from the drawing, the holes are said in words, and an alert list nobody
 * could read counts to a dash rather than to none.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const deleted: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key the path begins with wins: "/api/v1/hosts/h1"
        // also begins "/api/v1/hosts/h1/monitoring", and a short key
        // answering a longer path hands the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1", until: "2026-10-16T10:00:00Z", rule_name: "CPU high" });
      },
      put: () => Promise.resolve({}),
      del: (path: string) => {
        deleted.push(path);
        return Promise.resolve(undefined);
      },
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [{ name: "monitoring", version: 1, available: true, read_only: false }],
  identity: {},
} as unknown as Host;

const layout = { widgets: [], present: false, revision: 0 };

const probeAllowed = {
  version: 1,
  items: [{ action: "monitoring.probe.run", permission: "job.create", mutating: false, risk: "low", allowed: true }],
};

const point = (over: Partial<MetricPoint> & { at: string }): MetricPoint => ({
  cpu_percent: 12, load1: 0.4, load5: 0.3, load15: 0.2,
  memory_used: 1000, memory_total: 4000, memory_available: 3000, swap_used: 0, swap_total: 1000,
  uptime_seconds: 3600,
  ...over,
});

const alert = (over: Record<string, unknown> = {}) => ({
  id: "a1", rule_id: "r1", rule_name: "CPU high", metric: "cpu_percent",
  severity: "critical", state: "firing", silenced: false, value: 95,
  detail: "95% busy", fired_at: "2026-10-16T08:00:00Z", started_at: "2026-10-16T07:59:00Z",
  ...over,
});

/**
 * The module is three sub-tabs since 17.10 - what is alerting, the
 * drawings, and the two things that can be ordered - and the address
 * says which one is open. A test asks for the tab whose content it
 * reads, the way a reader following a link would.
 */
function draw(tab = "state") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/hosts/h1/monitoring?tab=${tab}`]}>
        <ToastProvider>{children}</ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Monitoring host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  deleted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the monitoring module of a host", () => {
  it("counts nothing before the state is read, and never a nought", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/hosts/h1/actions": probeAllowed });
    draw();
    const band = await screen.findByTestId("alert-states");
    // Nobody has read the alerts, so nobody has counted them: a nought
    // would say this machine is well, which nothing here knows.
    expect(band).toHaveTextContent("—");
    expect(band.querySelector(".fl-band")).toBeNull();
  });

  it("names the gaps in words rather than drawing them flat", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/metrics": {
        host_id: "h1", range: "3h", step_seconds: 60, sampling_interval_seconds: 60, source: "agent",
        points: [point({ at: "2026-10-16T08:00:00Z" }), point({ at: "2026-10-16T08:30:00Z" })],
        gaps: [{ from: "2026-10-16T08:01:00Z", to: "2026-10-16T08:29:00Z", steps: 28, reason: "clock_skew" }],
        latest: point({ at: "2026-10-16T08:30:00Z" }),
        last_sample_at: "2026-10-16T08:30:00Z",
      },
    });
    draw("charts");
    // The banner says it, and every chart repeats it at its own foot.
    await waitFor(() => expect(screen.getAllByText(/1 gaps in this window/).length).toBeGreaterThan(0));
    expect(screen.getByText(/clock_skew/)).toBeInTheDocument();
    // Two readings came back, so the chart has two columns and not thirty:
    // the twenty-eight the host never sent are nowhere on it.
    const chart = screen.getByTestId("cpu-chart");
    expect(chart.querySelectorAll(".fl-chart-axis")).toHaveLength(2);
  });

  it("draws a percentage to a hundred and labels memory in bytes, not in bare digits", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/metrics": {
        host_id: "h1", range: "3h", step_seconds: 60, sampling_interval_seconds: 60, source: "agent",
        points: [point({ at: "2026-10-16T08:00:00Z" }), point({ at: "2026-10-16T08:01:00Z" })],
        gaps: [],
        latest: point({ at: "2026-10-16T08:01:00Z" }),
        last_sample_at: "2026-10-16T08:01:00Z",
      },
    });
    draw("charts");
    await waitFor(() => expect(screen.getByTestId("cpu-chart")).toBeInTheDocument());
    // Every reading is 12%, and the axis still goes to a hundred: a chart
    // scaled to its own highest reading says a host at 12% is as loaded as
    // one at 99%.
    const cpu = [...screen.getByTestId("cpu-chart").querySelectorAll(".fl-chart-scale")]
      .map((one) => one.textContent);
    expect(cpu).toEqual(["0%", "50%", "100%"]);
    // The memory axis says what the numbers mean; 4000 on its own does not.
    const memory = [...screen.getByTestId("memory-chart").querySelectorAll(".fl-chart-scale")]
      .map((one) => one.textContent ?? "");
    expect(memory[memory.length - 1]).toBe(bytes(4000));
    expect(memory.every((one) => /[A-Za-z]/.test(one))).toBe(true);
  });

  it("silences with the reason and the window the server takes, and refuses a reason too short", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/monitoring": {
        host_id: "h1", latest: null, alerts: [alert()], silences: [], refused: [],
        clock_substitution: null, rules_matching: 3,
      },
      "/api/v1/monitoring/rules": { items: [{ id: "r1", name: "CPU high" }], count: 1, metrics: [], operators: [], severities: [] },
    });
    draw("change");
    await waitFor(() => expect(screen.getByTestId("silence")).toBeInTheDocument());
    expect(screen.getByTestId("silence")).toBeDisabled();
    fireEvent.change(screen.getByTestId("silence-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("silence")).toBeDisabled();
    fireEvent.change(screen.getByTestId("silence-reason"), { target: { value: "planned maintenance window" } });
    fireEvent.change(screen.getByTestId("silence-minutes"), { target: { value: "120" } });
    await waitFor(() => expect(screen.getByTestId("silence")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("silence"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/monitoring/silences");
    expect(posted[0].body).toMatchObject({ reason: "planned maintenance window", minutes: 120 });
  });

  it("silences the rule of the alert the button stands on", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/monitoring": {
        host_id: "h1", latest: null, alerts: [alert(), alert({ id: "a2", rule_id: "r2", rule_name: "Disk full", state: "resolved" })],
        silences: [], refused: [], clock_substitution: null, rules_matching: 3,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("alert-a1")).toBeInTheDocument());
    // Without a reason the button leads only to a refusal, so it is shut.
    expect(screen.getByTestId("silence-r1")).toBeDisabled();
    // The reason is written in the Silence form, which is a decision and
    // so lives on the change tab; the row of the alert still takes it,
    // and the tab keeps what was typed while the reader walks back.
    fireEvent.click(screen.getByRole("tab", { name: "Change" }));
    fireEvent.change(await screen.findByTestId("silence-reason"), { target: { value: "known noisy sensor" } });
    fireEvent.click(screen.getByRole("tab", { name: "State" }));
    await waitFor(() => expect(screen.getByTestId("silence-r1")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("silence-r1"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({ rule_id: "r1", reason: "known noisy sensor" });
    // A resolved alert has nothing left to silence.
    expect(within(screen.getByTestId("alert-a2")).queryByTestId("silence-r2")).toBeNull();
  });

  it("ends a fleet-wide silence on the fleet path and a host's on the host's", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/monitoring": {
        host_id: "h1", latest: null, alerts: [], refused: [], clock_substitution: null, rules_matching: 0,
        silences: [
          { id: "s1", host_id: "h1", until: "2026-10-16T10:00:00Z", reason: "mine", created_by: "me", created_at: "2026-10-16T08:00:00Z" },
          { id: "s2", until: "2026-10-16T10:00:00Z", reason: "everybody", created_by: "me", created_at: "2026-10-16T08:00:00Z" },
        ],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("unsilence-s1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("unsilence-s1"));
    await waitFor(() => expect(deleted).toContain("/api/v1/hosts/h1/monitoring/silences/s1"));
    fireEvent.click(screen.getByTestId("unsilence-s2"));
    // A silence that names no host belongs to no host, so it ends where it
    // was made.
    await waitFor(() => expect(deleted).toContain("/api/v1/monitoring/silences/s2"));
  });

  it("probes from the host and reports what the host saw", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/monitoring": {
        host_id: "h1", latest: null, alerts: [], silences: [], refused: [],
        clock_substitution: null, rules_matching: 0,
      },
      "/api/v1/jobs/job-1/attempts": {
        items: [{
          status: "succeeded",
          detail: { probe: { kind: "http", target: "https://app/health", reachable: true, passed: true, status_code: 200, duration_millis: 42 } },
        }],
      },
    });
    draw("change");
    await waitFor(() => expect(screen.getByTestId("probe")).toBeInTheDocument());
    // A half-written address is not a target: the button stays shut.
    fireEvent.change(screen.getByTestId("probe-target"), { target: { value: "app/health" } });
    expect(screen.getByTestId("probe")).toBeDisabled();
    fireEvent.change(screen.getByTestId("probe-target"), { target: { value: "https://app/health" } });
    fireEvent.change(screen.getByTestId("probe-status"), { target: { value: "200" } });
    await waitFor(() => expect(screen.getByTestId("probe")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("probe"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "monitoring.probe.run",
      payload: { monitoring: { kind: "http", target: "https://app/health", expect_status: 200 } },
    });
    await waitFor(() => expect(screen.getByText("passed")).toBeInTheDocument());
    expect(screen.getByText("42 ms")).toBeInTheDocument();
  });

  it("says the host refused a probe rather than showing a verdict nobody gave", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/monitoring": {
        host_id: "h1", latest: null, alerts: [], silences: [], refused: [],
        clock_substitution: null, rules_matching: 0,
      },
      "/api/v1/jobs/job-1/attempts": {
        items: [{ status: "failed", error_code: "probe_refused", message: "the target is outside the allowed range" }],
      },
    });
    draw("change");
    await waitFor(() => expect(screen.getByTestId("probe")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("probe-target"), { target: { value: "https://app/health" } });
    await waitFor(() => expect(screen.getByTestId("probe")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("probe"));
    await waitFor(() => expect(screen.getByText("the target is outside the allowed range")).toBeInTheDocument());
  });

  it("draws a figure the agent never reported as a dash", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": probeAllowed,
      "/api/v1/hosts/h1/metrics": {
        host_id: "h1", range: "3h", step_seconds: 60, sampling_interval_seconds: 60, source: "agent",
        points: [point({ at: "2026-10-16T08:00:00Z" })], gaps: [],
        latest: point({ at: "2026-10-16T08:00:00Z" }), last_sample_at: "2026-10-16T08:00:00Z",
      },
    });
    draw("charts");
    // An older agent does not report its own footprint; the facts say so
    // with a dash, and the chart is left out rather than drawn at nought.
    await screen.findByText(/does not report its footprint/);
    const facts = screen.getByText("Agent RSS").closest(".fl-fact") as HTMLElement;
    expect(facts).toHaveTextContent("—");
  });
});

describe("what the monitoring module knows on its own", () => {
  it("drops a point the server did not send instead of pushing a nought into it", () => {
    const points = [
      point({ at: "a", agent_rss_bytes: 10 }),
      point({ at: "b" }),
      point({ at: "c", agent_rss_bytes: 30 }),
    ];
    const read = readings(points, [(one) => one.agent_rss_bytes]);
    expect(read.labels).toEqual(["a", "c"]);
    expect(read.values[0]).toEqual([10, 30]);
    expect(read.values[0]).not.toContain(0);
  });

  it("keeps a reading the host did send at nought, because that is a fact", () => {
    const read = readings([point({ at: "a", cpu_percent: 0 })], [(one) => one.cpu_percent]);
    expect(read.values[0]).toEqual([0]);
  });

  it("drops a point where any of the series it shares a frame with is missing", () => {
    const read = readings(
      [point({ at: "a", agent_rss_bytes: 1, agent_cpu_percent: 2 }), point({ at: "b", agent_rss_bytes: 3 })],
      [(one) => one.agent_rss_bytes, (one) => one.agent_cpu_percent],
    );
    expect(read.labels).toEqual(["a"]);
  });

  it("picks the interface that moved the most, and counts how many there were", () => {
    const busiest = busiestInterface([
      point({ at: "a", interfaces: [
        { name: "eth0", rx_bytes_per_second: 10, tx_bytes_per_second: 10 },
        { name: "lo", rx_bytes_per_second: 1 },
      ] }),
    ]);
    expect(busiest).toEqual({ name: "eth0", count: 2 });
    expect(busiestInterface([point({ at: "a" })])).toBeUndefined();
  });

  it("reads a short window by the hour and a long one by the day", () => {
    expect(axisLabel("3h")("2026-10-16T08:09:00Z")).toHaveLength(5);
    expect(axisLabel("30d")("2026-10-16T08:09:00Z")).toHaveLength(5);
  });

  it("calls four fifths a warning and nine tenths a fault, and an unmeasured share neither", () => {
    expect(usageTone(95, 100)).toBe("error");
    expect(usageTone(85, 100)).toBe("warn");
    expect(usageTone(10, 100)).toBe("ok");
    expect(usageTone(undefined, 100)).toBe("neutral");
    expect(usageTone(1, 0)).toBe("neutral");
  });
});
