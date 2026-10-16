import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import {
  Logs, bootFilterSupport, bootParam, findMatches, followPayload, followSummary, jobWindow,
  logFileName, suppressedNotice, suppressionCountSupport, utcStamp,
} from "./Logs";

/**
 * Three kinds of nothing live on this module and the panel may not merge
 * them: the lines a view could not carry, the messages the host never
 * wrote at all, and a count an older agent cannot take. The first two are
 * numbers; the third is a dash with a reason. What is held here is that,
 * plus the one rule of every read - it is bounded, and a refusal says why.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key the path begins with wins: "/api/v1/jobs" also
        // begins "/api/v1/jobs/x/attempts", and a short key answering a
        // longer path hands the screen somebody else's document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1" });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

// The live view arrives over a stream this test has no business opening;
// what it carries is handed in instead.
const stream = { lines: [] as string[], dropped: 0 };
vi.mock("../../../lib/stream", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/stream")>();
  return { ...actual, useJournalPreview: () => stream };
});

const journald = (features: Record<string, boolean>) =>
  ({ name: "journald", version: 1, available: true, read_only: false, features });

const host = (over: Record<string, unknown> = {}) => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [journald({ boot_filter: true, suppression_notice: true })],
  identity: {},
  ...over,
} as unknown as Host);

const layout = { widgets: [], present: false, revision: 0 };

const reads = {
  version: 1,
  items: ["journal.read", "logfile.read", "journal.follow"].map((action) => ({
    action, permission: "job.create", mutating: false, risk: "low", allowed: true,
  })),
};

function draw(at = "/next/hosts/h1/logs", on: Host = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Logs host={on} />, { wrapper });
}

beforeEach(() => {
  stream.lines = [];
  stream.dropped = 0;
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the logs module of a host", () => {
  it("asks the host for a bounded read and shows exactly what came back", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": reads,
      "/api/v1/jobs/job-1/attempts": {
        items: [{ status: "succeeded", detail: { lines: ["first line", "second line"], truncated: true } }],
      },
    });
    draw();
    await screen.findByTestId("read");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fireEvent.change(screen.getByTestId("unit"), { target: { value: "sshd.service" } });
    fireEvent.change(screen.getByTestId("priority"), { target: { value: "3" } });
    fireEvent.change(screen.getByTestId("line-count"), { target: { value: "50" } });
    fireEvent.click(screen.getByTestId("read"));
    await vi.advanceTimersByTimeAsync(2000);
    vi.useRealTimers();

    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "journal.read",
      payload: { journal: { unit: "sshd.service", lines: 50, max_priority: 3 } },
    });
    await waitFor(() => expect(screen.getByTestId("log-output")).toHaveTextContent("second line"));
    // What the host said about the read itself stays with the lines.
    expect(screen.getByText(/output truncated/)).toBeInTheDocument();
  });

  it("says why the host refused, instead of showing an empty output", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": reads,
      "/api/v1/jobs/job-1/attempts": {
        items: [{ status: "failed", error_code: "path_not_allowed", message: "/etc/shadow is not on the allowlist" }],
      },
    });
    draw();
    await screen.findByTestId("read");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fireEvent.click(screen.getByTestId("read"));
    await vi.advanceTimersByTimeAsync(2000);
    vi.useRealTimers();
    await waitFor(() => expect(screen.getByText("/etc/shadow is not on the allowlist")).toBeInTheDocument());
    expect(screen.queryByTestId("log-output")).toBeNull();
  });

  it("counts nothing before a read, and never draws a nought for it", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/hosts/h1/actions": reads });
    draw();
    const band = await screen.findByTestId("line-counts");
    // Nothing has been read, so no line has been sorted: every count is a
    // dash. A nought here would say the host logged nothing.
    expect(band).toHaveTextContent("—");
    expect(band.querySelector(".fl-band")).toBeNull();
    expect(screen.getByText("nothing read yet")).toBeInTheDocument();
  });

  it("will not send a boot filter the agent cannot apply", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout, "/api/v1/hosts/h1/actions": reads });
    const old = host({ capabilities: [journald({ suppression_notice: true })] });
    draw("/next/hosts/h1/logs?boot=" + "a".repeat(32), old);
    await screen.findByTestId("read");
    expect(screen.getByTestId("boot-filter")).toBeInTheDocument();
    expect(screen.getByTestId("read")).toBeDisabled();
    expect(screen.getByText("not applied")).toBeInTheDocument();
    expect(posted).toHaveLength(0);
  });

  it("follows the journal and stops by cancelling the job behind it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": reads,
      "/api/v1/jobs/job-1/attempts": { items: [{ status: "succeeded", stdout: "" }] },
    });
    stream.lines = ["a live line"];
    draw();
    await screen.findByTestId("follow");
    fireEvent.click(screen.getByTestId("follow"));
    await waitFor(() => expect(screen.getByTestId("stop")).toBeInTheDocument());
    expect(posted[0].body).toMatchObject({
      action: "journal.follow",
      payload: { journal: { follow_seconds: 300, lines: 50 } },
    });
    expect(screen.getByTestId("log-output")).toHaveTextContent("a live line");

    vi.useFakeTimers({ shouldAdvanceTime: true });
    fireEvent.click(screen.getByTestId("stop"));
    await vi.advanceTimersByTimeAsync(2000);
    vi.useRealTimers();
    // Closing the stream is not enough: the follow is a task on the host,
    // and only a cancellation interrupts it there.
    await waitFor(() => expect(posted.some((one) => one.path === "/api/v1/jobs/job-1/cancel")).toBe(true));
  });

  it("finds the searched text and says how many lines carry it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": reads,
      "/api/v1/jobs/job-1/attempts": {
        items: [{ status: "succeeded", detail: { lines: ["sshd accepted", "cron ran", "sshd refused"] } }],
      },
    });
    draw();
    await screen.findByTestId("read");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fireEvent.click(screen.getByTestId("read"));
    await vi.advanceTimersByTimeAsync(2000);
    vi.useRealTimers();
    await waitFor(() => expect(screen.getByTestId("log-output")).toBeInTheDocument());

    fireEvent.change(screen.getByTestId("search"), { target: { value: "sshd" } });
    expect(screen.getByTestId("match-count")).toHaveTextContent("1 of 2 matches");
    expect(screen.getByTestId("current-match")).toHaveTextContent("sshd accepted");
    fireEvent.click(screen.getByTestId("next-match"));
    expect(screen.getByTestId("current-match")).toHaveTextContent("sshd refused");
    fireEvent.change(screen.getByTestId("search"), { target: { value: "nothing like this" } });
    expect(screen.getByTestId("match-count")).toHaveTextContent("0 matches");
  });
});

describe("what the logs module knows on its own", () => {
  it("bounds a read to the window of a job, with a margin after its end", () => {
    const window_ = jobWindow(
      { finished_at: "2026-10-16T08:00:30Z", payload: { unit: { unit: "sshd.service" } } } as never,
      [{ dispatched_at: "2026-10-16T08:00:00Z" } as never],
    );
    expect(window_).toEqual({
      since: "2026-10-16 08:00:00 UTC",
      until: "2026-10-16 08:01:00 UTC",
      unit: "sshd.service",
    });
  });

  it("gives no window for a job the host has not been handed yet", () => {
    expect(jobWindow({ payload: {} } as never, [])).toBeNull();
    expect(jobWindow(undefined, undefined)).toBeNull();
  });

  it("writes a moment the way journalctl takes it", () => {
    expect(utcStamp(Date.parse("2026-10-16T08:09:07Z"))).toBe("2026-10-16 08:09:07 UTC");
  });

  it("finds the lines that carry the text, whatever case they wrote it in", () => {
    expect(findMatches(["SSHD up", "cron", "sshd down"], "sshd")).toEqual([0, 2]);
    expect(findMatches(undefined, "sshd")).toEqual([]);
    expect(findMatches(["a"], "   ")).toEqual([]);
  });

  it("names a saved file after the host, the source and the moment", () => {
    expect(logFileName("agent-arch", "/var/log/syslog", Date.parse("2026-10-16T08:09:07Z")))
      .toBe("agent-arch-var-log-syslog-20261016080907.log");
  });

  it("takes a boot identifier only in the form the journal uses", () => {
    expect(bootParam("A1B2-C3D4".padEnd(40, "0"))).toBe("");
    expect(bootParam("a".repeat(32))).toBe("a".repeat(32));
    expect(bootParam(null)).toBe("");
  });

  it("leaves out of a follow every filter nobody set", () => {
    expect(followPayload({})).toEqual({
      unit: undefined, lines: 50, max_priority: undefined, follow_seconds: 300,
      since: undefined, after_cursor: undefined, boot_id: undefined,
    });
  });

  it("refuses a boot filter the agent cannot apply, and says which reason it is", () => {
    expect(bootFilterSupport([journald({ boot_filter: true })], (text) => text).supported).toBe(true);
    const old = bootFilterSupport([journald({})], (text) => text);
    expect(old.supported).toBe(false);
    expect(old.reason).toMatch(/cannot filter the journal by boot/);
    const none = bootFilterSupport([], (text) => text);
    expect(none.reason).toMatch(/no journald adapter/);
  });

  it("keeps a count the host answered with apart from one nobody could take", () => {
    const can = { supported: true };
    const t = (text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, name) => String(params?.[name] ?? ""));
    // A nought the host did answer with is a fact and stands.
    expect(suppressedNotice({ host_suppressed: 0 }, can, t).count).toBe(0);
    expect(suppressedNotice({ host_suppressed: 7 }, can, t).count).toBe(7);
    // A summary that said nothing about it leaves no count at all: the
    // dash must never borrow the dropped lines of the view.
    const unknown = suppressedNotice(null, { supported: false, reason: "the agent is too old" }, t);
    expect(unknown.count).toBeUndefined();
    expect(unknown.text).toBe("the agent is too old");
    const hidden = suppressedNotice({ host_suppressed_unknown_reason: "priority_filter" }, can, t);
    expect(hidden.count).toBeUndefined();
    expect(hidden.text).toMatch(/priority filter/);
  });

  it("reads a summary only from a view that wrote one", () => {
    expect(followSummary(JSON.stringify({ kind: "journal_follow", lines_sent: 3 }))).toEqual({
      kind: "journal_follow", lines_sent: 3,
    });
    expect(followSummary("not json")).toBeNull();
    expect(followSummary(JSON.stringify({ kind: "something_else" }))).toBeNull();
    expect(followSummary(undefined)).toBeNull();
  });

  it("counts the host's own suppression only where the agent takes that count", () => {
    expect(suppressionCountSupport([journald({ suppression_notice: true })], (text) => text).supported).toBe(true);
    expect(suppressionCountSupport([journald({})], (text) => text).reason).toMatch(/says unknown, never zero/);
  });
});
