import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Audit, actorKey, actorView, changedKeys, eventsPerHour, exportFileName, outcomeTone, targetLink, toLocalInput } from "./Audit";
import { ToastProvider } from "../../components/Toast";

/**
 * The trail is read for three things, and all three are held here: that a
 * question is put to the server rather than sifted on the screen, that a
 * refusal is told apart from a failure and from a success, and that an
 * event opens into what it actually did - both sides of a change
 * included.
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
        // The longest key wins: "/api/v1/audit" would otherwise answer
        // "/api/v1/audit/export" and hand the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        // Nothing answered is nothing this reader may see: the server
        // refuses a trail it has no permission for, and so does this.
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        return Promise.resolve(answers[key]);
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const event = (over: Record<string, unknown>) => ({
  id: 1,
  occurred_at: "2026-10-16T08:00:00Z",
  actor_type: "user",
  actor_id: "tszymanski",
  action: "host.enrollment.replace",
  target_type: "host",
  target_id: "377802f9-a0e9-4afa-ad68-293a0873bcf3",
  target_hostname: "agent-arch",
  outcome: "success",
  detail: {},
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Audit />, { wrapper });
}

afterEach(() => { cleanup(); asked.length = 0; for (const key of Object.keys(answers)) delete answers[key]; });

describe("the trail", () => {
  it("draws an event as who acted, what they did and how it came out", async () => {
    Object.assign(answers, {
      "/api/v1/audit": { items: [event({})], count: 1 },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-1")).toBeInTheDocument());
    const row = screen.getByTestId("event-1");
    expect(row).toHaveTextContent("tszymanski");
    expect(row).toHaveTextContent("host.enrollment.replace");
    expect(within(row).getByText("success")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "agent-arch" })).toHaveAttribute(
      "href", "/hosts/377802f9-a0e9-4afa-ad68-293a0873bcf3",
    );
  });

  it("keeps an operation on one line, so an identifier is cut rather than broken in two", async () => {
    Object.assign(answers, { "/api/v1/audit": { items: [event({})], count: 1 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-1")).toBeInTheDocument());
    const cell = screen.getByText("host.enrollment.replace").closest("td");
    expect(cell).toHaveClass("fl-tight");
    // The whole of it is on hover; the cell shows as much as it has room for.
    expect(screen.getByText("host.enrollment.replace")).toHaveAttribute("title", "host.enrollment.replace");
  });

  it("tells a refusal apart from a failure and from a success", async () => {
    Object.assign(answers, {
      "/api/v1/audit": {
        items: [
          event({ id: 1, outcome: "success" }),
          event({ id: 2, outcome: "denied", action: "host.delete" }),
          event({ id: 3, outcome: "failure", action: "job.create" }),
        ],
        count: 3,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-3")).toBeInTheDocument());
    const pill = (id: string, word: string) => within(screen.getByTestId(id)).getByText(word);
    expect(pill("event-1", "success")).toHaveClass("fl-ok");
    expect(pill("event-2", "denied")).toHaveClass("fl-warn");
    expect(pill("event-3", "failure")).toHaveClass("fl-error");
    // And the three are counted apart above the list.
    const band = screen.getByTestId("outcomes");
    expect(band).toHaveTextContent("denied");
    expect(band).toHaveTextContent("failure");
  });

  it("asks the server with what was typed, rather than sifting a page here", async () => {
    Object.assign(answers, { "/api/v1/audit": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("actor")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("actor"), { target: { value: "tszymanski" } });
    fireEvent.change(screen.getByTestId("action"), { target: { value: "job.create" } });
    await waitFor(
      () => expect(asked.some((one) => one.includes("actor=tszymanski") && one.includes("action=job.create"))).toBe(true),
      { timeout: 3000 },
    );
    // And the limit goes with it: the server pages the trail, the screen does not.
    expect(asked.some((one) => one.includes("limit="))).toBe(true);
  });

  it("asks the server for one outcome", async () => {
    Object.assign(answers, { "/api/v1/audit": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("outcome")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("outcome"), { target: { value: "denied" } });
    await waitFor(() => expect(asked.some((one) => one.includes("outcome=denied"))).toBe(true));
  });

  it("carries the approval and the changed fields under the row, unasked", async () => {
    Object.assign(answers, {
      "/api/v1/audit": {
        items: [
          event({
            id: 7,
            action: "host.owner",
            before: { owner: "tszymanski", site: "lab" },
            after: { owner: "akowalska", site: "lab" },
            approval_chain: { created_by: "tszymanski", approvers: ["akowalska"] },
          }),
          event({ id: 8, action: "host.read" }),
        ],
        count: 2,
      },
    });
    draw();
    // Read on the way past: the trail is scanned before anything is opened.
    const line = await screen.findByTestId("under-7");
    expect(line).toHaveTextContent("Ordered by tszymanski");
    expect(line).toHaveTextContent("owner");
    expect(line).toHaveTextContent("akowalska");
    expect(line).not.toHaveTextContent("site");
    // An event that approved nothing and moved nothing says nothing.
    expect(screen.queryByTestId("under-8")).toBeNull();
  });

  it("opens an event into both sides of what it changed", async () => {
    Object.assign(answers, {
      "/api/v1/audit": {
        items: [event({
          id: 7,
          action: "host.owner",
          before: { owner: "tszymanski", site: "lab" },
          after: { owner: "akowalska", site: "lab" },
          session_id: "0f3a9c1d2b4e",
          approval_chain: { created_by: "tszymanski", approvers: ["akowalska"] },
          detail: { reason: "handover" },
        })],
        count: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-7")).toBeInTheDocument());
    expect(screen.queryByTestId("changes")).toBeNull();
    fireEvent.click(screen.getByTestId("open-7"));
    const changes = await screen.findByTestId("changes");
    // Only what differs: the site stood still and is not a change.
    expect(changes).toHaveTextContent("owner");
    expect(changes).toHaveTextContent("tszymanski");
    expect(changes).toHaveTextContent("akowalska");
    expect(changes).not.toHaveTextContent("site");
    // Twice over: the row carries it unasked, and the open event repeats
    // it among the rest of what the trail kept.
    expect(screen.getAllByText(/Ordered by tszymanski/)).toHaveLength(2);
  });

  /**
   * The event opens under the row it belongs to, across the width of the
   * list - which is where the panel being replaced read it. A card
   * elsewhere on the board makes the reader hunt for the thing they just
   * clicked, and the row they were on scrolls away while they do.
   */
  it("opens the event under its own row, and closes it again from there", async () => {
    Object.assign(answers, {
      "/api/v1/audit": {
        items: [
          event({ id: 7, action: "host.owner", before: { owner: "a" }, after: { owner: "b" } }),
          event({ id: 8, action: "job.create" }),
        ],
        count: 2,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-7")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-7"));

    const detail = await screen.findByTestId("changes");
    // The detail is a row of the events table, not a card beside it.
    const opened = detail.closest("tr.fl-row-detail");
    expect(opened).not.toBeNull();
    expect(opened?.closest("table")).toBe(screen.getByTestId("events"));
    // And it stands directly under the row it belongs to.
    expect(opened?.previousElementSibling).toBe(screen.getByTestId("event-7"));

    fireEvent.click(screen.getByTestId("open-7"));
    await waitFor(() => expect(screen.queryByTestId("changes")).toBeNull());
  });

  /**
   * An incident is read key by key, and the field somebody opens an
   * event for is often one the panel has no sentence about. The record
   * itself stands under the facts, as it did on the old screen.
   */
  it("keeps the whole record under the facts, verbatim", async () => {
    Object.assign(answers, {
      "/api/v1/audit": {
        items: [event({ id: 11, action: "job.create", detail: { odd_field: "nobody wrote a sentence for this" } })],
        count: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-11")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-11"));
    const record = await screen.findByTestId("event-record-11");
    expect(record).toHaveTextContent("odd_field");
    expect(record).toHaveTextContent("nobody wrote a sentence for this");
  });

  it("says a refusal to read the trail in words, rather than drawing an empty list", async () => {
    draw();
    await waitFor(() => expect(
      screen.getByText("You may not read the fleet-wide trail. The trail of a single host is on that host's own screen."),
    ).toBeInTheDocument());
  });
});

describe("the facts of an event", () => {
  const hostID = "377802f9-a0e9-4afa-ad68-293a0873bcf3";
  const t = (text: string) => text;

  it("colours a refusal as a thing to read, not as a fault", () => {
    expect(outcomeTone("success")).toBe("ok");
    expect(outcomeTone("failure")).toBe("error");
    expect(outcomeTone("denied")).toBe("warn");
    // An outcome the panel does not know is not a success.
    expect(outcomeTone("something else")).toBe("unknown");
  });

  it("shows the name the actor had and keeps the identifier it does not lose", () => {
    expect(actorView({
      actor_type: "user", actor_id: "alice",
      actor: { principal_id: "p1", subject: "alice", display_name: "Alice Kowalska", kind: "user" },
    }, t)).toEqual({ text: "Alice Kowalska", id: "p1", kind: "user" });
    // A host identifier with a snapshot that names no host: the host is
    // gone, and the identifier is not turned into a screen.
    expect(actorView({ actor_type: "agent", actor_id: hostID, actor: { subject: hostID, kind: "agent" } }, t).to)
      .toBeUndefined();
    expect(actorView({
      actor_type: "agent", actor_id: "relay-warsaw",
      actor: { subject: "relay-warsaw", kind: "relay", resource_type: "relay", resource_id: "r1", resource_name: "relay-warsaw" },
    }, t).to).toBe("/relays/r1");
  });

  it("groups by the identifier, so a rename stays one actor", () => {
    const before = { actor_type: "user", actor_id: "alice", actor: { principal_id: "p1", display_name: "Alice", kind: "user" } };
    const after = { actor_type: "user", actor_id: "alice", actor: { principal_id: "p1", display_name: "Alicja", kind: "user" } };
    expect(actorKey(before)).toBe(actorKey(after));
    expect(actorKey({ actor_type: "system", actor_id: "panel" })).toBe("system:panel");
  });

  it("leads to the target where the new panel has a screen for it", () => {
    expect(targetLink("host", hostID)).toBe(`/hosts/${hostID}`);
    expect(targetLink("nothing", "x")).toBeNull();
    expect(targetLink("host", undefined)).toBeNull();
  });

  it("reads the two sides of a change and says nothing where nothing moved", () => {
    expect(changedKeys({ a: 1, b: 2 }, { a: 1, b: 3 })).toEqual([{ key: "b", before: "2", after: "3" }]);
    // An empty string against a missing key is the same nothing twice over.
    expect(changedKeys({ note: "" }, {})).toEqual([]);
    expect(changedKeys(undefined, undefined)).toEqual([]);
    expect(changedKeys({}, { owner: "akowalska" })).toEqual([{ key: "owner", before: "—", after: "akowalska" }]);
  });

  it("buckets what was read by the hour, with the outcomes side by side", () => {
    const hourly = eventsPerHour([
      event({ id: 1, occurred_at: "2026-10-16T08:10:00Z", outcome: "success" }),
      event({ id: 2, occurred_at: "2026-10-16T08:40:00Z", outcome: "denied" }),
      event({ id: 3, occurred_at: "2026-10-16T10:05:00Z", outcome: "failure" }),
    ] as unknown as Parameters<typeof eventsPerHour>[0]);
    expect(hourly.labels).toHaveLength(3);
    expect(hourly.success).toEqual([1, 0, 0]);
    expect(hourly.denied).toEqual([1, 0, 0]);
    expect(hourly.failure).toEqual([0, 0, 1]);
    expect(eventsPerHour([]).labels).toEqual([]);
  });

  it("keeps the name the server gave the export, and reads a bound that is not a date as none", () => {
    expect(exportFileName('attachment; filename="audit-from-20260901T000000Z.jsonl"'))
      .toBe("audit-from-20260901T000000Z.jsonl");
    expect(exportFileName(null)).toBe("audit.jsonl");
    expect(toLocalInput("not a date")).toBe("");
    expect(toLocalInput(null)).toBe("");
  });
});
