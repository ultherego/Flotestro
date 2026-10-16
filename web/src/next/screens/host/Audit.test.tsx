import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { AuditEvent, Host } from "../../../lib/types";
import { Audit, actorLabel, digest } from "./Audit";

/**
 * The trail of one machine. A refusal is not a failure and neither is a
 * success, so the three are counted apart; what nobody has read yet counts
 * to a dash; and the whole record of an event opens verbatim, because an
 * incident is read key by key and not column by column.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};
let refuse = false;

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        if (refuse && path.includes("/audit")) {
          return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        }
        // The longest key the path begins with wins: "/api/v1/hosts/h1"
        // also begins "/api/v1/hosts/h1/audit", and a short key answering
        // a longer path hands the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: () => Promise.resolve({}),
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
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
  capabilities: [], identity: {},
} as unknown as Host;

const event = (over: Record<string, unknown> = {}) => ({
  id: 1, occurred_at: "2026-10-16T08:00:00Z", actor_type: "user", actor_id: "tszymanski",
  action: "unit.restart", outcome: "success", target_type: "host", target_id: "h1",
  detail: { reason: "the service was wedged" },
  ...over,
}) as unknown as AuditEvent;

const layout = { widgets: [], present: false, revision: 0 };

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Audit host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  refuse = false;
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the audit module of a host", () => {
  it("reads this host's trail and draws an event as who, what and how it ended", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/audit": { count: 1, items: [event()] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-1")).toBeInTheDocument());
    expect(asked.some((one) => one.startsWith("/api/v1/hosts/h1/audit"))).toBe(true);
    const row = screen.getByTestId("event-1");
    expect(within(row).getByText("tszymanski")).toBeInTheDocument();
    expect(within(row).getByText("unit.restart")).toBeInTheDocument();
    expect(within(row).getByText("success")).toBeInTheDocument();
    expect(row).toHaveTextContent("reason=the service was wedged");
  });

  it("counts nothing before the trail is read, and never a nought", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout });
    draw();
    const band = await screen.findByTestId("outcomes");
    // A trail nobody has read is not a trail with nothing in it.
    expect(band).toHaveTextContent("—");
    expect(band.querySelector(".fl-band")).toBeNull();
  });

  it("counts the three outcomes apart, because a refusal is not a failure", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/audit": {
        count: 3,
        items: [
          event(),
          event({ id: 2, outcome: "denied", action: "host.retire" }),
          event({ id: 3, outcome: "failure", action: "packages.upgrade" }),
        ],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-3")).toBeInTheDocument());
    const band = screen.getByTestId("outcomes");
    expect(band).toHaveTextContent("success");
    expect(band).toHaveTextContent("denied");
    expect(band).toHaveTextContent("failure");
  });

  it("narrows on the server, not in the browser", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/audit": { count: 1, items: [event()] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("event-1")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("outcome"), { target: { value: "denied" } });
    await waitFor(() => expect(asked.some((one) => one.includes("outcome=denied"))).toBe(true));
    fireEvent.change(screen.getByTestId("action"), { target: { value: "job." } });
    await waitFor(() => expect(asked.some((one) => one.includes("action_prefix=job."))).toBe(true));
    fireEvent.change(screen.getByTestId("actor"), { target: { value: "tszymanski" } });
    await waitFor(() => expect(asked.some((one) => one.includes("actor=tszymanski"))).toBe(true));
  });

  it("opens the whole record of an event, as the trail wrote it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/audit": { count: 1, items: [event({ session_id: "sess-0123456789abcdef", acr: "mfa" })] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-1")).toBeInTheDocument());
    // The sign-in that acted stands under the actor: the name alone does
    // not say which session it was.
    expect(screen.getByTestId("event-1")).toHaveTextContent("sess-0123456");
    expect(screen.getByTestId("event-1")).toHaveTextContent("acr=mfa");
    fireEvent.click(screen.getByTestId("open-1"));
    const record = await screen.findByTestId("record");
    expect(record).toHaveTextContent("\"action\": \"unit.restart\"");
    expect(record).toHaveTextContent("\"session_id\": \"sess-0123456789abcdef\"");
    // It opens under the event's own row, across the whole width, which is
    // where the panel being replaced opened it.
    const row = screen.getByTestId("event-1");
    expect(row.nextElementSibling).toHaveClass("fl-row-detail");
    expect(row.nextElementSibling?.contains(record)).toBe(true);
    expect(row.nextElementSibling?.querySelector("td")?.getAttribute("colspan"))
      .toBe(String(row.querySelectorAll("td").length));
  });

  it("says plainly that the trail is not for this reader", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout });
    refuse = true;
    draw();
    await waitFor(() =>
      expect(screen.getByText(/do not have permission to read this host's audit trail/)).toBeInTheDocument());
    expect(screen.queryByTestId("events")).toBeNull();
  });

  it("narrows to one actor from the breakdown", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/audit": {
        count: 2,
        items: [
          event({ actor: { kind: "user", principal_id: "p-1", display_name: "Tomasz" } }),
          event({ id: 2, actor_id: "panel", actor_type: "system" }),
        ],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByText("By actor")).toBeInTheDocument());
    const breakdown = screen.getByText("By actor").closest(".fl-card") as HTMLElement;
    await waitFor(() => expect(within(breakdown).getByText("Tomasz")).toBeInTheDocument());
    asked.length = 0;
    // The breakdown narrows by the identifier the actor keeps, whatever it
    // was called at the time, and not by the name on the row.
    fireEvent.click(within(breakdown).getByText("Tomasz"));
    await waitFor(() => expect(asked.some((one) => one.includes("actor=p-1"))).toBe(true));
  });
});

describe("what the audit module knows on its own", () => {
  it("calls the agent of this very host by the host's own name", () => {
    const t = ((text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, name) => String(params?.[name] ?? ""))) as never;
    expect(actorLabel({ actor_type: "agent", actor_id: "h1" }, host, t).text).toBe("agent of agent-arch");
    // And so it does when the trail kept the whole snapshot of the actor.
    expect(actorLabel(
      { actor_type: "agent", actor_id: "x", actor: { resource_type: "host", resource_id: "h1" } },
      host, t,
    ).text).toBe("agent of agent-arch");
  });

  it("leads to the campaign that ordered the change, and not to this host", () => {
    const t = ((text: string, params?: Record<string, string | number>) =>
      text.replace(/\{(\w+)\}/g, (_, name) => String(params?.[name] ?? ""))) as never;
    const who = actorLabel({ actor_type: "system", actor_id: "campaign:abcdef0123456789" }, host, t);
    expect(who.text).toBe("campaign abcdef01");
    expect(who.to).toBe("/next/campaigns/abcdef0123456789");
  });

  it("puts the keys an incident is read by first, and nothing where there are none", () => {
    expect(digest({ reason: "wedged", state: "succeeded", noise: "ignored" }))
      .toBe("reason=wedged · state=succeeded");
    expect(digest(undefined)).toBe("");
    // An empty string is not a fact; it is left out rather than shown as a key.
    expect(digest({ reason: "" })).toBe("");
  });
});
