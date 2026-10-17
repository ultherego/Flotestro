import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Services, detailDocumentOf, unitTone } from "./Services";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";

/**
 * What the screen does, not what it looks like: the order it posts, the
 * refusal it shows, and the difference between a host nobody has read and
 * a host with nothing wrong.
 */

const answers: Record<string, unknown> = {};
const sent: { path: string; body: unknown }[] = [];

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it. A short key
  // left to answer a longer path hands the screen the wrong document:
  // `/api/v1/hosts/h1` would answer `/inventory/services.full`.
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
  reboot_required: false, failed_units: 1, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as Host);

/** The server's preview of what this operator may order on this host. */
const allow = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.operate", mutating: true, risk: "normal", allowed: true,
  })),
});

const EVERY = [
  "unit.status", "unit.start", "unit.stop", "unit.restart", "unit.reset_failed",
  "unit.enable.set", "unit.mask.set",
];

const fragment = (module: string, payload: Record<string, unknown>) => ({
  host_id: "h1", module, revision: "abcdef1234567890", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

const unit = (over: Record<string, unknown> = {}) => ({
  name: "nginx.service", load_state: "loaded", active_state: "active", sub_state: "running",
  unit_file_state: "enabled", ...over,
});

/**
 * The screen is two sub-tabs since 17.10 - the readings and the list of
 * units - and the address names which one is open, so a test that reads
 * the list asks for `?tab=units` the way a reader following a link would.
 */
function draw(one: Host = host(), at = "/hosts/h1/services") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Services host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  // The folded columns are this browser's, so one test must not leave
  // them folded for the next.
  window.localStorage.clear();
});

describe("the units of one host", () => {
  it("asks the host for its units, and that is the whole of the order", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("read-units")).toBeEnabled());
    fireEvent.click(screen.getByTestId("read-units"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(sent[0].body).toEqual({ action: "unit.status", payload: { unit_status: { all: true } } });
  });

  it("restarts a failed unit with the payload the registry composes", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/services": fragment("services", {
        failed_units: ["nginx.service"], failed_units_known: true,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("failed-nginx.service")).toBeInTheDocument());
    const row = screen.getByTestId("failed-nginx.service");
    fireEvent.click(within(row).getByRole("button", { name: "Restart" }));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "unit.restart",
      payload: { unit: { unit: "nginx.service" } },
    });
  });

  it("asks before it masks a unit, and sends the reason the trail keeps", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
      "/api/v1/hosts/h1/inventory/services.full": fragment("services.full", { units: [unit()] }),
    });
    draw(host(), "/hosts/h1/services?tab=units");
    await waitFor(() => expect(screen.getByTestId("mask-nginx.service")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("mask-nginx.service"));
    // Nothing is sent by opening the question.
    expect(sent).toHaveLength(0);
    // Nor by answering half of it: the hostname has to be typed out.
    fireEvent.change(screen.getByTestId("mask-reason"), { target: { value: "blocking a unit that fights the agent" } });
    expect(screen.getByTestId("mask-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("mask-hostname"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("mask-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "unit.mask.set",
      reason: "blocking a unit that fights the agent",
      payload: { unit_toggle: { unit: "nginx.service", enabled: true } },
    });
  });

  it("counts nothing until the host has been read: a dash, never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      // The inventory knows nothing about the units yet, and the full
      // listing has never been read.
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: null, failed_units_known: false }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("unit-states")).toBeInTheDocument());
    const states = screen.getByTestId("unit-states");
    // Every state says it was not counted rather than showing a nought,
    // which would read as a host with nothing wrong.
    expect(states).toHaveTextContent("active: not counted");
    expect(states).toHaveTextContent("failed: not counted");
    expect(within(states).queryByText("0")).toBeNull();
    expect(screen.getByText("Unit states could not be determined.")).toBeInTheDocument();
  });

  it("draws no button for an order this operator may not place", async () => {
    Object.assign(answers, {
      // Reading is allowed; nothing that changes the host is.
      "/api/v1/hosts/h1/actions": allow("unit.status"),
      "/api/v1/hosts/h1/inventory/services": fragment("services", {
        failed_units: ["nginx.service"], failed_units_known: true,
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("failed-nginx.service")).toBeInTheDocument());
    const row = screen.getByTestId("failed-nginx.service");
    expect(within(row).queryByRole("button", { name: "Restart" })).toBeNull();
    expect(within(row).queryByRole("button", { name: "Reset failed" })).toBeNull();
  });

  it("says the whole module is read-only when every change is refused", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": {
        version: 1,
        items: [
          ...EVERY.filter((action) => action !== "unit.status").map((action) => ({
            action, permission: "host.operate", mutating: true, risk: "normal",
            allowed: false, reason_code: "permission_denied", missing_permission: "host.operate",
          })),
          { action: "unit.status", permission: "host.read", mutating: false, risk: "read", allowed: true },
        ],
      },
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.operate/)).toBeInTheDocument());
  });

  it("marks a listing the host cut short, so it is not read as the whole machine", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
      "/api/v1/hosts/h1/inventory/services.full": fragment("services.full", { units: [unit()], truncated: true }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/truncated by the host limit/)).toBeInTheDocument());
  });

  it("opens the unit named in the address, wherever the alphabet put it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
      "/api/v1/hosts/h1/inventory/services.full": fragment("services.full", {
        units: [unit(), unit({ name: "sshd.service" })],
      }),
    });
    draw(host(), "/hosts/h1/services?tab=units&unit=sshd.service");
    // The address narrows the list to that unit and asks the host for its
    // detail; the order that goes out is the detail read.
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "unit.status",
      payload: { unit_status: { units: ["sshd.service"], detail: true } },
    });
    expect(screen.getByTestId("unit-filter")).toHaveValue("sshd.service");
  });
});

describe("reading the answer of a detail read", () => {
  it("takes the typed result when the panel has one", () => {
    const document = { kind: "unit_detail", units: [{ state: { name: "a.service" } }] };
    expect(detailDocumentOf({ status: "succeeded", detail: document } as never)).toBe(document);
  });

  it("falls back to what the agent printed, and to nothing when that is not readable", () => {
    expect(detailDocumentOf({ status: "succeeded", stdout: '{"units":[]}' }).units).toEqual([]);
    expect(detailDocumentOf({ status: "succeeded", stdout: "not json" })).toEqual({});
  });
});

describe("the condition of a unit", () => {
  it("tells a unit nobody could place from one that is simply not running", () => {
    expect(unitTone("active")).toBe("ok");
    expect(unitTone("failed")).toBe("error");
    expect(unitTone("inactive")).toBe("neutral");
    expect(unitTone("activating")).toBe("unknown");
  });
});

describe("what the unit list kept from the panel being replaced", () => {
  const listed = () => Object.assign(answers, {
    "/api/v1/hosts/h1/actions": allow(...EVERY),
    "/api/v1/hosts/h1/inventory/services": fragment("services", { failed_units: [], failed_units_known: true }),
    "/api/v1/hosts/h1/inventory/services.full": fragment("services.full", { units: [unit()] }),
  });

  it("opens a unit's detail under its own row, not in a card somewhere else", async () => {
    listed();
    draw(host(), "/hosts/h1/services?tab=units");
    await waitFor(() => expect(screen.getByTestId("unit-nginx.service")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("unit-nginx.service")).getByRole("button", { name: "nginx.service" }));
    await waitFor(() =>
      expect(within(screen.getByTestId("units")).getByText(/asked about this unit|not been read yet/)).toBeInTheDocument());
    // The detail is the row immediately under the unit's own, across the
    // whole width - which is where the old module put it.
    const row = screen.getByTestId("unit-nginx.service");
    expect(row.nextElementSibling).toHaveClass("fl-row-detail");
    expect(row.nextElementSibling?.querySelector("td")?.getAttribute("colspan"))
      .toBe(String(row.querySelectorAll("td").length));
  });

  it("folds a column away and keeps the choice in this browser", async () => {
    listed();
    draw(host(), "/hosts/h1/services?tab=units");
    await waitFor(() => expect(screen.getByTestId("units")).toBeInTheDocument());
    expect(within(screen.getByTestId("units")).getByText("Sub-state")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("units-columns"));
    fireEvent.click(screen.getByRole("checkbox", { name: "Sub-state" }));
    expect(within(screen.getByTestId("units")).queryByText("Sub-state")).not.toBeInTheDocument();
    expect(window.localStorage.getItem("fl.columns.host-services")).toContain("sub");
  });
});
