import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Settings, chosenAddress, confirmable, hubState, settingsTab, sourceTone, OWN_ADDRESS,
} from "./Settings";
import { ToastProvider } from "../../components/Toast";

/**
 * The settings area: the tabs a sign-in may open, the retentions it may
 * write, and the values it may only read.
 *
 * Two rules are worth a test of their own. A setting is never stored
 * before the server has said what the change would remove, and a secret
 * among the started-with values says whether it is set and nothing else.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What a write answers with; an Error here is rejected rather than returned. */
const writes: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. "/api/v1/settings"
  // left to answer "/api/v1/settings/monitoring" would hand the retention
  // form the installation's facts, and every assertion after that is
  // measuring the harness rather than the screen.
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

const DURATIONS = {
  raw_retention: "720h0m0s",
  rollup_retention: "2160h0m0s",
  max_lateness: "1h0m0s",
  raw_query_window: "168h0m0s",
  clock_skew_limit: "5m0s",
  partitions_ahead: 7,
};

const monitoring = {
  effective: DURATIONS,
  environment: DURATIONS,
  stored: {
    present: true,
    updated_at: "2026-10-01T08:00:00Z",
    updated_by: "tszymanski",
    revision: 3,
    values: { ...DURATIONS },
  },
  note: "Every replica picks these up within half a minute.",
};

const quiet = {
  dropped_raw_partitions: [],
  raw_samples_estimate: 0,
  rollup_rows: 0,
  gap_rows: 0,
  clock_skew_rows: 0,
  expired_silence_rows: 0,
  destructive: false,
};

const facts = {
  source: "environment",
  note: "Read at start.",
  areas: [
    { key: "build", title: "Build", facts: [
      { key: "version", value: "0.63.1" },
      { key: "commit", value: "6c38561" },
    ] },
    { key: "oidc", title: "Sign-in", facts: [
      { key: "issuer", value: "https://id.example.org" },
      { key: "client_secret", value: null, secret: true, configured: true },
      { key: "groups_claim", value: null, secret: true, configured: false },
      { key: "session_idle", value: "720h0m0s" },
      { key: "oidc_admin_logout", value: false },
    ] },
    { key: "retention", title: "Retention", facts: [
      { key: "audit", value: "" },
      { key: "jobs", value: null },
    ] },
  ],
};

const advertised = {
  in_force: ["127.0.0.1"],
  source: "default",
  loopback_only: true,
  environment_in_force: false,
  candidates: [
    { name: "192.168.56.10", kind: "address", interface: "eth1", loopback: false },
    { name: "panel", kind: "hostname", loopback: false },
  ],
  note: "The agents are told this at enrolment.",
};

/** Everything the screen reads, so a short key never answers a longer path. */
const base = () => ({
  "/api/v1/settings": facts,
  "/api/v1/settings/monitoring": monitoring,
  "/api/v1/settings/advertised": advertised,
});

const admin = {
  subject: "t", kind: "user", roles: [], bindings: [],
  permissions: ["settings.read", "settings.advertise.write", "principal.manage", "host.read",
                "notification.read", "budget.read", "policy.read"],
};
const reader = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.read"] };

function draw(at = "/next/settings") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Settings />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(writes)) delete writes[key];
});

describe("what the screen decides before it draws", () => {
  it("lands on the named tab, and on one that exists when the name does not", () => {
    const all = new Set(["principal.manage", "host.read", "notification.read", "budget.read", "policy.read"]);
    expect(settingsTab("users", all)).toBe("users");
    expect(settingsTab(null, all)).toBe("general");
    expect(settingsTab("nonsense", all)).toBe("general");
    // A bookmark kept from a wider role lands somewhere that exists.
    expect(settingsTab("users", new Set<string>())).toBe("general");
  });

  it("counts a hub honestly: a refusal is not a count of none", () => {
    expect(hubState({ count: 4 }, null, false)).toEqual({ kind: "count", n: 4 });
    expect(hubState({ items: [1, 2] }, null, false)).toEqual({ kind: "count", n: 2 });
    expect(hubState(undefined, null, true)).toEqual({ kind: "unknown" });
    expect(hubState(undefined, new Error("off"), false)).toEqual({ kind: "unknown" });
  });

  it("reads the address a choice amounts to, and refuses the ones the server would", () => {
    expect(chosenAddress("192.168.56.10", "")).toEqual(["192.168.56.10"]);
    expect(chosenAddress(OWN_ADDRESS, " a.example.org , b.example.org ")).toEqual(["a.example.org", "b.example.org"]);
    expect(chosenAddress("", "")).toEqual([]);
    expect(confirmable([], false)).toBe(false);
    expect(confirmable(["a.example.org"], true)).toBe(false);
    expect(confirmable(["a.example.org/x"], false)).toBe(false);
    expect(confirmable(["a.example.org"], false)).toBe(true);
  });

  it("marks an address that reaches only this machine as the fault it is", () => {
    expect(sourceTone("confirmed", true)).toBe("error");
    expect(sourceTone("default", false)).toBe("warn");
    expect(sourceTone("environment", false)).toBe("ok");
  });
});

describe("the tabs", () => {
  it("offers only the sections this sign-in may read", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": reader });
    draw();
    // host.read opens the role catalogue and nothing else.
    await waitFor(() => expect(screen.getByRole("tab", { name: "Roles" })).toBeInTheDocument());
    expect(screen.getByRole("tab", { name: "General" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Budgets" })).toBeNull();
  });

  it("leads to the section's own screen inside the new panel", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw("/next/settings?tab=users");
    await waitFor(() => expect(screen.getByTestId("settings-open-section")).toBeInTheDocument());
    expect(screen.getByTestId("settings-open-section")).toHaveAttribute("href", "/next/access");
  });

  it("switches on a click and says what the section decides", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByRole("tab", { name: "Fleet CA" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: "Fleet CA" }));
    await waitFor(() => expect(screen.getByTestId("settings-open-section")).toHaveAttribute("href", "/next/certificates"));
    expect(screen.getByText(/Rotation is four deliberate stages/)).toBeInTheDocument();
  });
});

describe("the values the process was started with", () => {
  it("says whether a secret is set, and never what it is", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByText("Client secret")).toBeInTheDocument());
    expect(screen.getByText("set")).toBeInTheDocument();
    expect(screen.getByText("not set")).toBeInTheDocument();
  });

  it("does not turn a value nobody has read into a nought", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    // A retention left unset keeps the record for good; a dash would read
    // as "nothing kept", which is the opposite of what happens.
    await waitFor(() => expect(screen.getByText("forever")).toBeInTheDocument());
    expect(screen.getByText("no snapshot yet")).toBeInTheDocument();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("narrows the areas to the setting somebody is looking for", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByText("Build")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "issuer" } });
    await waitFor(() => expect(screen.queryByText("Build")).toBeNull());
    expect(screen.getByText("Issuer")).toBeInTheDocument();
  });

  it("says nothing answers rather than drawing an empty board", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByText("Build")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "zzz" } });
    await waitFor(() => expect(screen.getByText("No setting of that name.")).toBeInTheDocument());
  });
});

describe("the monitoring retentions", () => {
  async function ready() {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByTestId("monitoring-raw_retention")).toBeInTheDocument());
  }

  it("will not store anything before the server has said what the change removes", async () => {
    Object.assign(writes, { "/api/v1/settings/monitoring?dry_run=true": { valid: true, effective: DURATIONS, impact: quiet } });
    await ready();
    expect(screen.getByTestId("monitoring-store")).toBeDisabled();

    fireEvent.change(screen.getByTestId("monitoring-raw_retention"), { target: { value: "1440h0m0s" } });
    fireEvent.click(screen.getByTestId("monitoring-check"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("PUT");
    expect(sent[0].path).toBe("/api/v1/settings/monitoring?dry_run=true");
    expect(sent[0].body).toEqual({
      ...DURATIONS,
      raw_retention: "1440h0m0s",
      acknowledge_data_loss: false,
      reason: "changed on the settings screen",
    });
    await waitFor(() => expect(screen.getByTestId("monitoring-impact")).toBeInTheDocument());
    expect(screen.getByTestId("monitoring-store")).toBeEnabled();
  });

  it("stores exactly the settings that were checked", async () => {
    Object.assign(writes, {
      "/api/v1/settings/monitoring?dry_run=true": { valid: true, effective: DURATIONS, impact: quiet },
      "/api/v1/settings/monitoring": { valid: true, effective: DURATIONS, impact: quiet },
    });
    await ready();
    fireEvent.change(screen.getByTestId("monitoring-partitions-ahead"), { target: { value: "14" } });
    fireEvent.click(screen.getByTestId("monitoring-check"));
    await waitFor(() => expect(screen.getByTestId("monitoring-store")).toBeEnabled());
    fireEvent.click(screen.getByTestId("monitoring-store"));

    await waitFor(() => expect(sent).toHaveLength(2));
    expect(sent[1].path).toBe("/api/v1/settings/monitoring");
    expect(sent[1].body).toEqual({
      ...DURATIONS,
      partitions_ahead: 14,
      acknowledge_data_loss: false,
      reason: "changed on the settings screen",
    });
  });

  it("names what a destructive change removes and holds the button until it is acknowledged", async () => {
    Object.assign(writes, {
      "/api/v1/settings/monitoring?dry_run=true": {
        valid: true,
        effective: DURATIONS,
        impact: {
          ...quiet,
          dropped_raw_partitions: ["2026-09-01", "2026-09-02"],
          raw_samples_estimate: 412000,
          rollup_rows: 9100,
          destructive: true,
        },
      },
      "/api/v1/settings/monitoring": { valid: true, effective: DURATIONS, impact: quiet },
    });
    await ready();
    fireEvent.change(screen.getByTestId("monitoring-raw_retention"), { target: { value: "24h0m0s" } });
    fireEvent.click(screen.getByTestId("monitoring-check"));

    await waitFor(() => expect(screen.getByText("2026-09-01, 2026-09-02")).toBeInTheDocument());
    expect(screen.getByText("Days of raw samples dropped")).toBeInTheDocument();
    expect(screen.getByTestId("monitoring-store")).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByTestId("monitoring-store")).toBeEnabled();
    fireEvent.click(screen.getByTestId("monitoring-store"));
    await waitFor(() => expect(sent).toHaveLength(2));
    expect((sent[1].body as { acknowledge_data_loss: boolean }).acknowledge_data_loss).toBe(true);
  });

  it("refuses a window that would delete readings still arriving, and says why", async () => {
    Object.assign(writes, {
      "/api/v1/settings/monitoring?dry_run=true": { valid: false, code: "metrics_retention_too_short", effective: DURATIONS, impact: quiet },
    });
    await ready();
    fireEvent.change(screen.getByTestId("monitoring-raw_retention"), { target: { value: "1h0m0s" } });
    fireEvent.click(screen.getByTestId("monitoring-check"));
    await waitFor(() => expect(screen.getByText(/cannot be stored/)).toBeInTheDocument());
    expect(screen.getByTestId("monitoring-store")).toBeDisabled();
  });

  it("puts the server's refusal where the operator pressed the button", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(writes, {
      "/api/v1/settings/monitoring?dry_run=true": { valid: true, effective: DURATIONS, impact: quiet },
      "/api/v1/settings/monitoring": new ApiError(403, "forbidden", "not yours"),
    });
    await ready();
    fireEvent.click(screen.getByTestId("monitoring-check"));
    await waitFor(() => expect(screen.getByTestId("monitoring-store")).toBeEnabled());
    fireEvent.click(screen.getByTestId("monitoring-store"));
    await waitFor(() =>
      expect(screen.getByTestId("monitoring-refusal"))
        .toHaveTextContent("You may not change the monitoring settings"));
  });

  it("says nothing at all where the installation has no monitoring", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, base(), {
      "/api/v1/whoami": admin,
      "/api/v1/settings/monitoring": new ApiError(404, "not_found", "no monitoring here"),
    });
    draw();
    await waitFor(() => expect(screen.getByText("Build")).toBeInTheDocument());
    expect(screen.queryByText("Monitoring retention")).toBeNull();
  });
});

describe("the address the agents dial", () => {
  it("confirms the candidate that was picked, with the reason beside it", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    Object.assign(writes, {
      "/api/v1/settings/advertised": { ...advertised, in_force: ["192.168.56.10"], source: "confirmed", loopback_only: false },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("advertised-address")).toBeInTheDocument());
    // Nothing the panel found is in use until somebody says which one.
    expect(screen.getByTestId("advertised-confirm")).toBeDisabled();

    fireEvent.click(screen.getByTestId("advertised-192.168.56.10"));
    fireEvent.change(screen.getByTestId("advertised-reason"), { target: { value: "the lab network" } });
    expect(screen.getByTestId("advertised-confirm")).toBeEnabled();
    fireEvent.click(screen.getByTestId("advertised-confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "PUT",
      path: "/api/v1/settings/advertised",
      body: { names: ["192.168.56.10"], reason: "the lab network" },
    });
  });

  it("confirms nothing where the deployment already declares it", async () => {
    Object.assign(answers, base(), {
      "/api/v1/whoami": admin,
      "/api/v1/settings/advertised": {
        ...advertised,
        in_force: ["panel.example.org"],
        source: "environment",
        loopback_only: false,
        environment_in_force: true,
        environment: ["panel.example.org"],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("advertised-address")).toBeInTheDocument());
    expect(screen.getByText(/that declaration decides/)).toBeInTheDocument();
    expect(screen.queryByTestId("advertised-confirm")).toBeNull();
  });

  it("reads an answer it does not understand as an answer, not as an address of none", async () => {
    Object.assign(answers, base(), {
      "/api/v1/whoami": admin,
      "/api/v1/settings/advertised": { ...advertised, in_force: undefined },
    });
    draw();
    await waitFor(() =>
      expect(screen.getByTestId("advertised-address"))
        .toHaveTextContent("This panel did not say which address is in force."));
  });

  it("is not offered at all to somebody who may not name it", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": { ...admin, permissions: ["settings.read"] } });
    draw();
    await waitFor(() => expect(screen.getByTestId("advertised-address")).toBeInTheDocument());
    expect(screen.getByText("Only a platform administrator names the address the fleet connects to; ask one."))
      .toBeInTheDocument();
    expect(screen.queryByTestId("advertised-confirm")).toBeNull();
  });

  it("keeps the whole card away from a sign-in with neither permission", async () => {
    Object.assign(answers, base(), { "/api/v1/whoami": reader });
    draw();
    await waitFor(() => expect(screen.getByText("Build")).toBeInTheDocument());
    expect(screen.queryByTestId("advertised-address")).toBeNull();
  });
});

describe("what has not arrived yet", () => {
  it("draws the shape of it rather than the word loading", () => {
    Object.assign(answers, base(), { "/api/v1/whoami": admin });
    const { container } = draw();
    expect(container.querySelectorAll(".fl-bone").length).toBeGreaterThan(0);
    expect(within(container).queryByText("Loading…")).toBeNull();
  });
});
