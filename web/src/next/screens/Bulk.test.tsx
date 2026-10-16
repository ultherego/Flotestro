import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Bulk, campaignTone } from "./Bulk";
import { ToastProvider } from "../../components/Toast";

/**
 * The wizard is one long consent: what runs, where, on which of those
 * hosts, how fast, when, and then the campaign, its plans and the
 * approval.
 *
 * What is held here is what the wizard must never get wrong. A step that
 * is shut says why. A count nobody has taken is not a count of nothing -
 * while the server is counting, the screen must not say the selector
 * matches no host. The order that reaches the server is the order the
 * screen showed, with the preview it was placed from named in it. And a
 * refusal is read in the operator's own language rather than as a code.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
const refusals: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const find = (path: string) => Object.keys(answers)
    .filter((one) => path.startsWith(one))
    .sort((a, b) => b.length - a.length)[0];
  const answer = (path: string) => {
    asked.push(path);
    const key = find(path);
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    const found = answers[key];
    if (found instanceof Error) return Promise.reject(found);
    return Promise.resolve(found);
  };
  const write = (method: string) => (path: string, body?: unknown) => {
    sent.push({ method, path, body });
    const refusal = Object.keys(refusals)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (refusal) return Promise.reject(refusals[refusal]);
    const key = find(path);
    return Promise.resolve(key ? answers[key] : {});
  };
  return {
    ...actual,
    api: { ...actual.api, get: answer, post: write("POST"), put: write("PUT"), del: write("DELETE") },
  };
});

const restart = {
  action: "unit.restart", campaign_ready: true, mutating: true, campaign_mode: "plan",
  risk: "medium", cancel_mode: "checkpoint_only", retry_class: "automatic",
  rollback: "none", verification: "unit_health", resource_claims: [],
  default_timeout_seconds: 600,
};

const refused = {
  action: "agent.upgrade", campaign_ready: false, mutating: true, campaign_mode: "none",
  campaign_refusal: "the agent upgrades itself through its channel",
};

const preview = (over: Record<string, unknown> = {}) => ({
  count: 3, limit: 500, eligible: 3,
  sample: ["agent-arch", "agent-debian", "agent-fedora"],
  excluded: [], notes: [], campaign_mode: "plan", requires_plan: true,
  preview_id: "pv-1", preview_digest: "sha256:abc",
  ...over,
});

const campaign = (over: Record<string, unknown> = {}) => ({
  id: "camp-1", name: "Restart nginx", action_type: "unit.restart", state: "awaiting_approval",
  canary_size: 1, wave_size: 10, max_concurrent: 5, failure_threshold_percent: 20,
  failure_threshold_absolute: 0, reboot_policy: "never", requires_approval: true,
  offline_policy: "wait_until_deadline", manual_gate: false, connectivity_lost_absolute: 0,
  approval_fingerprint: "fp-0123456789abcdef", created_by: "ulther", created_at: "2026-10-16T08:00:00Z",
  ...over,
});

/** The address a half-written order arrives on, as another screen hands it over. */
const ORDER = "/next/bulk?action=unit.restart&name=Restart+nginx"
  + `&payload=${encodeURIComponent(JSON.stringify({ unit: { unit: "nginx.service" } }))}`;

function base() {
  Object.assign(answers, {
    "/api/v1/capabilities": { campaign_v2: true, identity_provider: false, directory: false, directory_write: false, local_users: false },
    "/api/v1/actions": { items: [restart, refused], count: 2 },
    "/api/v1/fleet/activity": {
      hours: [], succeeded: [], failed: [], other: [],
      by_connection_state: [], by_os_family: [{ key: "arch", count: 1 }],
      by_agent_version: [], by_site: [{ key: "lab", count: 3 }], by_environment: [{ key: "test", count: 3 }],
    },
    "/api/v1/campaigns/preview": preview(),
  });
}

function draw(address = "/next/bulk") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[address]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Bulk />, { wrapper });
}

/** From the scope step to the create step, the way an operator walks it. */
async function walkToCreate() {
  draw(ORDER);
  await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
  fireEvent.click(screen.getByTestId("step-next"));
  // The fleet has to be narrowed before anything is counted.
  fireEvent.change(screen.getByTestId("target-site"), { target: { value: "lab" } });
  await waitFor(() => expect(screen.getByTestId("matched")).toHaveTextContent("The selector matches 3 hosts"));
  fireEvent.click(screen.getByTestId("step-next"));
  await waitFor(() => expect(screen.getByTestId("eligibility")).toBeInTheDocument());
  fireEvent.click(screen.getByTestId("step-next"));
  await waitFor(() => expect(screen.getByTestId("canary")).toBeInTheDocument());
  fireEvent.click(screen.getByTestId("step-next"));
  await waitFor(() => expect(screen.getByTestId("window-start")).toBeInTheDocument());
  fireEvent.click(screen.getByTestId("step-next"));
  await waitFor(() => expect(screen.getByTestId("create-campaign")).toBeInTheDocument());
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
  // The wizard keeps its draft in the tab; one test must not open on the
  // order the one before it was writing.
  try { window.sessionStorage.clear(); } catch { /* a browser without one */ }
});

describe("the bulk workspace", () => {
  it("says so when the backend has no campaign engine, instead of offering a wizard that cannot run", async () => {
    base();
    answers["/api/v1/capabilities"] = { campaign_v2: false, identity_provider: false, directory: false, directory_write: false, local_users: false };
    draw();
    await waitFor(() => expect(screen.getByText(/the backend has no campaign engine/)).toBeInTheDocument());
    expect(screen.queryByTestId("step-next")).toBeNull();
  });

  it("holds the first step shut until the campaign has a name, an operation and a payload", async () => {
    base();
    draw();
    await waitFor(() => expect(screen.getByTestId("order-action")).toBeInTheDocument());
    // Nothing is named yet: the step says what it is waiting for rather
    // than offering a button that does nothing.
    expect(screen.getByTestId("step-next")).toBeDisabled();
    expect(screen.getAllByText(/pick an operation and name the campaign/).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByTestId("order-action"), { target: { value: "unit.restart" } });
    fireEvent.change(screen.getByTestId("order-name"), { target: { value: "Restart nginx" } });
    // The operation's own field is still empty, so the gate names that.
    expect(screen.getByTestId("step-next")).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^Unit/), { target: { value: "nginx.service" } });
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
  });

  it("offers exactly what the registry opens to the fleet, and names what it refuses", async () => {
    base();
    draw();
    await waitFor(() => expect(screen.getByTestId("order-action")).toBeInTheDocument());
    // The catalogue is read: a wizard that cannot list the operations the
    // registry opens to the fleet cannot be trusted to say what is missing.
    expect(asked.some((one) => one.startsWith("/api/v1/actions"))).toBe(true);
    const operations = screen.getByTestId("order-action") as HTMLSelectElement;
    expect([...operations.options].map((one) => one.value))
      .toEqual(["", "unit.restart"]);
    // What changes hosts but is refused in bulk is not silently absent:
    // it is behind one press, with the registry's own reason beside it.
    fireEvent.click(screen.getByTestId("show-refusals"));
    const refused = await screen.findByTestId("bulk-refusals");
    expect(refused).toHaveTextContent("agent.upgrade");
    expect(refused).toHaveTextContent("the agent upgrades itself through its channel");
  });

  it("offers the sites, environments and OS families the fleet really has", async () => {
    base();
    draw(ORDER);
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("target-site")).toBeInTheDocument());
    expect(asked.some((one) => one.startsWith("/api/v1/fleet/activity"))).toBe(true);
    // A hint, not a boundary: the field still takes anything typed into it.
    await waitFor(() => expect(
      (document.getElementById("next-bulk-sites") as HTMLDataListElement).options,
    ).toHaveLength(1));
    const sites = document.getElementById("next-bulk-sites") as HTMLDataListElement;
    expect([...sites.options].map((one) => one.value)).toEqual(["lab"]);
    const environments = document.getElementById("next-bulk-environments") as HTMLDataListElement;
    expect([...environments.options].map((one) => one.value)).toEqual(["test"]);
    const families = document.getElementById("next-bulk-os-families") as HTMLDataListElement;
    expect([...families.options].map((one) => one.value)).toEqual(["arch"]);
    expect(screen.getByTestId("target-site")).toHaveAttribute("list", "next-bulk-sites");
  });

  it("reads the catalogue's refusal of an operation in bulk before the form is filled in", async () => {
    base();
    draw("/next/bulk?action=agent.upgrade&name=Upgrade");
    await waitFor(() => expect(
      screen.getAllByText(/the agent upgrades itself through its channel/).length,
    ).toBeGreaterThan(0));
    expect(screen.getByTestId("step-next")).toBeDisabled();
  });

  it("counts on the server, and never says the selector matches nobody while it is counting", async () => {
    base();
    draw(ORDER);
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("target-site")).toBeInTheDocument());
    // Nothing is narrowed: no count is taken, and the screen says so.
    expect(screen.getByTestId("matched")).toHaveTextContent("The fleet is not narrowed yet");
    expect(screen.getByTestId("matched")).not.toHaveTextContent("matches 0 hosts");

    asked.length = 0;
    fireEvent.change(screen.getByTestId("target-site"), { target: { value: "lab" } });
    // The question goes to the server with the selector in it.
    await waitFor(() => expect(
      asked.some((one) => one.startsWith("/api/v1/campaigns/preview") && one.includes("site=lab")),
    ).toBe(true));
    await waitFor(() => expect(screen.getByTestId("matched")).toHaveTextContent("The selector matches 3 hosts"));
  });

  it("names the buckets of the eligibility step, and what cannot run the operation", async () => {
    base();
    answers["/api/v1/campaigns/preview"] = preview({
      eligible: 2,
      excluded: [{ reason: "capability_missing", count: 1, sample: ["agent-fedora"] }],
      notes: [{ reason: "offline", count: 1, sample: ["agent-debian"] }],
    });
    draw(ORDER);
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
    fireEvent.click(screen.getByTestId("step-next"));
    fireEvent.change(screen.getByTestId("target-site"), { target: { value: "lab" } });
    await waitFor(() => expect(screen.getByTestId("matched")).toHaveTextContent("matches 3 hosts"));
    fireEvent.click(screen.getByTestId("step-next"));
    const table = await screen.findByTestId("eligibility");
    expect(table).toHaveTextContent("no adapter");
    expect(table).toHaveTextContent("agent-fedora");
    // A note does not exclude a host: an offline host comes back.
    expect(table).toHaveTextContent("offline");
    expect(table).toHaveTextContent("agent-debian");
  });

  it("sends the order the screen showed, with the preview it was placed from named in it", async () => {
    base();
    answers["/api/v1/campaigns"] = campaign();
    await walkToCreate();
    // The button waits for a reason: a consent with none is noise in the trail.
    expect(screen.getByTestId("create-campaign")).toBeDisabled();
    fireEvent.change(screen.getByTestId("order-reason"), { target: { value: "CHG-1234: restart the web tier" } });
    await waitFor(() => expect(screen.getByTestId("create-campaign")).toBeEnabled());
    fireEvent.click(screen.getByTestId("create-campaign"));

    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/campaigns")).toBe(true));
    const body = sent.find((one) => one.path === "/api/v1/campaigns")?.body as Record<string, unknown>;
    expect(body.name).toBe("Restart nginx");
    expect(body.action).toBe("unit.restart");
    expect(body.reason).toBe("CHG-1234: restart the web tier");
    expect(body.payload).toEqual({ unit: { unit: "nginx.service" } });
    expect(body.selector).toMatchObject({ site: "lab" });
    // Every campaign carries the gate, whatever the client says.
    expect(body.requires_approval).toBe(true);
    // The order names the preview it was placed from, so the server can
    // refuse it when the fleet moved in between.
    expect(body.preview_id).toBe("pv-1");
    expect(body.preview_digest).toBe("sha256:abc");
  });

  it("carries the rollout policy the operator set into the order", async () => {
    base();
    answers["/api/v1/campaigns"] = campaign();
    draw(ORDER);
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
    fireEvent.click(screen.getByTestId("step-next"));
    fireEvent.change(screen.getByTestId("target-site"), { target: { value: "lab" } });
    await waitFor(() => expect(screen.getByTestId("matched")).toHaveTextContent("matches 3 hosts"));
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("eligibility")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("canary")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("canary"), { target: { value: "2" } });
    fireEvent.change(screen.getByTestId("wave"), { target: { value: "20" } });
    fireEvent.change(screen.getByTestId("reboot-policy"), { target: { value: "if_required" } });
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("window-start")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("create-campaign")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("order-reason"), { target: { value: "CHG-1234: restart the web tier" } });
    fireEvent.click(screen.getByTestId("create-campaign"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/campaigns")).toBe(true));
    const body = sent.find((one) => one.path === "/api/v1/campaigns")?.body as Record<string, unknown>;
    expect(body.canary_size).toBe(2);
    expect(body.wave_size).toBe(20);
    expect(body.reboot_policy).toBe("if_required");
  });

  it("reads a refusal of the order in the operator's own language", async () => {
    const { ApiError } = await import("../../lib/api");
    base();
    refusals["/api/v1/campaigns"] = new ApiError(400, "selector_required", "selector required");
    await walkToCreate();
    fireEvent.change(screen.getByTestId("order-reason"), { target: { value: "CHG-1234: restart the web tier" } });
    fireEvent.click(screen.getByTestId("create-campaign"));
    await waitFor(() => expect(
      screen.getByText(/its selector names nobody, and an empty selector is not an order on everything/),
    ).toBeInTheDocument());
  });

  it("will not keep a schedule without a moment to place the order at", async () => {
    base();
    draw(ORDER);
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeEnabled());
    fireEvent.click(screen.getByTestId("step-next"));
    fireEvent.change(screen.getByTestId("target-site"), { target: { value: "lab" } });
    await waitFor(() => expect(screen.getByTestId("matched")).toHaveTextContent("matches 3 hosts"));
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("eligibility")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("canary")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("window-start")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Schedule instead of ordering now"));
    // A schedule with neither a first run nor a recurrence names no moment,
    // and the step says so rather than letting the order through.
    await waitFor(() => expect(screen.getByTestId("step-next")).toBeDisabled());
    expect(screen.getAllByText(/give the schedule a first run or a recurrence/).length).toBeGreaterThan(0);
  });

  it("approves what is on the screen: the fingerprint goes with the consent", async () => {
    base();
    answers["/api/v1/campaigns"] = campaign();
    answers["/api/v1/campaigns/camp-1"] = campaign();
    answers["/api/v1/campaigns/camp-1/plans"] = { items: [] };
    answers["/api/v1/campaigns/camp-1/targets"] = {
      items: [{
        campaign_id: "camp-1", host_id: "h1", hostname: "agent-arch", wave: 0,
        state: "queued", message: "",
      }],
      count: 1, total: 1,
    };
    await walkToCreate();
    fireEvent.change(screen.getByTestId("order-reason"), { target: { value: "CHG-1234: restart the web tier" } });
    fireEvent.click(screen.getByTestId("create-campaign"));
    // The campaign exists: the plans step opens on it, and the targets of
    // the campaign are listed under it.
    await waitFor(() => expect(screen.getByTestId("campaign-targets")).toBeInTheDocument());
    // A target with no error code is a dash, not an invented blocker.
    expect(within(screen.getByTestId("target-agent-arch")).getAllByText("—").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByTestId("step-next"));
    await waitFor(() => expect(screen.getByTestId("approval-fingerprint")).toBeInTheDocument());
    expect(screen.getByTestId("approve")).toBeDisabled();
    fireEvent.change(screen.getByTestId("approve-reason"), { target: { value: "reviewed with the owner" } });
    fireEvent.change(screen.getByTestId("approve-ticket"), { target: { value: "CHG-1234" } });
    await waitFor(() => expect(screen.getByTestId("approve")).toBeEnabled());
    fireEvent.click(screen.getByTestId("approve"));
    await waitFor(() => expect(sent.some((one) => one.path.endsWith("/approve"))).toBe(true));
    const body = sent.find((one) => one.path.endsWith("/approve"))?.body as Record<string, unknown>;
    expect(body.reason).toBe("reviewed with the owner");
    expect(body.change_ticket).toBe("CHG-1234");
    expect(body.approval_fingerprint).toBe("fp-0123456789abcdef");
  });
});

describe("the colour a campaign's state wears", () => {
  it("separates what finished from what is still going and what nobody knows", () => {
    expect(campaignTone("completed")).toBe("ok");
    expect(campaignTone("failed")).toBe("error");
    expect(campaignTone("paused")).toBe("warn");
    expect(campaignTone("running")).toBe("info");
    expect(campaignTone("canceled")).toBe("neutral");
    expect(campaignTone("something the server grew since")).toBe("unknown");
  });
});
