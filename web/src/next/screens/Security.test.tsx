import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Security, scopeMissing, selectorOf, severityTone, type RemediationDraft } from "./Security";
import { ToastProvider } from "../../components/Toast";

/**
 * A finding nobody can act on is half a screen.
 *
 * What is held here is the whole of the remediation: that a reader without
 * the right is offered nothing at all, that a check without a remediating
 * operation cannot be ticked and says why, that nothing is ordered before
 * the plans have been shown, that the body the order sends is the one the
 * server reads, and that a refusal is put in front of the reader rather
 * than swallowed.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the next write answers with, keyed by its path. */
const refusals: Record<string, unknown> = {};

const navigated: string[] = [];
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => (to: string) => { navigated.push(to); } };
});

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix answers: "/api/v1/security" would
  // otherwise answer the remediation preview with the fleet's findings.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const given = answers[key];
    return given instanceof Error ? Promise.reject(given) : Promise.resolve(given);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => { asked.push(path); return answer(path); },
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        const refusal = refusals[path];
        if (refusal) return Promise.reject(refusal);
        return answer(path);
      },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve(undefined); },
    },
  };
});

const check = (over: Record<string, unknown> = {}) => ({
  check_id: "ssh_root_login",
  title: "Root may not sign in over SSH",
  severity: "high",
  expected: "PermitRootLogin no",
  failed: 3,
  passed: 7,
  unknown: 0,
  not_applicable: 0,
  fixable: 3,
  hosts: [
    { host_id: "h1", hostname: "web-1" },
    { host_id: "h2", hostname: "web-2" },
  ],
  ...over,
});

/** A check the panel cannot fix: the sentence that says so is on the row. */
const undecided = () => check({
  check_id: "disk_encryption",
  title: "The system disk is encrypted",
  severity: "medium",
  failed: 2,
  fixable: 0,
  hosts: [{ host_id: "h3", hostname: "db-1" }],
});

const plans = {
  check_ids: ["ssh_root_login"],
  hosts: 2,
  eligible: 2,
  groups: [{
    plan_hash: "0123456789abcdef0123",
    count: 2,
    changes: ["sshd"],
    steps: [{ position: 1, check_id: "ssh_root_login", check_version: 1, action_type: "file.render", requires_reboot: false }],
    hosts: [{ host_id: "h1", hostname: "web-1" }, { host_id: "h2", hostname: "web-2" }],
  }],
  excluded: [{ host_id: "h9", hostname: "old-1", reason: "no_plan", message: "the agent is too old to render the file" }],
  generated_at: "2026-10-16T09:00:00Z",
};

function given(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/security": {
      hosts: 10, hosts_judged: 10, unknown_hosts: 0, checks: [check(), undecided()],
      generated_at: "2026-10-16T08:00:00Z",
    },
    "/api/v1/whoami": { permissions: ["security.read", "security.remediate"] },
    "/api/v1/fleet/activity": { by_site: [{ key: "lab", count: 3 }], by_environment: [{ key: "test", count: 3 }] },
    "/api/v1/security/remediation/preview": plans,
    "/api/v1/security/remediation": { campaign: { id: "c-7", name: "remediate" }, groups: plans.groups, excluded: [] },
    ...over,
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Security />, { wrapper });
}

/** The screen with one check ticked and its plans on screen. */
async function previewed() {
  draw();
  fireEvent.click(await screen.findByTestId("fix-ssh_root_login"));
  fireEvent.click(await screen.findByTestId("remediation-preview"));
  await waitFor(() => expect(screen.getByTestId("remediation-plans")).toBeInTheDocument());
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  navigated.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
});

describe("a reader who may not remediate", () => {
  it("is offered no tick and no remediation at all", async () => {
    given({ "/api/v1/whoami": { permissions: ["security.read"] } });
    draw();
    await waitFor(() => expect(screen.getByTestId("check-ssh_root_login")).toBeInTheDocument());
    expect(screen.queryByTestId("fix-ssh_root_login")).not.toBeInTheDocument();
    expect(screen.queryByText("Remediate on the fleet")).not.toBeInTheDocument();
    expect(screen.queryByTestId("remediation-preview")).not.toBeInTheDocument();
  });
});

describe("the checks", () => {
  it("keys a row on the check the server named, not on a field it never sent", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("check-ssh_root_login")).toBeInTheDocument());
    expect(screen.getByTestId("check-disk_encryption")).toBeInTheDocument();
  });

  it("refuses the tick on a check with no remediating operation, and says why on the row", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("fix-disk_encryption")).toBeInTheDocument());
    expect(screen.getByTestId("fix-disk_encryption")).toBeDisabled();
    expect(screen.getByTestId("decision-disk_encryption"))
      .toHaveTextContent("2 need a decision: this check has no remediating operation.");
    // The one the panel can fix whole carries no such sentence at all.
    const fixable = screen.getByTestId("check-ssh_root_login");
    expect(within(fixable).queryByText(/need a decision/)).not.toBeInTheDocument();
    expect(screen.getByTestId("fix-ssh_root_login")).toBeEnabled();
  });
});

describe("the remediation", () => {
  it("appears only once a check is ticked, and names the hosts it would act on", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("fix-ssh_root_login")).toBeInTheDocument());
    expect(screen.queryByTestId("remediation-preview")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("fix-ssh_root_login"));
    await waitFor(() => expect(screen.getByTestId("remediation-preview")).toBeInTheDocument());
    expect(screen.getByTestId("remediation-scope")).toHaveTextContent("hosts with findings (2)");
  });

  it("asks the server what the plans would do, with the checks and the hosts in the body", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("fix-ssh_root_login"));
    fireEvent.click(await screen.findByTestId("remediation-preview"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({
      method: "POST",
      path: "/api/v1/security/remediation/preview",
      body: { check_ids: ["ssh_root_login"], selector: { host_ids: ["h1", "h2"] } },
    });
  });

  it("shows the plans and the hosts that get none before anything can be ordered", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("fix-ssh_root_login"));
    // Nothing can be ordered while nothing has been shown.
    expect(screen.queryByTestId("remediation-order")).not.toBeInTheDocument();
    fireEvent.click(await screen.findByTestId("remediation-preview"));
    await waitFor(() => expect(screen.getByTestId("remediation-plans")).toBeInTheDocument());
    expect(screen.getByTestId("plan-0123456789abcdef")).toHaveTextContent("file.render");
    expect(screen.getByTestId("excluded-h9")).toHaveTextContent("the agent is too old to render the file");
    expect(screen.getByTestId("remediation-order")).toBeInTheDocument();
  });

  it("drops the plans the moment the question changes, so an old answer is never ordered", async () => {
    given();
    await previewed();
    // The plans were computed for the hosts of the ticked checks; asked
    // over a site instead they answer a question nobody put any more.
    fireEvent.change(screen.getByTestId("remediation-scope"), { target: { value: "filters" } });
    await waitFor(() => expect(screen.queryByTestId("remediation-plans")).not.toBeInTheDocument());
    expect(screen.queryByTestId("remediation-order")).not.toBeInTheDocument();
  });

  it("orders nothing without a reason of its own, and then sends the body the server reads", async () => {
    given();
    await previewed();
    fireEvent.click(screen.getByTestId("remediation-order"));

    const confirm = await screen.findByTestId("remediation-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("remediation-reason"), { target: { value: "short" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("remediation-reason"), { target: { value: "the audit asked for it" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() => expect(sent).toHaveLength(2));
    expect(sent[1]).toMatchObject({
      method: "POST",
      path: "/api/v1/security/remediation",
      body: {
        check_ids: ["ssh_root_login"],
        selector: { host_ids: ["h1", "h2"] },
        reason: "the audit asked for it",
        canary_size: 1,
        wave_size: 5,
        max_concurrent: 2,
        manual_gate: false,
      },
    });
    await waitFor(() => expect(navigated).toEqual(["/next/campaigns/c-7"]));
  });

  it("carries the rollout the operator set, not the one the form opened with", async () => {
    given();
    await previewed();
    fireEvent.change(screen.getByTestId("remediation-wave"), { target: { value: "3" } });
    fireEvent.change(screen.getByTestId("remediation-concurrent"), { target: { value: "1" } });
    fireEvent.click(screen.getByText("stop after the canary until somebody advances the campaign"));
    fireEvent.click(screen.getByTestId("remediation-order"));
    fireEvent.change(await screen.findByTestId("remediation-reason"), { target: { value: "quarterly hardening" } });
    fireEvent.click(screen.getByTestId("remediation-confirm"));
    await waitFor(() => expect(sent).toHaveLength(2));
    expect(sent[1].body).toMatchObject({ wave_size: 3, max_concurrent: 1, manual_gate: true });
  });

  it("sends the filters rather than a host list when the scope is a site", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("fix-ssh_root_login"));
    fireEvent.change(await screen.findByTestId("remediation-scope"), { target: { value: "filters" } });
    // Until a site or an environment is named the order reaches nobody, and
    // the panel says so rather than letting the server refuse a fix-all.
    expect(screen.getByTestId("remediation-preview")).toBeDisabled();
    expect(screen.getByText("Name the hosts first: there is no fix-all.")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("remediation-site"), { target: { value: "lab" } });
    fireEvent.click(screen.getByTestId("remediation-preview"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toMatchObject({ selector: { site: "lab" } });
    expect((sent[0].body as { selector: Record<string, unknown> }).selector).not.toHaveProperty("host_ids");
  });

  it("puts a refusal of the preview in front of the reader", async () => {
    given();
    const { ApiError } = await import("../../lib/api");
    refusals["/api/v1/security/remediation/preview"] =
      new ApiError(400, "no_targets", "the selector matched no hosts");
    draw();
    fireEvent.click(await screen.findByTestId("fix-ssh_root_login"));
    fireEvent.click(await screen.findByTestId("remediation-preview"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("the selector matched no hosts"));
    expect(screen.queryByTestId("remediation-order")).not.toBeInTheDocument();
  });

  it("puts a refusal of the order in the dialog it was given in, and orders nothing", async () => {
    given();
    const { ApiError } = await import("../../lib/api");
    refusals["/api/v1/security/remediation"] =
      new ApiError(403, "forbidden", "you may not remediate in this scope");
    await previewed();
    fireEvent.click(screen.getByTestId("remediation-order"));
    fireEvent.change(await screen.findByTestId("remediation-reason"), { target: { value: "the audit asked for it" } });
    fireEvent.click(screen.getByTestId("remediation-confirm"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("you may not remediate in this scope"));
    expect(navigated).toEqual([]);
  });
});

describe("whom an order names", () => {
  const draft: RemediationDraft = {
    scope: "findings", site: "", environment: "", canary: 1, wave: 5, concurrent: 2, manualGate: false,
  };
  const checks = [check(), undecided()];

  it("lists the hosts of the ticked checks once each, in order", () => {
    expect(selectorOf(draft, checks, ["ssh_root_login"])).toEqual({ host_ids: ["h1", "h2"] });
  });

  it("leaves an untyped filter out rather than sending it empty", () => {
    expect(selectorOf({ ...draft, scope: "filters", site: " lab " }, checks, []))
      .toEqual({ site: "lab", environment: undefined });
  });

  it("knows an order that names nobody from one that names somebody", () => {
    expect(scopeMissing(draft, { host_ids: [] })).toBe(true);
    expect(scopeMissing(draft, { host_ids: ["h1"] })).toBe(false);
    expect(scopeMissing({ ...draft, scope: "filters" }, {})).toBe(true);
    expect(scopeMissing({ ...draft, scope: "filters", environment: "test" }, { environment: "test" })).toBe(false);
  });

  it("colours a severity the way the reader reads it", () => {
    expect(severityTone("high")).toBe("error");
    expect(severityTone("medium")).toBe("warn");
    expect(severityTone("info")).toBe("unknown");
  });
});
