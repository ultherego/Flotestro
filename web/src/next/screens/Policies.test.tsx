import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Policies, complianceShares, policyStanding, pruneRule, ruleSummary, selectorOf } from "./Policies";
import { ToastProvider } from "../../components/Toast";

/**
 * A policy says what is to be true on a group of hosts, so the thing held
 * hardest here is the difference between a fleet nobody has judged and a
 * fleet with nothing wrong: an unevaluated policy has no verdicts, never
 * four noughts.
 *
 * The screen is also the single policy - `/next/policies/<id>` opens one -
 * so what is checked is what it reads, what it writes, on which version,
 * and what it refuses to do without being asked twice.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const written: { path: string; body: unknown; headers?: Record<string, string> }[] = [];
const deleted: { path: string; body: unknown; headers?: Record<string, string> }[] = [];
const answers: Record<string, unknown> = {};

let etag = 'W/"3"';
let refuse: unknown = null;

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key wins: "/api/v1/policies/p1" would otherwise answer
  // "/api/v1/policies/p1/results" with the policy itself.
  const pick = (path: string) => Object.keys(answers)
    .filter((one) => path.startsWith(one))
    .sort((a, b) => b.length - a.length)[0];
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const key = pick(path);
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      getWithMeta: (path: string) => {
        asked.push(path);
        const key = pick(path);
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such policy"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve({ data: answer, etag });
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        if (refuse) return Promise.reject(refuse);
        if (path.endsWith("/evaluate")) {
          return Promise.resolve({
            policy_id: "p1", version: 2, hosts: 4,
            counts: { compliant: 3, drift: 1, error: 0, not_applicable: 0 },
            evaluated_at: "2026-10-16T09:00:00Z",
          });
        }
        if (path.endsWith("/publish")) return Promise.resolve({ ...policy(), version: 2 });
        return Promise.resolve({ ...policy(), id: "p9", name: "baseline-cron", version: 0 });
      },
      put: (path: string, body: unknown, options?: { headers?: Record<string, string> }) => {
        written.push({ path, body, headers: options?.headers });
        if (refuse) return Promise.reject(refuse);
        return Promise.resolve({});
      },
      del: (path: string, body: unknown, options?: { headers?: Record<string, string> }) => {
        deleted.push({ path, body, headers: options?.headers });
        if (refuse) return Promise.reject(refuse);
        return Promise.resolve(undefined);
      },
    },
  };
});

const policy = (over: Record<string, unknown> = {}) => ({
  id: "p1", name: "baseline-cron", description: "cron is on every host",
  version: 1, selector: { site: "warsaw" },
  rules: [{ kind: "package_installed", name: "cron" }],
  remediation_mode: "report", enabled: true, check_interval_seconds: 900,
  created_by: "ada", created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-15T00:00:00Z",
  published_at: "2026-10-02T00:00:00Z", published_by: "ada",
  last_evaluated_at: "2026-10-16T08:00:00Z", draft: false,
  counts: { compliant: 7, drift: 2, error: 0, not_applicable: 1 },
  ...over,
});

const everything = { permissions: ["policy.write", "policy.publish"] };
const nothing = { permissions: [] as string[] };

function draw(at = "/next/policies") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><ToastProvider>{children}</ToastProvider></QueryClientProvider>
  );
  return render(
    <MemoryRouter initialEntries={[at]}>
      <Routes>
        <Route path="/next/policies" element={<Policies />} />
        <Route path="/next/policies/:id" element={<Policies />} />
      </Routes>
    </MemoryRouter>,
    { wrapper },
  );
}

/** Everything one open policy answers, so the detail cards all fill. */
function openOne(over: Record<string, unknown> = {}, who: unknown = everything) {
  Object.assign(answers, {
    "/api/v1/policies": { items: [policy(over)] },
    "/api/v1/policies/p1": policy(over),
    "/api/v1/policies/p1/results": { items: [], total: 0 },
    "/api/v1/policies/p1/versions": { items: [] },
    "/api/v1/policies/p1/campaigns": { items: [] },
    "/api/v1/whoami": who,
  });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  written.length = 0;
  deleted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  etag = 'W/"3"';
  refuse = null;
});

describe("the policy list", () => {
  it("draws a policy and leads to it inside the new panel", async () => {
    Object.assign(answers, {
      "/api/v1/policies": { items: [policy()] },
      "/api/v1/whoami": nothing,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("policy-baseline-cron")).toBeInTheDocument());
    const row = screen.getByTestId("policy-baseline-cron");
    expect(within(row).getByRole("link", { name: "baseline-cron" })).toHaveAttribute("href", "/next/policies/p1");
    expect(row).toHaveTextContent("v1");
    expect(row).toHaveTextContent("7 compliant");
    expect(row).toHaveTextContent("2 drift");
  });

  it("says a policy nobody evaluated is unevaluated, not wholly compliant", async () => {
    Object.assign(answers, {
      "/api/v1/policies": { items: [policy({
        name: "fresh", version: 0, draft: true, last_evaluated_at: undefined,
        counts: { compliant: 0, drift: 0, error: 0, not_applicable: 0 },
      })] },
      "/api/v1/whoami": nothing,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("policy-fresh")).toBeInTheDocument());
    const row = screen.getByTestId("policy-fresh");
    expect(row).toHaveTextContent("not evaluated");
    expect(row).toHaveTextContent("not published");
    expect(row).toHaveTextContent("never");
    // Four noughts would read as a fleet with nothing wrong with it.
    expect(within(row).queryByText("0 compliant")).toBeNull();
  });

  it("says a list nobody has answered for is unknown, and never nought", async () => {
    Object.assign(answers, {
      "/api/v1/policies": new Promise(() => { /* never answers */ }),
      "/api/v1/whoami": nothing,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-policies")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-policies")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-policies")).not.toHaveTextContent("0");
    expect(screen.getByTestId("kpi-drifting")).toHaveAttribute("data-state", "unknown");
  });

  it("creates a draft and opens it", async () => {
    Object.assign(answers, {
      "/api/v1/policies": { items: [] },
      "/api/v1/whoami": everything,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-policy")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-policy"));
    // A draft with no name is not a draft.
    expect(screen.getByTestId("create-policy")).toBeDisabled();
    fireEvent.change(screen.getByTestId("policy-name"), { target: { value: " baseline-cron " } });
    fireEvent.change(screen.getByTestId("policy-mode"), { target: { value: "campaign" } });
    fireEvent.click(screen.getByTestId("create-policy"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/policies");
    expect(posted[0].body).toEqual({
      name: "baseline-cron", description: "", selector: {}, rules: [], remediation_mode: "campaign",
    });
  });
});

describe("one policy", () => {
  it("opens the policy the address names", async () => {
    openOne();
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("draft-name")).toHaveValue("baseline-cron"));
    expect(asked).toContain("/api/v1/policies/p1");
    expect(asked.some((one) => one.startsWith("/api/v1/policies/p1/versions"))).toBe(true);
    expect(asked.some((one) => one.startsWith("/api/v1/policies/p1/campaigns"))).toBe(true);
    // The document is the published one, and the compliance is of this
    // policy rather than of the list.
    expect(screen.getByTestId("policy-compliance")).toHaveTextContent("compliant");
  });

  it("holds an unevaluated policy's verdicts as uncounted rather than as noughts", async () => {
    openOne({ last_evaluated_at: undefined, counts: { compliant: 0, drift: 0, error: 0, not_applicable: 0 } });
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("policy-compliance")).toBeInTheDocument());
    const band = screen.getByTestId("policy-compliance");
    expect(band).toHaveTextContent("not counted");
    expect(screen.getByText("Not evaluated yet.")).toBeInTheDocument();
  });

  it("asks before publishing and sends the reason with the publication", async () => {
    openOne();
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("publish")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("publish"));
    expect(posted).toHaveLength(0);
    fireEvent.change(screen.getByTestId("publish-reason"), { target: { value: "the baseline moved" } });
    fireEvent.click(screen.getByTestId("publish-confirm"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/policies/p1/publish");
    expect(posted[0].body).toEqual({ reason: "the baseline moved" });
    await waitFor(() => expect(screen.getByText(/Published as version 2/)).toBeInTheDocument());
  });

  it("warns that automatic remediation is approved by the publication itself", async () => {
    openOne({ remediation_mode: "automatic" });
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("publish")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("publish"));
    expect(screen.getByText(/start without a second look/)).toBeInTheDocument();
  });

  it("evaluates on demand and says what the evaluation found", async () => {
    openOne();
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("evaluate")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("evaluate"));
    await waitFor(() => expect(posted[0].path).toBe("/api/v1/policies/p1/evaluate"));
    await waitFor(() => expect(screen.getByText(/Evaluated 4 hosts/)).toBeInTheDocument());
  });

  it("asks before deleting, refuses a reason of under eight characters, and writes on the version it read", async () => {
    openOne();
    etag = 'W/"11"';
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("delete-policy")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("delete-policy"));
    expect(deleted).toHaveLength(0);
    fireEvent.change(screen.getByTestId("delete-policy-reason"), { target: { value: "stale" } });
    expect(screen.getByTestId("delete-policy-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("delete-policy-reason"), { target: { value: "superseded by the image" } });
    fireEvent.click(screen.getByTestId("delete-policy-confirm"));
    await waitFor(() => expect(deleted).toHaveLength(1));
    expect(deleted[0].path).toBe("/api/v1/policies/p1");
    expect(deleted[0].headers).toEqual({ "If-Match": 'W/"11"' });
    expect(deleted[0].body).toEqual({ reason: "superseded by the image" });
  });

  it("offers nothing to change to somebody who may neither write nor publish", async () => {
    openOne({}, nothing);
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("draft-name")).toBeInTheDocument());
    expect(screen.queryByTestId("new-policy")).toBeNull();
    expect(screen.queryByTestId("publish")).toBeNull();
    expect(screen.queryByTestId("evaluate")).toBeNull();
    expect(screen.queryByTestId("delete-policy")).toBeNull();
    expect(screen.queryByTestId("save-draft")).toBeNull();
    // The document is readable, but not writable.
    expect(screen.getByTestId("draft-name")).toBeDisabled();
  });

  it("lets somebody who may publish but not write do neither of the other two", async () => {
    openOne({}, { permissions: ["policy.publish"] });
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("publish")).toBeInTheDocument());
    expect(screen.queryByTestId("evaluate")).toBeNull();
    expect(screen.queryByTestId("delete-policy")).toBeNull();
  });

  it("writes the draft on the tag it read, and carries no field of the kind a rule used to be", async () => {
    openOne();
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByLabelText("Rule 1")).toBeInTheDocument());
    // A package name must not ride along into a sysctl rule: the server
    // would store whatever it was sent.
    fireEvent.change(screen.getByLabelText("Rule 1"), { target: { value: "sysctl" } });
    fireEvent.change(screen.getByLabelText("net.ipv4.ip_forward"), { target: { value: "net.ipv4.ip_forward" } });
    fireEvent.change(screen.getByLabelText("value"), { target: { value: "1" } });
    fireEvent.click(screen.getByTestId("save-draft"));
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0].path).toBe("/api/v1/policies/p1");
    expect(written[0].headers).toEqual({ "If-Match": 'W/"3"' });
    const spec = written[0].body as { rules: unknown[]; check_interval_seconds: number; selector: unknown };
    expect(spec.rules).toEqual([{ kind: "sysctl", key: "net.ipv4.ip_forward", value: "1" }]);
    // The form holds minutes; the server takes seconds.
    expect(spec.check_interval_seconds).toBe(900);
    expect(spec.selector).toEqual({ site: "warsaw", environment: undefined, os_family: undefined });
  });

  it("says a refusal of the write in the words the API used", async () => {
    openOne();
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("save-draft")).toBeInTheDocument());
    const { ApiError } = await import("../../lib/api");
    refuse = new ApiError(412, "stale_etag", "the policy changed since it was read");
    fireEvent.change(screen.getByTestId("draft-name"), { target: { value: "baseline-cron-2" } });
    fireEvent.click(screen.getByTestId("save-draft"));
    await waitFor(() => expect(screen.getByText(/stale_etag/)).toBeInTheDocument());
  });

  it("narrows the verdicts on the server rather than in the browser", async () => {
    openOne();
    Object.assign(answers, {
      "/api/v1/policies/p1/results": {
        items: [{
          policy_id: "p1", host_id: "h1", hostname: "agent-arch", rule_index: 0,
          rule: { kind: "package_installed", name: "cron" }, version: 1,
          verdict: "drift", reason: "cron is absent", evaluated_at: "2026-10-16T08:00:00Z",
        }],
        total: 1,
      },
    });
    draw("/next/policies/p1");
    await waitFor(() => expect(screen.getByTestId("result-h1-0")).toBeInTheDocument());
    const row = screen.getByTestId("result-h1-0");
    expect(within(row).getByRole("link", { name: "agent-arch" })).toHaveAttribute("href", "/next/hosts/h1/policies");
    expect(row).toHaveTextContent("package cron installed");
    expect(row).toHaveTextContent("drift");

    asked.length = 0;
    fireEvent.change(screen.getByTestId("result-verdict"), { target: { value: "error" } });
    await waitFor(() => expect(asked.some((one) => one.includes("verdict=error"))).toBe(true));
  });

  it("says nothing of a policy before one is opened", async () => {
    Object.assign(answers, {
      "/api/v1/policies": { items: [policy()] },
      "/api/v1/whoami": everything,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("policy-baseline-cron")).toBeInTheDocument());
    // No policy is open, so nothing is read for one.
    expect(asked.some((one) => one.startsWith("/api/v1/policies/p1"))).toBe(false);
    expect(screen.queryByTestId("save-draft")).toBeNull();
    expect(screen.getAllByText(/Open a policy from the list/).length).toBeGreaterThan(0);
  });
});

describe("the vocabulary of a policy", () => {
  it("gives one segment per verdict with a count, and none at all to an unjudged policy", () => {
    expect(complianceShares({ compliant: 3, drift: 1 }).map((one) => one.verdict)).toEqual(["compliant", "drift"]);
    expect(complianceShares({ compliant: 0, drift: 0, error: 0, not_applicable: 0 })).toEqual([]);
    expect(complianceShares(undefined)).toEqual([]);
  });

  it("tells a never-published draft from a draft on top of a version", () => {
    expect(policyStanding({ version: 0, draft: true, enabled: true })).toBe("unpublished");
    expect(policyStanding({ version: 2, draft: true, enabled: true })).toBe("draft");
    expect(policyStanding({ version: 2, draft: false, enabled: false })).toBe("disabled");
    expect(policyStanding({ version: 2, draft: false, enabled: true })).toBe("published");
  });

  it("puts every rule kind in the server's words and keeps an unknown one by name", () => {
    expect(ruleSummary({ kind: "unit_state", unit: "cron.service", enabled: true, active: false }))
      .toBe("unit cron.service enabled and inactive");
    expect(ruleSummary({ kind: "sysctl", key: "net.ipv4.ip_forward", value: "1" }))
      .toBe("sysctl net.ipv4.ip_forward = 1");
    expect(ruleSummary({ kind: "something_new" })).toBe("something_new");
  });

  it("drops an undeclared half of a unit state rather than sending it as false", () => {
    expect(pruneRule({ kind: "unit_state", unit: "cron.service", enabled: undefined, active: true }))
      .toEqual({ kind: "unit_state", unit: "cron.service", active: true });
  });

  it("sends the flat fields, the built expression or the JSON as typed", () => {
    const base = { site: "", environment: "", osFamily: "", selectorRules: [], combine: "all" as const, expressionText: "" };
    expect(selectorOf({ ...base, targetMode: "filters", site: "warsaw" }).selector)
      .toEqual({ site: "warsaw", environment: undefined, os_family: undefined });
    expect(selectorOf({ ...base, targetMode: "expression", selectorRules: [{ field: "tag", value: "db", negated: false }] }).selector)
      .toEqual({ expression: { tag: "db" } });
    expect(selectorOf({ ...base, targetMode: "json", expressionText: "{" }).error).toBeTruthy();
  });
});
