import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Policies, countVerdicts, groupByPolicy, worstVerdict } from "./Policies";
import type { Host, PolicyResult } from "../../../lib/types";

/**
 * The verdicts of the declared state. Nothing is ordered from here, so
 * what the module does is read: it groups the rules by the policy that
 * declared them, it names the inventory revision each was judged against,
 * and it refuses to turn "nobody has judged this host" into a clean pass.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest match wins: `/api/v1/hosts/h1` is a prefix of
  // `/api/v1/hosts/h1/policies`, and answering the second with the first
  // hands the screen the wrong document.
  const reply = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const answer = answers[key];
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => { asked.push(path); return reply(path); },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  enrolled_at: "2026-10-01T00:00:00Z",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, capabilities: [], identity: {},
} as unknown as Host;

const result = (over: Partial<PolicyResult> = {}): PolicyResult => ({
  policy_id: "p1",
  policy_name: "Baseline",
  host_id: "h1",
  rule_index: 0,
  rule: { kind: "package_installed", name: "chrony" },
  version: 3,
  verdict: "compliant",
  observed_revision: "abcdef0123456789",
  evaluated_at: "2026-10-16T08:00:00Z",
  ...over,
} as PolicyResult);

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Policies host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the module reads", () => {
  it("keeps the rules of one policy together, in the order the server gave them", () => {
    const groups = groupByPolicy([
      result({ policy_id: "p1", rule_index: 0 }),
      result({ policy_id: "p2", policy_name: "Hardening", rule_index: 0 }),
      result({ policy_id: "p1", rule_index: 1 }),
    ]);
    expect(groups.map((one) => one.policyID)).toEqual(["p1", "p2"]);
    expect(groups[0].results).toHaveLength(2);
  });

  it("falls back to the identifier when the policy has no name of its own", () => {
    expect(groupByPolicy([result({ policy_name: undefined })])[0].name).toBe("p1");
  });

  it("counts every verdict, zero included, so the four always add up", () => {
    expect(countVerdicts([result(), result({ verdict: "drift" })])).toEqual({
      compliant: 1, drift: 1, error: 0, not_applicable: 0,
    });
  });

  it("lets the worst verdict decide how a policy reads, and says nothing of an empty one", () => {
    expect(worstVerdict([result(), result({ verdict: "drift" })])).toBe("drift");
    expect(worstVerdict([result({ verdict: "error" }), result({ verdict: "drift" })])).toBe("error");
    expect(worstVerdict([])).toBeUndefined();
  });
});

describe("the policies of a host", () => {
  it("draws a rule with its verdict, its reason and what it was judged against", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/policies": {
        items: [result({ verdict: "drift", reason: "chrony is not installed" })],
        count: 1,
      },
    });
    draw();
    const row = await screen.findByTestId("rule-p1-0");
    expect(row).toHaveTextContent("package chrony installed");
    expect(within(row).getByText("drift")).toBeInTheDocument();
    expect(row).toHaveTextContent("chrony is not installed");
    // The revision is what makes a verdict checkable; the whole of it is
    // too long to read, the first twelve are enough to match.
    expect(row).toHaveTextContent("abcdef012345");
    // And the heading says what the revision is, as the old one did.
    expect(screen.getByText("Judged against"))
      .toHaveAttribute("title", "The inventory revision the rule was judged against.");
  });

  it("names the rule by its index when the policy did not describe it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/policies": { items: [result({ rule: undefined, rule_index: 4 })], count: 1 },
    });
    draw();
    const row = await screen.findByTestId("rule-p1-4");
    expect(row).toHaveTextContent("#4");
  });

  it("says a reason nobody gave is a dash rather than an empty cell", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/policies": {
        items: [result({ reason: undefined, observed_revision: undefined })],
        count: 1,
      },
    });
    draw();
    const row = await screen.findByTestId("rule-p1-0");
    expect(row).toHaveTextContent("—");
  });

  it("gives each policy the worst of its own verdicts and a way into its record", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/policies": {
        items: [result(), result({ rule_index: 1, verdict: "error", reason: "could not read /etc" })],
        count: 2,
      },
    });
    draw();
    const row = await screen.findByTestId("policy-Baseline");
    expect(within(row).getByText("error")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "Baseline" })).toHaveAttribute("href", "/policies/p1");
    expect(row).toHaveTextContent("3");
  });

  it("counts the rules over the policies that selected this host", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/policies": {
        items: [result(), result({ rule_index: 1, verdict: "drift" }), result({ policy_id: "p2", policy_name: "Hardening" })],
        count: 3,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByText("3 rules over 2 policies")).toBeInTheDocument());
    const band = screen.getByTestId("verdicts");
    expect(band).toHaveTextContent("compliant");
    expect(band).toHaveTextContent("drift");
  });

  it("says a host nobody has judged is not a host that passed", async () => {
    // The answer never arrives: the verdicts are not counted, and that is
    // a different answer from four noughts.
    Object.assign(answers, { "/api/v1/hosts/h1/policies": new Promise(() => {}) });
    draw();
    await waitFor(() => expect(screen.getByTestId("verdicts")).toBeInTheDocument());
    const band = screen.getByTestId("verdicts");
    expect(band).toHaveTextContent("not counted");
    expect(band).toHaveTextContent("—");
  });

  it("offers the policies themselves where no policy selects this host", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/policies": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByText(/No policy selects this host, or none has been evaluated yet/))
      .toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Open the policies" })).toHaveAttribute("href", "/policies");
  });

  it("says a refusal to read the verdicts rather than drawing a host with none", async () => {
    Object.assign(answers, { "/api/v1/hosts/h1/policies": new Error("not for you") });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("not for you"));
  });
});
