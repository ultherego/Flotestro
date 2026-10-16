import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Budgets, classTotals, describeBudgetKey, holderLink } from "./Budgets";
import { ToastProvider } from "../../components/Toast";

/**
 * A budget is a number the store reads before an operation runs, so what
 * is held hardest here is the difference between a capacity nobody has
 * answered for and a capacity of nought - the second one reads as an
 * installation that refuses everything.
 *
 * The rest is what the screen does rather than what it draws: which
 * address a write goes to, on which version, and what it refuses to send.
 */

const asked: string[] = [];
const written: { path: string; body: unknown; headers?: Record<string, string> }[] = [];
const deleted: { path: string; body: unknown; headers?: Record<string, string> }[] = [];
const answers: Record<string, unknown> = {};

/** The record of a configured budget, and the tag the editor writes back on. */
let limit: { capacity: number; note: string; updated_at: string } = {
  capacity: 10, note: "the link of the site", updated_at: "2026-10-15T09:00:00Z",
};
let etag = 'W/"7"';
let refuse: unknown = null;

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  const pick = (path: string) => Object.keys(answers)
    .filter((one) => path.startsWith(one))
    // The longest key wins: "/api/v1/budgets" would otherwise answer
    // "/api/v1/budgets/global:mutations" with the whole list.
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
        return Promise.resolve({ data: { key: "k", ...limit }, etag });
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
      post: () => Promise.resolve({}),
    },
  };
});

const budget = (over: Record<string, unknown> = {}) => ({
  key: "global:mutations", capacity: 10, used: 4, claimants: 2,
  waiting_jobs: 0, waiting_targets: 0, holders: [], by_class: {},
  ...over,
});

const mayWrite = { permissions: ["budget.write"] };
const mayNot = { permissions: [] as string[] };

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Budgets />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  written.length = 0;
  deleted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  limit = { capacity: 10, note: "the link of the site", updated_at: "2026-10-15T09:00:00Z" };
  etag = 'W/"7"';
  refuse = null;
});

describe("the budgets", () => {
  it("draws a key as what it guards, how full it is and who holds it", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget({
        key: "site:warsaw:packages",
        holders: [{ owner: "t1", claimant: "campaign:c1", class: "maintenance", tokens: 2, since: "2026-10-16T07:00:00Z" }],
      })] },
      "/api/v1/whoami": mayNot,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("budget-site:warsaw:packages")).toBeInTheDocument());
    const row = screen.getByTestId("budget-site:warsaw:packages");
    expect(row).toHaveTextContent("site:warsaw:packages");
    // The family and the scope are read off the key, not sent by the server.
    expect(row).toHaveTextContent("Site");
    expect(row).toHaveTextContent("warsaw");
    expect(row).toHaveTextContent("4 / 10");
    // A holder leads where the work is, inside the new panel.
    expect(within(row).getByRole("link", { name: /campaign/ })).toHaveAttribute("href", "/next/campaigns/c1");
  });

  it("leads the work waiting on a budget to where it waits", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget({ waiting_jobs: 3, waiting_targets: 5 })] },
      "/api/v1/whoami": mayNot,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("budget-global:mutations")).toBeInTheDocument());
    const row = screen.getByTestId("budget-global:mutations");
    expect(within(row).getByRole("link", { name: "3" })).toHaveAttribute("href", "/next/jobs?state=queued");
    expect(within(row).getByRole("link", { name: "5" })).toHaveAttribute("href", "/next/campaigns");
  });

  it("says a fleet nobody has answered for is unknown, and never nought", async () => {
    // The request is still out: a tile reading 0 here would say the
    // installation has no capacity at all, which nobody has asked yet.
    Object.assign(answers, {
      "/api/v1/budgets": new Promise(() => { /* never answers */ }),
      "/api/v1/whoami": mayWrite,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-keys")).toBeInTheDocument());
    expect(screen.getByTestId("kpi-keys")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-keys")).not.toHaveTextContent("0");
    expect(screen.getByTestId("kpi-waiting-jobs")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-saturated")).toHaveAttribute("data-state", "unknown");
  });

  it("names an installation that has no budgets at all instead of failing", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, {
      "/api/v1/budgets": new ApiError(501, "not_implemented", "budgets are off"),
      "/api/v1/whoami": mayWrite,
    });
    draw();
    await waitFor(() => expect(screen.getByText("Budgets are disabled in this installation.")).toBeInTheDocument());
    // It is a fact about the installation, not a failure of the screen.
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers no form and no editor to somebody who may not write", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget()] },
      "/api/v1/whoami": mayNot,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("budget-global:mutations")).toBeInTheDocument());
    expect(screen.queryByTestId("new-budget")).toBeNull();
    fireEvent.click(screen.getByTestId("pick-global:mutations"));
    await waitFor(() => expect(screen.getByText(/You may not change this budget/)).toBeInTheDocument());
    expect(screen.queryByTestId("capacity-save")).toBeNull();
    expect(screen.queryByTestId("budget-delete")).toBeNull();
  });

  it("refuses a key that is not a budget key, and one already configured", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget({ key: "site:*:packages" })] },
      "/api/v1/whoami": mayWrite,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-budget")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-budget"));

    fireEvent.change(screen.getByTestId("new-budget-key"), { target: { value: "nonsense" } });
    expect(screen.getByTestId("new-budget-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("new-budget-key"), { target: { value: "site:*:packages" } });
    expect(screen.getByTestId("new-budget-save")).toBeDisabled();
    expect(screen.getByText(/already configured/)).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("new-budget-key"), { target: { value: "site:warsaw:reads" } });
    fireEvent.change(screen.getByTestId("new-budget-capacity"), { target: { value: "0" } });
    expect(screen.getByTestId("new-budget-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("new-budget-capacity"), { target: { value: "6" } });
    fireEvent.change(screen.getByTestId("new-budget-note"), { target: { value: "the uplink" } });
    expect(screen.getByTestId("new-budget-save")).toBeEnabled();

    fireEvent.click(screen.getByTestId("new-budget-save"));
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0].path).toBe("/api/v1/budgets/site%3Awarsaw%3Areads");
    expect(written[0].body).toEqual({ capacity: 6, note: "the uplink" });
    // A key nobody has configured has no version to write on.
    expect(written[0].headers).toEqual({});
  });

  it("changes a capacity on the version it read, and says so when that version moved", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget()] },
      "/api/v1/whoami": mayWrite,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-global:mutations")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-global:mutations"));
    await waitFor(() => expect(screen.getByTestId("capacity-note")).toHaveValue("the link of the site"));

    // Nothing has changed yet, so there is nothing to save.
    expect(screen.getByTestId("capacity-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("capacity"), { target: { value: "20" } });
    expect(screen.getByTestId("capacity-save")).toBeEnabled();

    const { ApiError } = await import("../../lib/api");
    refuse = new ApiError(412, "precondition_failed", "it moved");
    fireEvent.click(screen.getByTestId("capacity-save"));
    await waitFor(() => expect(screen.getByText(/changed since it was read/)).toBeInTheDocument());
    expect(written[0].path).toBe("/api/v1/budgets/global%3Amutations");
    expect(written[0].headers).toEqual({ "If-Match": 'W/"7"' });
    expect(written[0].body).toEqual({ capacity: 20, note: "the link of the site" });
  });

  it("asks before taking a capacity away, and will not take a reason of under eight characters", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget({ used: 3 })] },
      "/api/v1/whoami": mayWrite,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("pick-global:mutations")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-global:mutations"));
    await waitFor(() => expect(screen.getByTestId("budget-delete")).toBeInTheDocument());

    // Nothing is sent before the question is answered.
    fireEvent.click(screen.getByTestId("budget-delete"));
    expect(deleted).toHaveLength(0);
    // The held tokens are said out loud: the server will refuse until the
    // work finishes, and that is worth knowing before the button is found.
    expect(screen.getByText(/3 tokens are held right now/)).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("budget-delete-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("budget-delete-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("budget-delete-reason"), { target: { value: "the site is gone" } });
    expect(screen.getByTestId("budget-delete-confirm")).toBeEnabled();

    fireEvent.click(screen.getByTestId("budget-delete-confirm"));
    await waitFor(() => expect(deleted).toHaveLength(1));
    expect(deleted[0].path).toBe("/api/v1/budgets/global%3Amutations");
    expect(deleted[0].body).toEqual({ reason: "the site is gone" });
    // The removal goes on the version it was read at, not on whatever the
    // list happened to hold.
    expect(deleted[0].headers).toEqual({ "If-Match": 'W/"7"' });
  });

  it("marks a token it cannot place rather than counting it as a class", async () => {
    Object.assign(answers, {
      "/api/v1/budgets": { items: [budget({ by_class: { incident: 2, unknown: 1 } })] },
      "/api/v1/whoami": mayNot,
    });
    draw();
    await waitFor(() => expect(screen.getByText(/incident/)).toBeInTheDocument());
    // The known classes are always there, zero included; a class the API
    // named on its own only when it holds something.
    const totals = classTotals([{ by_class: { incident: 2, unknown: 1 } }]);
    expect(totals.map((one) => one.name)).toEqual(["incident", "interactive", "maintenance", "background", "unknown"]);
    expect(totals[0].tokens).toBe(2);
  });
});

describe("the vocabulary of a key", () => {
  it("marks an asterisk in the scope as the default of its family", () => {
    expect(describeBudgetKey("site:*:packages")).toEqual({ kind: "site", scope: "*", resource: "packages", pattern: true });
    expect(describeBudgetKey("global:mutations")).toEqual({ kind: "global", scope: "", resource: "mutations", pattern: false });
    expect(describeBudgetKey("whatever")).toEqual({ kind: "other", scope: "", resource: "whatever", pattern: false });
  });

  it("leads a holder into the new panel, and a holder of an unknown shape nowhere", () => {
    expect(holderLink({ owner: "job:j1", claimant: "jobs:ada" })?.to).toBe("/next/jobs?actor=ada");
    expect(holderLink({ owner: "fanout:f1", claimant: "reads:ada" })?.to).toBe("/next/reads/f1");
    expect(holderLink({ owner: "x", claimant: "y" })).toBeNull();
  });
});
