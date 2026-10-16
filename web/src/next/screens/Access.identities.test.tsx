import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Access, reviewedBy, type BindingScope } from "./Access";
import { ToastProvider } from "../../components/Toast";

/**
 * The access review: who has been checked, and who has not.
 *
 * It is the one question the list of identities cannot answer, and the one
 * an auditor asks first. What the server did not count is an em dash here
 * and never a nought - an installation nobody has reviewed and one with
 * nothing to review are opposite answers - and the right that guards the
 * read is the right that writes an identity, so somebody without it is
 * offered no review rather than a card that comes back a refusal.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
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
      post: () => Promise.resolve({}),
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const labScope: BindingScope = {
  site: "lab", environment: "test", team_scope: { mode: "any" }, owners: ["*"], tags: ["db"],
};

const review = {
  items: [
    {
      id: "p1", subject: "tszymanski", display_name: "Tomasz Szymanski", kind: "user",
      created_at: "2026-01-01T08:00:00Z", last_seen_at: "2026-07-01T08:00:00Z",
      bindings: [{
        role: "operator", scope: labScope, expired: false,
        created_by: "admin", created_at: "2026-01-01T08:00:00Z",
      }],
      tokens: [{ id: "t1ab2cd3e4", description: "backup runner", created_at: "2026-01-01T08:00:00Z" }],
      flags: ["unused_90_days"],
    },
    {
      id: "p2", subject: "backup-runner", kind: "service", created_at: "2026-02-01T08:00:00Z",
      bindings: [], tokens: [], flags: [],
    },
  ],
  count: 2, flagged: 1, reviewed_at: "2026-10-16T08:00:00Z",
  thresholds: { unused_days: 90, expires_soon_days: 7, token_max_days: 365 },
};

function given(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/roles": { items: [{ role: "operator", built_in: true, permissions: ["host.read"] }], count: 1 },
    "/api/v1/permissions": { items: [{ permission: "host.read", group: "host" }], count: 1 },
    "/api/v1/teams": { items: [], count: 0 },
    "/api/v1/group-mappings": { items: [], count: 0 },
    "/api/v1/whoami": { permissions: ["principal.manage"] },
    "/api/v1/access/review": review,
    "/api/v1/access/holders": { items: [], count: 0, directory: { configured: false, read: false } },
    "/api/v1/principals": { items: [], count: 0, total: 0, limit: 50, offset: 0 },
    ...over,
  });
}

/** One figure of the review's foot, found by the label under it. */
function fig(card: HTMLElement, label: string): string {
  const found = [...card.querySelectorAll(".fl-fig")]
    .find((one) => one.querySelector(".fl-fig-label")?.textContent === label);
  return found?.querySelector(".fl-fig-value")?.textContent ?? "";
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Access />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the access review", () => {
  it("says who has been checked and who has not, with what to look at", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("review-tszymanski")).toBeInTheDocument());
    const flagged = screen.getByTestId("review-tszymanski");
    expect(within(flagged).getByText("unused for 90 days")).toBeInTheDocument();
    // The scope is read as a sentence here too: a review that said "the
    // whole fleet" over a narrowed binding would miss what it exists for.
    expect(flagged).toHaveTextContent("site lab");
    // Somebody with nothing against them says so rather than being left
    // blank, which reads as a row that did not load.
    expect(within(screen.getByTestId("review-backup-runner")).getByText("nothing to review")).toBeInTheDocument();
  });

  it("counts the flags over everything the review carries", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("review-tszymanski")).toBeInTheDocument());
    const card = screen.getByText("Access review").closest(".fl-card") as HTMLElement;
    expect(fig(card, "Flagged")).toBe("1");
    expect(fig(card, "Unused 90 days")).toBe("1");
    // A flag nobody carries is a nought, because the review did count it.
    expect(fig(card, "Admins without expiry")).toBe("0");
  });

  it("draws an em dash where the review has not arrived, never a nought", async () => {
    // A promise that never settles is a review still on its way.
    given({ "/api/v1/access/review": new Promise(() => { /* never */ }) });
    draw();
    await waitFor(() => expect(screen.getByText("Access review")).toBeInTheDocument());
    const card = screen.getByText("Access review").closest(".fl-card") as HTMLElement;
    expect(fig(card, "Identities")).toBe("—");
    expect(fig(card, "Flagged")).toBe("—");
  });

  it("narrows to one flag without asking the server a second question", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("review-backup-runner")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("review-only"), { target: { value: "flagged" } });
    await waitFor(() => expect(screen.queryByTestId("review-backup-runner")).not.toBeInTheDocument());
    expect(screen.getByTestId("review-tszymanski")).toBeInTheDocument();
    expect(asked.some((one) => one.startsWith("/api/v1/access/review"))).toBe(false);
  });

  it("is not on the screen at all for a reader who may not manage access", async () => {
    given({ "/api/v1/whoami": { permissions: ["host.read"] } });
    draw();
    await waitFor(() => expect(screen.getByText("Group mappings")).toBeInTheDocument());
    expect(screen.queryByText("Access review")).not.toBeInTheDocument();
    expect(screen.queryByTestId("access-review")).not.toBeInTheDocument();
  });
});

describe("whom a review shows", () => {
  it("keeps everybody, everybody flagged and one flag apart", () => {
    const rows = review.items as Parameters<typeof reviewedBy>[0];
    expect(reviewedBy(rows, "all")).toHaveLength(2);
    expect(reviewedBy(rows, "flagged").map((one) => one.subject)).toEqual(["tszymanski"]);
    expect(reviewedBy(rows, "unused_90_days").map((one) => one.subject)).toEqual(["tszymanski"]);
    expect(reviewedBy(rows, "expires_soon")).toHaveLength(0);
  });
});
