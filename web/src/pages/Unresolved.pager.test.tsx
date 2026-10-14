import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import Unresolved from "./Unresolved";

/* The owner pressed 2 at the foot of the table and the table came back to 1.
   This holds the paging of the screen against that: the page he asked for is
   the page he gets, and it stays. */

const TOTAL = 31;
let asked: string[] = [];

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const offset = Number(new URL(path, "http://panel").searchParams.get("offset") ?? 0);
        const limit = Number(new URL(path, "http://panel").searchParams.get("limit") ?? 20);
        const rows = Math.max(0, Math.min(limit, TOTAL - offset));
        return Promise.resolve({
          counts: {
            outcome_unknown_operations: 0, outcome_unknown_hosts: 0,
            applied_unverified_operations: TOTAL, applied_unverified_hosts: 2,
          },
          total: TOTAL,
          items: Array.from({ length: rows }, (_, i) => ({
            attempt_id: `attempt-${offset + i}`,
            job_id: `job-${offset + i}`,
            host_id: "host-1",
            hostname: "agent-debian",
            action: "sysctl.ensure",
            kind: "applied_unverified" as const,
            reason: "the change was made, but the host does not show the state asked for",
            first_seen: "2026-10-14T10:00:00Z",
          })),
        });
      },
      post: () => Promise.reject(new Error("this test writes nothing")),
    },
  };
});

function draw(): ReactNode {
  // The client is given the panel's own defaults: the previous page's data
  // stays on screen while the next one is fetched, and a test with a bare
  // client would not be testing what the panel does.
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, placeholderData: (previous: unknown) => previous },
    },
  });
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/unresolved"]}>
        <Unresolved />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

beforeEach(() => { asked = []; });
afterEach(cleanup);

describe("paging the screen of unconfirmed operations", () => {
  it("stays on the page that was asked for", async () => {
    render(draw());
    await waitFor(() => expect(screen.getByTestId("page-2")).toBeInTheDocument());

    screen.getByTestId("page-2").click();

    // The second page is asked for...
    await waitFor(() => expect(asked.some((p) => p.includes("offset=20"))).toBe(true));
    // ...and it is still the second page a moment later. The clamp that puts a
    // reader back on the last page when the list shrinks must not fire while
    // the page it is about is still being fetched.
    await waitFor(() => expect(screen.getByTestId("page-2")).toHaveAttribute("aria-current", "page"));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.getByTestId("page-2")).toHaveAttribute("aria-current", "page");
    expect(screen.getByTestId("page-of")).toHaveTextContent("21-31");
  });
});
